/*
 * Copyright 2016 Cumulus Networks, Inc.  All rights reserved.
 *   TACACS+ work based on pam_tacplus.c
 *     Copyright (C) 2010, Pawel Krawczyk <pawel.krawczyk@hush.com> and
 *     Jeroen Nijhof <jeroen@jeroennijhof.nl>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Author: Dave Olson <olson@cumulusnetworks.com>
 * Cumulus Networks, Inc.
 * 185 E. Dana Street
 * Mountain View, CA 94041
 *
 * This program is used for TACACS+ authorization of commands.
 * It uses libtac to communicate with the TACACS+ servers
 * It uses the configuration file /etc/tacplus_servers normally
 * shipped with libpam-tacplus
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>
#include <errno.h>
#include <limits.h>
#include <libaudit.h>
#include <sys/stat.h>

#include <tacplus/libtac.h>

const char *configfile = "/etc/tacplus_servers";

/*
 * WARNING: don't show the key in any debug messages, since we are
 * usually run by an unprivileged user.
 */
typedef struct {
    struct addrinfo *addr;
    const char *key;
} tacplus_server_t;

/* set from configuration file parsing */
static tacplus_server_t tac_srv[TAC_PLUS_MAXSERVERS];
static int tac_srv_no, tac_key_no;
static int debug = 0;
static uid_t auth_uid;

static const char *progname = "tacplus-auth"; /* for syslogs and errors */

static int build_auth_req(const char *user, const char *cmd,
    char **argv, int argc);

static void
tacplus_config(const char *cfile, int level)
{
    FILE *conf;
    char lbuf[256];

    conf = fopen(cfile, "r");
    if(conf == NULL) {
        fprintf(stderr, "%s: can't open config file %s: %s\n",
            progname, cfile, strerror(errno));
        return;
    }

    while(fgets(lbuf, sizeof lbuf, conf)) {
        if(*lbuf == '#' || isspace(*lbuf))
            continue; /* skip comments, white space lines, etc. */
        strtok(lbuf, " \t\n\r\f"); /* terminate buffer at first whitespace */
        if(!strncmp(lbuf, "include=", 8)) {
            /*
             * allow include files, useful for centralizing tacacs
             * server IP address and secret.
             */
            if(lbuf[8]) /* else treat as empty config */
                tacplus_config(&lbuf[8], level+1);
        }
        else if(!strncmp(lbuf, "debug=", 6))
            debug = strtoul(lbuf+6, NULL, 0);
        else if(!strncmp(lbuf, "secret=", 7)) {
            /* no need to complain if too many on this one */
            if(tac_key_no < TAC_PLUS_MAXSERVERS) {
                int i;
                if((tac_srv[tac_key_no].key = strdup(lbuf+7)))
                    tac_key_no++;
                else {
                    /*
                     * don't show the actual key, since we are usually run
                     * by an unprivileged user.
                     */
                    fprintf(stderr, "%s: unable to copy server secret\n",
                        progname);
                }
                /* handle case where 'secret=' was given after a 'server='
                 * parameter, fill in the current secret */
                for(i = tac_srv_no-1; i >= 0; i--) {
                    if (tac_srv[i].key)
                        continue;
                    tac_srv[i].key = strdup(lbuf+7);
                }
            }
        }
        else if(!strncmp(lbuf, "server=", 7)) {
            if(tac_srv_no < TAC_PLUS_MAXSERVERS) {
                struct addrinfo hints, *servers, *server;
                int rv;
                char *port, server_buf[sizeof lbuf];

                memset(&hints, 0, sizeof hints);
                hints.ai_family = AF_UNSPEC;  /* use IPv4 or IPv6, whichever */
                hints.ai_socktype = SOCK_STREAM;

                strcpy(server_buf, lbuf + 7);

                port = strchr(server_buf, ':');
                if(port != NULL) {
                    *port = '\0';
					port++;
                }
                if((rv = getaddrinfo(server_buf, (port == NULL) ?
                            "49" : port, &hints, &servers)) == 0) {
                    for(server = servers; server != NULL &&
                        tac_srv_no < TAC_PLUS_MAXSERVERS;
                        server = server->ai_next) {
                        tac_srv[tac_srv_no].addr = server;
                        if(tac_key_no && tac_srv_no != (tac_key_no-1))
                            /* use current key if set, and not the same index */
                            tac_srv[tac_srv_no].key = tac_srv[tac_key_no-1].key;
                        tac_srv_no++;
                    }
                }
                else {
                    fprintf(stderr,
                        "%s: skip invalid server: %s (getaddrinfo: %s)\n",
                        progname, server_buf, gai_strerror(rv));
                }
            }
            else {
                fprintf(stderr, "%s: maximum number of servers (%d) exceeded, "
                    "skipping\n", progname, TAC_PLUS_MAXSERVERS);
            }
        }
        else if(debug) /* ignore unrecognized lines, unless debug on */
            fprintf(stderr, "%s: unrecognized parameter: %s\n",
                progname, lbuf);
    }

    if(level == 0 && tac_srv_no == 0)
        fprintf(stderr, "%s no tacacs servers in file %s\n",
            progname, configfile);

    fclose(conf);
}

/*
 * Drop our privileges, since we expect to be setuid.
 * Don't worry about groups.  If somebody chooses to
 * make us setgid also, that's the admin's choice.
 * if the auth_uid is -1, set it to the ruid.
 * If getresuid() fails, but getuid and geteuid work
 * and are equal, and not 0, continue.
 *
 * We also do nothing about any privileges that might be set
 * via setcap on our executable, or from the original user.
 */
void
drop_privilege(void)
{
    uid_t ruid, euid, suid;

    if (getresuid(&ruid, &euid, &suid)) {
        perror("Unable to get original uid");
        euid = geteuid();
        if (euid == (uid_t)-1)
            exit(1);
        ruid = getuid();
        if (euid != ruid || ruid == (uid_t)-1)
            exit(1);
        if (ruid == 0) {
            fprintf(stderr, "%s: Real uid is 0, exiting\n", progname);
            exit(1);
        }
    }
    else if (setreuid(ruid, ruid)) {
        perror("Unable to drop privilege");
        exit(1);
    }
    if (auth_uid == (uid_t)-1) {
        auth_uid = ruid;
        if (debug)
            fprintf(stderr, "%s: audit uid is not set, using realuid=%u\n",
                progname, ruid);
    }
}

static int
getlogindefs(char *path, size_t len, const char *var)
{
    char line[PATH_MAX];
    FILE *defs;
    int vlen, ret = 1;

    defs = fopen("/etc/login.defs", "r");
    if (!defs)
        return 1;

    vlen = strlen(var);

    while(fgets(line, sizeof line, defs)) {
        char *start, *p;
        /*  skip any leading space, although there shouldn't be any */
        for(p=line; isblank(*p); p++)
            ;
        if(strncmp(p, var, vlen))
            continue;

        p += vlen;
        start = p;
        while(isblank(*p))
            p++;
        if (p == start) /* no whitespace; substring match or error */
            continue;
        snprintf(path, len, "%s", p);
        ret = 0;
        break;
    }
    fclose(defs);
    return ret;
}

static int
getenvironment(char *path, size_t len, const char *var)
{
    char line[PATH_MAX];
    FILE *env;
    int vlen, ret = 1;

    env = fopen("/etc/environment", "r");
    if (!env)
        return 1;

    vlen = strlen(var);

    while(fgets(line, sizeof line, env)) {
        char *p;
        /*  skip any leading space, although there shouldn't be any */
        for(p=line; isblank(*p); p++)
            ;
        if(strncmp(p, var, vlen))
            continue;
        if(p[vlen] != '=')
            continue; /* no =; substring match or error */
        snprintf(path, len, "%s", p);
        ret = 0;
        break;
    }
    fclose(env);
    return ret;
}

/*  
 *  Get system PATH setting from login.defs ENV_PATH, and if login.defs
 *  can't be opened, try /etc/environment.
 *  the prefix through PATH= is stripped, as is any trailing whitespace
 *  returns 0 if a PATH settings is found, otherwise 1.
 */
static int
getpath(char *dpath, size_t len)
{
    char tmp[PATH_MAX], *p;

    if (getlogindefs(tmp, sizeof tmp, "ENV_PATH")) {
        if (debug)
            fprintf(stderr, "%s: No PATH from login.defs, try environment\n",
                progname);
        if (getenvironment(tmp, sizeof tmp, "PATH")) {
            if (debug)
                fprintf(stderr, "%s: No PATH from /etc/environment\n",
                    progname);
            return 1;
        }
    }
    snprintf(dpath, len, "%s", tmp + strlen("PATH="));
    /*
     * strip any trailing whitespace including newline from fgets()
     * because login.defs in core pkgs do that in debian.
     */
    p = dpath + strlen(dpath);
    while(p >= dpath && isspace(p[-1]))
        p--;
    if (isspace(*p))
        *p = '\0';
    return 0;
}

/*
 *  Try to found an executable of the same name as the cmd passed
 *  (which is expected to be relative, no /'s in name).
 *  by looking in the system ENV_PATH list of directories
 *  from /etc/login.defs, and if that file is not found, by looking for
 *  PATH in /etc/environment.
 *  If command is found, copy it into the passed buffer (no check is
 *  made to see if the command can be executed, as long as it is a
 *  regular file, and at least one execut bit is set.
 *  Return 0 if a matching executable is found, otherwise 1
 */
static int
findcmd(char *cmd, char *path, size_t pathlen)
{
    char dpath[PATH_MAX], *dir, *dinit;

    if (getpath(dpath, sizeof dpath)) {
        if (debug)
            fprintf(stderr, "%s: Unable to get PATH setting, giving up\n",
                progname);
        return 1;
    }

    for(dinit=dpath; (dir=strtok(dinit, ":")); dinit=NULL) {
        struct stat st;
        char cmdpath[PATH_MAX];
        snprintf(cmdpath, sizeof cmdpath, "%s/%s", dir, cmd);
        if (stat(cmdpath, &st) == 0 && S_ISREG(st.st_mode) &&
            (st.st_mode & (S_IXUSR|S_IXGRP|S_IXOTH))) {
            /*  found it, and it's an executable file  */
            snprintf(path, pathlen, "%s", cmdpath);
            return 0;
        }
    }

    return 1;
}

int
main(int argc, char *argv[])
{
    struct passwd *pw;
    char path[PATH_MAX], *cmd;

    if(getenv("TACACSAUTHDEBUG")) /* if present, with any value */
        debug = 1;

    tacplus_config(configfile, 0);

    auth_uid = audit_getloginuid(); /* drop_privilege will set if this fails */
    drop_privilege();

    pw = getpwuid(auth_uid);
    if (pw == NULL || !pw->pw_name[0]) {
        fprintf(stderr, "%s: Unable to find username for uid=%u\n",
            progname, auth_uid);
        exit(1);
    }

    /*
     * convert the command name to the basename (relative) for
     * matching, and to send to the tacacs server, since most
     * tacacs servers won't be configured for linux pathnames
     */
    /*  get relative name of cmd */
    cmd = strrchr(argv[0], '/');
    if (cmd)
        cmd++;
    else
        cmd = argv[0];

    if (findcmd(cmd, path, sizeof path)) {
        fprintf(stderr, "%s: could not find real command for (%s) in "
            "system PATH\n", progname, cmd);
        exit(1);
    }
    if (debug)
        fprintf(stderr, "%s: found matching command (%s) request authorization\n",
            progname, path);

    /* accumulate command, and do auth; */
    if (build_auth_req(pw->pw_name, cmd, argv, argc) == 0) {
        if (debug)
            fprintf(stderr, "%s: %s authorized, executing\n",
                progname, cmd);
            execvp(path, argv);
            fprintf(stderr, "%s exec failed: %s\n",
                path, strerror(errno));
    }
    fprintf(stderr, "%s not authorized by TACACS+ with given arguments, not"
        " executing\n", cmd);

	return 1;
}

int
send_auth_msg(int tac_fd, const char *user, const char *tty, const char *host,
    uint16_t taskid, const char *cmd, char **args, int argc)
{
    char buf[128];
    struct tac_attrib *attr;
    int retval;
    struct areply re;
    int i;

    attr=(struct tac_attrib *)tac_xcalloc(1, sizeof(struct tac_attrib));

    snprintf(buf, sizeof buf, "%hu", taskid);
    tac_add_attrib(&attr, "task_id", buf);
    tac_add_attrib(&attr, "protocol", "ssh");
    tac_add_attrib(&attr, "service", "shell");

    tac_add_attrib(&attr, "cmd", (char*)cmd);

    /* 
     * Add the command arguments.  Each argument has to be
     * less than 255 chars, including the "cmdargs=" portion
     * With the linux tac_plus server, at least, somewhere around
     * 2300 bytes of total argument always fails authorization.
     * I don't see a need to handle that specially.  Any truncation
     * might mean that something the administrator wants to deny
     * might miss being denied, if we didn't send that argument.
     */
    for(i=1; i<argc; i++) {
        char tbuf[248];
        const char *arg;
        if(strlen(args[i]) > 247) {
            snprintf(tbuf, sizeof tbuf, "%s", args[i]);
            arg = tbuf;
        }
        else
            arg = args[i];
        tac_add_attrib(&attr, "cmd-arg", (char *)arg);
    }

    re.msg = NULL;
    retval = tac_author_send(tac_fd, (char *)user, (char *)tty, (char *)host,
        attr);

    if(retval < 0)
        fprintf(stderr, "%s: send of authorization msg failed: %s\n",
            progname, strerror(errno));
    else {
        retval = tac_author_read(tac_fd, &re);
        if (retval < 0) {
            if(debug)
                fprintf(stderr, "%s: authorization response failed: %d\n",
                    progname, retval);
        }
        else if(re.status == AUTHOR_STATUS_PASS_ADD ||
            re.status == AUTHOR_STATUS_PASS_REPL)
            retval = 0;
        else  {
            if(debug)
                fprintf(stderr, "%s: cmd not authorized (%d)\n",
                    progname, re.status);
            retval = 1;
        }
    }

    tac_free_attrib(&attr);
    if(re.msg != NULL)
        free(re.msg);

    return retval;
}

/*
 * Send the command authorization request to the to each TACACS+ server
 * in the list, until one responds successfully or we exhaust the list.
 */
static int
send_tacacs_auth(const char *user, const char *tty, const char *host,
    const char *cmd, char **args, int argc)
{
    int retval = 1, srv_i, srv_fd;
    uint16_t task_id;

    task_id = (uint16_t)getpid();

    for(srv_i = 0; srv_i < tac_srv_no; srv_i++) {
        srv_fd = tac_connect_single(tac_srv[srv_i].addr, tac_srv[srv_i].key,
            NULL);
        if(srv_fd == -1) {
            fprintf(stderr, "%s: error connecting to %s to request"
                " authorization for %s: %s\n", progname,
                tac_ntop(tac_srv[srv_i].addr->ai_addr),
                cmd, strerror(errno));
            continue;
        }
        retval = send_auth_msg(srv_fd, user, tty, host, task_id,
            cmd, args, argc);
        if(retval && debug)
            fprintf(stderr, "%s: %s not authorized from %s\n",
                progname, cmd, tac_ntop(tac_srv[srv_i].addr->ai_addr));
        close(srv_fd);
        if(!retval) {
            fprintf(stderr, "%s: %s authorized command %s\n",
                progname, tac_ntop(tac_srv[srv_i].addr->ai_addr), cmd);
            break; /* stop after first successful response */
        }
    }
    return retval;
}


/*
 * Build up the command authorization request, using as many of the
 * args as will fit in a single tacacs packet.
 */
static int
build_auth_req(const char *user, const char *cmd, char **argv, int argc)
{
    int i;
    char tty[64], host[64];

    tty[0] = host[0] = 0;
    (void)gethostname(host, sizeof host -1);

    for(i=0; i<3; i++) {
        int r;
        if (isatty(i)) {
            r = ttyname_r(i, tty, sizeof tty -1);
            if (r && debug)
                fprintf(stderr, "%s: failed to get tty name for fd %d: %s\n",
                    progname, i, strerror(r));
            break;
        }
    }
    if (!host[0]) {
        snprintf(host, sizeof host, "UNK");
        if (debug)
            fprintf(stderr, "%s: Unable to determine hostname, passing %s\n",
                progname, host);
    }
    if (!tty[0]) {
        snprintf(tty, sizeof tty, "UNK");
        if (debug)
            fprintf(stderr, "%s: Unable to determine tty, passing %s\n",
                progname, tty);
    }

    return send_tacacs_auth(user, tty, host, cmd, argv, argc);
}
