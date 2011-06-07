/*
 * Dropbear - a SSH2 server
 * SSH client implementation
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * Copyright (c) 2004 by Mihnea Stoenescu
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

#include "includes.h"
#include "dbutil.h"
#include "runopts.h"
#include "session.h"

static void cli_dropbear_exit(int exitcode, const char* format, va_list param);
static void cli_dropbear_log(int priority, const char* format, va_list param);

static void ccn_publish_host_key();
static void ccn_publish_client_mountpoint();

#if 0
#ifdef ENABLE_CLI_PROXYCMD
static void cli_proxy_cmd(int *sock_in, int *sock_out);
#endif
#endif

#if defined(DBMULTI_dbclient) || !defined(DROPBEAR_MULTI)
#if defined(DBMULTI_dbclient) && defined(DROPBEAR_MULTI)
int cli_main(int argc, char ** argv) {
#else
int main(int argc, char ** argv) {
#endif

#if 0
	int sock_in, sock_out;
	char* error = NULL;
#endif

	_dropbear_exit = cli_dropbear_exit;
	_dropbear_log = cli_dropbear_log;

	disallow_core();

	cli_getopts(argc, argv);

#if 0
	TRACE(("user='%s' host='%s' port='%s'", cli_opts.username,
				cli_opts.remotehost, cli_opts.remoteport))
#endif
	TRACE(("user='%s' remotehost='%s'", cli_opts.username,
				cli_opts.remote_name_str));

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		dropbear_exit("signal() error");
	}

#if 0
#ifdef ENABLE_CLI_PROXYCMD
	if (cli_opts.proxycmd) {
		cli_proxy_cmd(&sock_in, &sock_out);
		m_free(cli_opts.proxycmd);
	} else
#endif
	{
		int sock = connect_remote(cli_opts.remotehost, cli_opts.remoteport, 
				0, &error);
		sock_in = sock_out = sock;
	}

	if (sock_in < 0) {
		dropbear_exit("%s", error);
	}

	cli_session(sock_in, sock_out);
#endif
    srand(time(NULL));
    cli_opts.ssh_ccn = ccn_create();
    cli_opts.ccn_cached_keystore = ccn_init_keystore();
    if( cli_opts.ssh_ccn == NULL || ccn_connect(cli_opts.ssh_ccn,NULL) == -1 )
        dropbear_exit("Failed to connect to ccnd");
    ccn_publish_host_key();

    ccn_publish_client_mountpoint();

    cli_session(cli_opts.remote_name_str);

	/* not reached */
	return -1;
}
#endif /* DBMULTI stuff */

static void cli_dropbear_exit(int exitcode, const char* format, va_list param) {

	char fmtbuf[300];

	if (!sessinitdone) {
		snprintf(fmtbuf, sizeof(fmtbuf), "Exited: %s",
				format);
	} else {
		snprintf(fmtbuf, sizeof(fmtbuf), 
#if 0
				"Connection to %s@%s:%s exited: %s", 
				cli_opts.username, cli_opts.remotehost, 
				cli_opts.remoteport, format);
#endif
				"Connection to %s@%s exited: %s", 
				cli_opts.username, cli_opts.remote_name_str, format);
	}

	/* Do the cleanup first, since then the terminal will be reset */
	cli_session_cleanup();
	common_session_cleanup();

	_dropbear_log(LOG_INFO, fmtbuf, param);

	exit(exitcode);
}

static void cli_dropbear_log(int UNUSED(priority), 
		const char* format, va_list param) {

	char printbuf[1024];

	vsnprintf(printbuf, sizeof(printbuf), format, param);

	fprintf(stderr, "%s: %s\n", cli_opts.progname, printbuf);

}

static void
ccn_publish_host_key()
{
    if( ccn_publish_key(cli_opts.ssh_ccn,
                cli_opts.ccn_cached_keystore,
                cli_opts.ccnxdomain) < 0 )
        dropbear_exit("Could not publish ccn host key");
}

static void
ccn_publish_client_mountpoint()
{
    int result;
    struct ccn_charbuf *mountpoint;
    char client_id_str[6];
    char *client_name_str = NULL;

    mountpoint = ccn_charbuf_create();
    if( mountpoint == NULL )
        dropbear_exit("Failed to allocate client mountpoint charbuf");

    client_name_str = strdup((const char*)cli_opts.ccnxdomain);
    strcat(client_name_str,"/ssh/");
    sprintf(client_id_str,"%6d",rand());
    strcat(client_name_str,client_id_str);
    cli_opts.ccnxdomain = client_name_str;

    result = ccn_name_from_uri(mountpoint,cli_opts.ccnxdomain);
    if( result < 0 )
        dropbear_exit("Can't resolve client domain");
}

#if 0
static void exec_proxy_cmd(void *user_data_cmd) {
	const char *cmd = user_data_cmd;
	char *usershell;

	usershell = m_strdup(get_user_shell());
	run_shell_command(cmd, ses.maxfd, usershell);
	dropbear_exit("Failed to run '%s'\n", cmd);
}
#endif

#if 0
#ifdef ENABLE_CLI_PROXYCMD
static void cli_proxy_cmd(int *sock_in, int *sock_out) {
	int ret;

	fill_passwd(cli_opts.own_user);

	ret = spawn_command(exec_proxy_cmd, cli_opts.proxycmd,
			sock_out, sock_in, NULL, NULL);
	if (ret == DROPBEAR_FAILURE) {
		dropbear_exit("Failed running proxy command");
		*sock_in = *sock_out = -1;
	}
}
#endif // ENABLE_CLI_PROXYCMD
#endif
