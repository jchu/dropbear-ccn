/*
 * Dropbear - a SSH2 server
 * 
 * Copyright (c) 2002,2003 Matt Johnston
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
#include "session.h"
#include "dbutil.h"
#include "packet.h"
#include "algo.h"
#include "buffer.h"
#include "dss.h"
#include "ssh.h"
#include "random.h"
#include "kex.h"
#include "channel.h"
#include "chansession.h"
#include "atomicio.h"
#include "tcpfwd.h"
#include "service.h"
#include "auth.h"
#include "runopts.h"

static void svr_remoteclosed();

struct serversession svr_ses; /* GLOBAL */

static const packettype svr_packettypes[] = {
	{SSH_MSG_CHANNEL_DATA, recv_msg_channel_data},
	{SSH_MSG_CHANNEL_WINDOW_ADJUST, recv_msg_channel_window_adjust},
	{SSH_MSG_USERAUTH_REQUEST, recv_msg_userauth_request}, /* server */
	{SSH_MSG_SERVICE_REQUEST, recv_msg_service_request}, /* server */
	{SSH_MSG_KEXINIT, recv_msg_kexinit},
	{SSH_MSG_KEXDH_INIT, recv_msg_kexdh_init}, /* server */
	{SSH_MSG_NEWKEYS, recv_msg_newkeys},
#ifdef ENABLE_SVR_REMOTETCPFWD
	{SSH_MSG_GLOBAL_REQUEST, recv_msg_global_request_remotetcp},
#endif
	{SSH_MSG_CHANNEL_REQUEST, recv_msg_channel_request},
	{SSH_MSG_CHANNEL_OPEN, recv_msg_channel_open},
	{SSH_MSG_CHANNEL_EOF, recv_msg_channel_eof},
	{SSH_MSG_CHANNEL_CLOSE, recv_msg_channel_close},
#ifdef USING_LISTENERS
	{SSH_MSG_CHANNEL_OPEN_CONFIRMATION, recv_msg_channel_open_confirmation},
	{SSH_MSG_CHANNEL_OPEN_FAILURE, recv_msg_channel_open_failure},
#endif
	{0, 0} /* End */
};

static const struct ChanType *svr_chantypes[] = {
	&svrchansess,
#ifdef ENABLE_SVR_LOCALTCPFWD
	&svr_chan_tcpdirect,
#endif
	NULL /* Null termination is mandatory. */
};

#if 0
void svr_session(int sock, int childpipe) {
	char *host, *port;
#endif
void svr_session(unsigned char *local_name, unsigned char *remote_name)
{
    dropbear_log(LOG_WARNING,"Enter svr_session");
    int result;
#if 0
	size_t len;
#endif
    reseedrandom();

	crypto_init();
#if 0
	common_session_init(sock, sock);
#endif
	common_session_init();

	/* Initialise server specific parts of the session */
#if 0
	svr_ses.childpipe = childpipe;
    svr_ses.conn_idx = conn_idx;
#endif
#ifdef __uClinux__
	svr_ses.server_pid = getpid();
#endif
	svr_authinitialise();
	chaninitialise(svr_chantypes); // TODO: Figure out what listeners do
	svr_chansessinitialise();

	ses.connect_time = time(NULL);

	/* for logging the remote address */
#if 0
	get_socket_address(ses.sock_in, NULL, NULL, &host, &port, 0);
	len = strlen(host) + strlen(port) + 2;
	svr_ses.addrstring = m_malloc(len);
	snprintf(svr_ses.addrstring, len, "%s:%s", host, port);
	m_free(host);
	m_free(port);

	get_socket_address(ses.sock_in, NULL, NULL, 
			&svr_ses.remotehost, NULL, 1);
#endif
    ses.ssh_ccn = ccn_create();
    if( ses.ssh_ccn == NULL || ccn_connect(ses.ssh_ccn,NULL) == -1 )
        dropbear_exit("Failed to connect to ccnd");

    ses.ccn_cached_keystore = svr_opts.ccn_cached_keystore;
    ses.local_name_str = local_name;
    ses.remote_name_str = remote_name;

    ses.remote_name = ccn_charbuf_create();
    result = ccn_name_from_uri(ses.remote_name,ses.remote_name_str);
    if( result < 0 )
        dropbear_exit("Can't resolve client domain");
    ses.local_name = ccn_charbuf_create();
    result = ccn_name_from_uri(ses.local_name,ses.local_name_str);
    if( result < 0 )
        dropbear_exit("Can't resolve local domain");

    dropbear_log(LOG_WARNING,"svr_session: %s <-> %s", ses.local_name_str, ses.remote_name_str);

	/* set up messages etc */
	ses.remoteclosed = svr_remoteclosed;

	/* packet handlers */
	ses.packettypes = svr_packettypes;
	ses.buf_match_algo = svr_buf_match_algo;

	ses.isserver = 1;

	/* We're ready to go now */
	sessinitdone = 1;

	/* exchange identification, version etc */
	session_identification();

	/* start off with key exchange */
	//send_msg_kexinit();

	/* Run the main for loop. NULL is for the dispatcher - only the client
	 * code makes use of it */
#if 0
	session_loop(NULL);
#endif

    dropbear_log(LOG_WARNING,"loop?");
    ccn_run(ses.ssh_ccn,-1);
    dropbear_log(LOG_WARNING,"deloop?");

	/* Not reached */
}

/* failure exit - format must be <= 100 chars */
void svr_dropbear_exit(int exitcode, const char* format, va_list param) {

	char fmtbuf[300];

	if (!sessinitdone) {
		/* before session init */
		snprintf(fmtbuf, sizeof(fmtbuf), 
				"Premature exit: %s", format);
	} else if (ses.authstate.authdone) {
		/* user has authenticated */
		snprintf(fmtbuf, sizeof(fmtbuf),
				"Exit (%s): %s", 
				ses.authstate.pw_name, format);
	} else if (ses.authstate.pw_name) {
		/* we have a potential user */
		snprintf(fmtbuf, sizeof(fmtbuf), 
				"Exit before auth (user '%s', %d fails): %s",
				ses.authstate.pw_name, ses.authstate.failcount, format);
	} else {
		/* before userauth */
		snprintf(fmtbuf, sizeof(fmtbuf), 
				"Exit before auth: %s", format);
	}

	_dropbear_log(LOG_INFO, fmtbuf, param);

#ifdef __uClinux__
	/* only the main server process should cleanup - we don't want
	 * forked children doing that */
	if (svr_ses.server_pid == getpid())
#else
	if (1)
#endif
	{
		/* free potential public key options */
		svr_pubkey_options_cleanup();

		/* must be after we've done with username etc */
		common_session_cleanup();
	}

	exit(exitcode);

}

/* priority is priority as with syslog() */
void svr_dropbear_log(int priority, const char* format, va_list param) {

	char printbuf[1024];
	char datestr[20];
	time_t timesec;
	int havetrace = 0;

	vsnprintf(printbuf, sizeof(printbuf), format, param);

#ifndef DISABLE_SYSLOG
	if (svr_opts.usingsyslog) {
		syslog(priority, "%s", printbuf);
	}
#endif

	/* if we are using DEBUG_TRACE, we want to print to stderr even if
	 * syslog is used, so it is included in error reports */
#ifdef DEBUG_TRACE
	havetrace = debug_trace;
#endif

	if (!svr_opts.usingsyslog || havetrace)
	{
		struct tm * local_tm = NULL;
		timesec = time(NULL);
		local_tm = localtime(&timesec);
		if (local_tm == NULL
			|| strftime(datestr, sizeof(datestr), "%b %d %H:%M:%S", 
						localtime(&timesec)) == 0)
		{
			/* upon failure, just print the epoch-seconds time. */
			snprintf(datestr, sizeof(datestr), "%d", (int)timesec);
		}
		fprintf(stderr, "[%d] %s %s\n", getpid(), datestr, printbuf);
	}
}

/* called when the remote side closes the connection */
static void svr_remoteclosed() {
#if 0
	m_close(ses.sock_in);
	m_close(ses.sock_out);
	ses.sock_in = -1;
	ses.sock_out = -1;
#endif
	dropbear_close("Exited normally");

}

