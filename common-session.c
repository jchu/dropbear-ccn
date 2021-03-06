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
#include "atomicio.h"
#include "runopts.h"

#if 0
static void checktimeouts();
static long select_timeout();
static int ident_readln(int fd, char* buf, int count);
#endif

struct sshsession ses; /* GLOBAL */

/* need to know if the session struct has been initialised, this way isn't the
 * cleanest, but works OK */
int sessinitdone = 0; /* GLOBAL */

/* this is set when we get SIGINT or SIGTERM, the handler is in main.c */
int exitflag = 0; /* GLOBAL */

static enum ccn_upcall_res
remoteIdentHandler(struct ccn_closure *selfp,
        enum ccn_upcall_kind kind,
        struct ccn_upcall_info *info);

static struct ccn_closure
remoteIdentAction =
{
    .p = &remoteIdentHandler
};

/* called only at the start of a session, set up initial state */
#if 0
void common_session_init(int sock_in, int sock_out) {
#endif
void common_session_init() {

    dropbear_log(LOG_WARNING,"Enter common_session_init");
	TRACE(("enter session_init"));

#if 0
	ses.sock_in = sock_in;
	ses.sock_out = sock_out;
	ses.maxfd = MAX(sock_in, sock_out);
#endif

	ses.connect_time = 0;
	ses.last_trx_packet_time = 0;
	ses.last_packet_time = 0;
	
	if (pipe(ses.signal_pipe) < 0) {
		dropbear_exit("Signal pipe failed");
	}
	setnonblocking(ses.signal_pipe[0]);
	setnonblocking(ses.signal_pipe[1]);
#if 0
	ses.maxfd = MAX(ses.maxfd, ses.signal_pipe[0]);
	ses.maxfd = MAX(ses.maxfd, ses.signal_pipe[1]);
#endif
	ses.maxfd = MAX(ses.signal_pipe[0], ses.signal_pipe[0]);
	
	kexfirstinitialise(); /* initialise the kex state */

	ses.writepayload = buf_new(TRANS_MAX_PAYLOAD_LEN);
	ses.transseq = 0;

	ses.readbuf = NULL;
	ses.payload = NULL;
	ses.recvseq = 0;

	initqueue(&ses.writequeue);

	ses.requirenext = SSH_MSG_KEXINIT;
	ses.dataallowed = 1; /* we can send data until we actually 
							send the SSH_MSG_KEXINIT */
	ses.ignorenext = 0;
	ses.lastpacket = 0;
	ses.reply_queue_head = NULL;
	ses.reply_queue_tail = NULL;

	/* set all the algos to none */
	ses.keys = (struct key_context*)m_malloc(sizeof(struct key_context));
	ses.newkeys = NULL;
	ses.keys->recv.algo_crypt = &dropbear_nocipher;
	ses.keys->trans.algo_crypt = &dropbear_nocipher;
	ses.keys->recv.crypt_mode = &dropbear_mode_none;
	ses.keys->trans.crypt_mode = &dropbear_mode_none;
	
	ses.keys->recv.algo_mac = &dropbear_nohash;
	ses.keys->trans.algo_mac = &dropbear_nohash;

	ses.keys->algo_kex = -1;
	ses.keys->algo_hostkey = -1;
	ses.keys->recv.algo_comp = DROPBEAR_COMP_NONE;
	ses.keys->trans.algo_comp = DROPBEAR_COMP_NONE;

#ifndef DISABLE_ZLIB
	ses.keys->recv.zstream = NULL;
	ses.keys->trans.zstream = NULL;
#endif

	/* key exchange buffers */
	ses.session_id = NULL;
	ses.kexhashbuf = NULL;
	ses.transkexinit = NULL;
	ses.dh_K = NULL;
	ses.remoteident = NULL;

	ses.chantypes = NULL;

	ses.allowprivport = 0;

	TRACE(("leave session_init"))
}

#if 0
void session_loop(void(*loophandler)()) {
	fd_set readfd, writefd;
	struct timeval timeout;
	int val;

	/* main loop, select()s for all sockets in use */
	for(;;) {

		timeout.tv_sec = select_timeout();
		timeout.tv_usec = 0;
		FD_ZERO(&writefd);
		FD_ZERO(&readfd);
		dropbear_assert(ses.payload == NULL);
		if (ses.sock_in != -1) {
			FD_SET(ses.sock_in, &readfd);
		}
		if (ses.sock_out != -1 && !isempty(&ses.writequeue)) {
			FD_SET(ses.sock_out, &writefd);
		}
		
		/* We get woken up when signal handlers write to this pipe.
		   SIGCHLD in svr-chansession is the only one currently. */
		FD_SET(ses.signal_pipe[0], &readfd);

		/* set up for channels which require reading/writing */
		if (ses.dataallowed) {
			setchannelfds(&readfd, &writefd);
		}
		val = select(ses.maxfd+1, &readfd, &writefd, NULL, &timeout);

		if (exitflag) {
			dropbear_exit("Terminated by signal");
		}
		
		if (val < 0 && errno != EINTR) {
			dropbear_exit("Error in select");
		}

		if (val <= 0) {
			/* If we were interrupted or the select timed out, we still
			 * want to iterate over channels etc for reading, to handle
			 * server processes exiting etc. 
			 * We don't want to read/write FDs. */
			FD_ZERO(&writefd);
			FD_ZERO(&readfd);
		}
		
		/* We'll just empty out the pipe if required. We don't do
		any thing with the data, since the pipe's purpose is purely to
		wake up the select() above. */
		if (FD_ISSET(ses.signal_pipe[0], &readfd)) {
			char x;
			while (read(ses.signal_pipe[0], &x, 1) > 0) {}
		}

		/* check for auth timeout, rekeying required etc */
		checktimeouts();

		/* process session socket's incoming/outgoing data */
		if (ses.sock_out != -1) {
			if (FD_ISSET(ses.sock_out, &writefd) && !isempty(&ses.writequeue)) {
				write_packet();
			}
		}

		if (ses.sock_in != -1) {
			if (FD_ISSET(ses.sock_in, &readfd)) {
				read_packet();
			}
			
			/* Process the decrypted packet. After this, the read buffer
			 * will be ready for a new packet */
			if (ses.payload != NULL) {
				process_packet();
			}
		}
		
		/* if required, flush out any queued reply packets that
		were being held up during a KEX */
		maybe_flush_reply_queue();

		/* process pipes etc for the channels, ses.dataallowed == 0
		 * during rekeying ) */
		if (ses.dataallowed) {
			channelio(&readfd, &writefd);
		}

		if (loophandler) {
			loophandler();
		}

	} /* for(;;) */
	
	/* Not reached */
}
#endif

/* clean up a session on exit */
void common_session_cleanup() {
	
	TRACE(("enter session_cleanup"))
	
	/* we can't cleanup if we don't know the session state */
	if (!sessinitdone) {
		TRACE(("leave session_cleanup: !sessinitdone"))
		return;
	}
	
	m_free(ses.session_id);
	m_burn(ses.keys, sizeof(struct key_context));
	m_free(ses.keys);

	chancleanup();

	TRACE(("leave session_cleanup"))
}


void session_identification() {
    dropbear_log(LOG_WARNING,"Enter session_identification");
#if 0

	/* max length of 255 chars */
	char linebuf[256];
	int len = 0;
	char done = 0;
	int i;

	/* write our version string, this blocks */
	if (atomicio(write, ses.sock_out, LOCAL_IDENT "\r\n",
				strlen(LOCAL_IDENT "\r\n")) == DROPBEAR_FAILURE) {
		ses.remoteclosed();
	}

	/* If they send more than 50 lines, something is wrong */
	for (i = 0; i < 50; i++) {
		len = ident_readln(ses.sock_in, linebuf, sizeof(linebuf));

		if (len < 0 && errno != EINTR) {
			/* It failed */
			break;
		}

		if (len >= 4 && memcmp(linebuf, "SSH-", 4) == 0) {
			/* start of line matches */
			done = 1;
			break;
		}
	}

	if (!done) {
		TRACE(("err: %s for '%s'\n", strerror(errno), linebuf))
		ses.remoteclosed();
	} else {
		/* linebuf is already null terminated */
		ses.remoteident = m_malloc(len);
		memcpy(ses.remoteident, linebuf, len);
	}

	/* Shall assume that 2.x will be backwards compatible. */
	if (strncmp(ses.remoteident, "SSH-2.", 6) != 0
			&& strncmp(ses.remoteident, "SSH-1.99-", 9) != 0) {
		dropbear_exit("Incompatible remote version '%s'", ses.remoteident);
	}

	TRACE(("remoteident: %s", ses.remoteident))
#endif

    // Send out a new interest for session_id
    // sessionIdHandler takes care of comparison
    int result;
    dropbear_log(LOG_WARNING,"session_ident: register localIdentAction to");
    print_ccnb_charbuf(ses.local_name);

    result = ccn_set_interest_filter(ses.ssh_ccn,ses.local_name,&remoteIdentAction);

    dropbear_log(LOG_WARNING,"session_ident: expressing interest to");
    print_ccnb_charbuf(ses.remote_name);

    struct ccn_charbuf *templ = ccn_make_generic_template();
    result = ccn_express_interest(ses.ssh_ccn,ses.remote_name,
            &remoteIdentAction, templ);
    if( result < 0 )
        dropbear_exit("Failed to express interest for ession id (res == %d)",result);
}

#if 0
/* returns the length including null-terminating zero on success,
 * or -1 on failure */
static int ident_readln(int fd, char* buf, int count) {
	
	char in;
	int pos = 0;
	int num = 0;
	fd_set fds;
	struct timeval timeout;

	TRACE(("enter ident_readln"))

	if (count < 1) {
		return -1;
	}

	FD_ZERO(&fds);

	/* select since it's a non-blocking fd */
	
	/* leave space to null-terminate */
	while (pos < count-1) {

		FD_SET(fd, &fds);

		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		if (select(fd+1, &fds, NULL, NULL, &timeout) < 0) {
			if (errno == EINTR) {
				continue;
			}
			TRACE(("leave ident_readln: select error"))
			return -1;
		}

		checktimeouts();
		
		/* Have to go one byte at a time, since we don't want to read past
		 * the end, and have to somehow shove bytes back into the normal
		 * packet reader */
		if (FD_ISSET(fd, &fds)) {
			num = read(fd, &in, 1);
			/* a "\n" is a newline, "\r" we want to read in and keep going
			 * so that it won't be read as part of the next line */
			if (num < 0) {
				/* error */
				if (errno == EINTR) {
					continue; /* not a real error */
				}
				TRACE(("leave ident_readln: read error"))
				return -1;
			}
			if (num == 0) {
				/* EOF */
				TRACE(("leave ident_readln: EOF"))
				return -1;
			}
			if (in == '\n') {
				/* end of ident string */
				break;
			}
			/* we don't want to include '\r's */
			if (in != '\r') {
				buf[pos] = in;
				pos++;
			}
		}
	}

	buf[pos] = '\0';
	TRACE(("leave ident_readln: return %d", pos+1))
	return pos+1;
}
#endif

void send_msg_ignore() {
	CHECKCLEARTOWRITE();
	buf_putbyte(ses.writepayload, SSH_MSG_IGNORE);
	buf_putstring(ses.writepayload, "", 0);
	encrypt_packet();
}

#if 0
/* Check all timeouts which are required. Currently these are the time for
 * user authentication, and the automatic rekeying. */
static void checktimeouts() {

	time_t now;

	now = time(NULL);
	
	if (ses.connect_time != 0 && now - ses.connect_time >= AUTH_TIMEOUT) {
			dropbear_close("Timeout before auth");
	}

	/* we can't rekey if we haven't done remote ident exchange yet */
	if (ses.remoteident == NULL) {
		return;
	}

	if (!ses.kexstate.sentkexinit
			&& (now - ses.kexstate.lastkextime >= KEX_REKEY_TIMEOUT
			|| ses.kexstate.datarecv+ses.kexstate.datatrans >= KEX_REKEY_DATA)) {
		TRACE(("rekeying after timeout or max data reached"))
		send_msg_kexinit();
	}
	
	if (opts.keepalive_secs > 0 
			&& now - ses.last_trx_packet_time >= opts.keepalive_secs) {
		send_msg_ignore();
	}

	if (opts.idle_timeout_secs > 0 && ses.last_packet_time > 0
			&& now - ses.last_packet_time >= opts.idle_timeout_secs) {
		dropbear_close("Idle timeout");
	}
}

static long select_timeout() {
	/* determine the minimum timeout that might be required, so
	as to avoid waking when unneccessary */
	long ret = LONG_MAX;
	if (KEX_REKEY_TIMEOUT > 0)
		ret = MIN(KEX_REKEY_TIMEOUT, ret);
	if (AUTH_TIMEOUT > 0)
		ret = MIN(AUTH_TIMEOUT, ret);
	if (opts.keepalive_secs > 0)
		ret = MIN(opts.keepalive_secs, ret);
    if (opts.idle_timeout_secs > 0)
        ret = MIN(opts.idle_timeout_secs, ret);
	return ret;
}
#endif

const char* get_user_shell() {
	/* an empty shell should be interpreted as "/bin/sh" */
	if (ses.authstate.pw_shell[0] == '\0') {
		return "/bin/sh";
	} else {
		return ses.authstate.pw_shell;
	}
}
void fill_passwd(const char* username) {
	struct passwd *pw = NULL;
	if (ses.authstate.pw_name)
		m_free(ses.authstate.pw_name);
	if (ses.authstate.pw_dir)
		m_free(ses.authstate.pw_dir);
	if (ses.authstate.pw_shell)
		m_free(ses.authstate.pw_shell);
	if (ses.authstate.pw_passwd)
		m_free(ses.authstate.pw_passwd);

	pw = getpwnam(username);
	if (!pw) {
		return;
	}
	ses.authstate.pw_uid = pw->pw_uid;
	ses.authstate.pw_gid = pw->pw_gid;
	ses.authstate.pw_name = m_strdup(pw->pw_name);
	ses.authstate.pw_dir = m_strdup(pw->pw_dir);
	ses.authstate.pw_shell = m_strdup(pw->pw_shell);
	ses.authstate.pw_passwd = m_strdup(pw->pw_passwd);
}

static enum ccn_upcall_res
remoteIdentHandler(struct ccn_closure *selfp,
        enum ccn_upcall_kind kind,
        struct ccn_upcall_info *info)
{
    dropbear_log(LOG_WARNING,"enter remoteIdentHandler");
    dropbear_log(LOG_WARNING,"Got interest matching %d components, kind = %d\n", info->matched_comps, kind);

    switch (kind) {
        case CCN_UPCALL_INTEREST:
            return send_ident(info);
        case CCN_UPCALL_INTEREST_TIMED_OUT:
            return CCN_UPCALL_RESULT_REEXPRESS;
        case CCN_UPCALL_CONTENT_UNVERIFIED:
            // TODO: fix verification
            return verify_ident(info);
        case CCN_UPCALL_CONTENT:
            return verify_ident(info);
        default:
            return CCN_UPCALL_RESULT_ERR;
    }
    return CCN_UPCALL_RESULT_ERR;
}

enum ccn_upcall_res
send_ident(struct ccn_upcall_info *info)
{
    dropbear_log(LOG_WARNING,"enter send_ident");
    int result;

    struct ccn_charbuf *reply_name;

    struct ccn_charbuf *reply = NULL;
    size_t reply_length = 0;

    reply_name = ccn_charbuf_create();
    ccn_name_init(reply_name);
    ccn_name_append_components(reply_name,
            info->interest_ccnb,
            info->interest_comps->buf[0],
            info->interest_comps->buf[4]);

    unsigned char *ident = LOCAL_IDENT "\r\n";

    result = ccn_wrap_content(ses.ccn_cached_keystore,
            reply_name,
            ident, strlen(ident),
            &reply);

    dropbear_log(LOG_WARNING,"send_ident: %s (%d)",ident,strlen(ident));
    dropbear_log(LOG_WARNING,"send_ident: reply to");
    print_ccnb_charbuf(reply_name);

    dropbear_log(LOG_WARNING,"reply length: %d",reply->length);

    result = ccn_put(info->h,reply->buf,reply->length);
    if( result < 0 ) {
        dropbear_exit("Failed to reply with ident: %d",result);
    }

    return CCN_UPCALL_RESULT_INTEREST_CONSUMED;
}

enum ccn_upcall_res
verify_ident(struct ccn_upcall_info *info)
{
    dropbear_log(LOG_WARNING,"enter verify_ident");
    int result;

    unsigned char ident_reply = NULL;
    size_t ident_reply_length = 0;
    result = ccn_unwrap_content(info,&ident_reply,&ident_reply_length);
    if( result < 0 )
        dropbear_exit("Failed to parse ident reply");

    // Parse out ident line
    char* ident_line = strstr((const char*)&ident_reply,"SSH-");
    if( ident_line == NULL )
        dropbear_exit("Failed to find ident in reply");

    char* newline = strstr(ident_line,"\n");
    memcpy(ses.remoteident, ident_line, newline - ident_line);

	/* Shall assume that 2.x will be backwards compatible. */
	if (strncmp(ses.remoteident, "SSH-2.", 6) != 0
			&& strncmp(ses.remoteident, "SSH-1.99-", 9) != 0) {
		dropbear_exit("Incompatible remote version '%s'", ses.remoteident);
	}

	TRACE(("remoteident: %s", ses.remoteident));

    return CCN_UPCALL_RESULT_OK;
}
