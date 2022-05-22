#ifndef SESSION_H
#define SESSION_H

#include "def.h"

#include <arpa/inet.h>
#include <sys/types.h>

/*
 * Session represents a connection between server and a client. Session knows
 * what communication state is currently active, and, based on it, can act (I/O)
 * respectively.
 *
 * When one of the listenig (input) states is active read operations from client
 * socket are performed until a LF is not found. All the read data are stored
 * into an internal buffer of size 4092*.
 *
 * When writing operation can't be perfomed in one iteration (for example file
 * upload) the session will mark how many bytes have been written so far in
 * order to start from N byte on next big write operation.
*/

/* sst - Session STatus */
enum com_state {
    sst_unk,                            /* unknown */
    sst_disc,                           /* disconnect */
    sst_err,                            /* error */

    /* Read states */
    sst_lsn_auth,                       /* listen for authorization key */
    sst_lsn_req,                        /* listen for a request */
    sst_lsn_usr,                        /* listen for username */
    sst_lsn_pwd,                        /* listen for password */

    /* Write states */
    sst_intro,                          /* show intro */
    sst_help,                           /* show help */
    sst_ask_usr,                        /* ask username */
    sst_ask_pwd,                        /* ask password */
};

/* cac - Communication ACtion */
enum com_action {
    cac_unk,                            /* unknown */
    cac_log,                            /* login */
    cac_reg,                            /* register */
};

struct session
{
    com_state state;
    com_action action;
    struct sockaddr_in *addr;
    int fd;
    int logined;
    buffer *buf;
};

session *session_create(int cfd);
void session_delete(session *item);

#endif /* SESSION_H */
