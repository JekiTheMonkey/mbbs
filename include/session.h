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
    sst_upload,                         /* send a file to user */
};

/* cac - Communication ACtion */
enum com_action {
    cac_unk,                            /* unknown */
    cac_log,                            /* login */
    cac_reg,                            /* register */
};

enum permissions {
    perms_upload        = 1 << 0,       /* upload files */
    perms_remove        = 1 << 1,       /* remove files */
    perms_edit_desc     = 1 << 2,       /* edit descriptions */
};

enum sys_file_zones {
    description = 1,                    /* file description */
    owner,                              /* owner username */
    last_edit,                          /* last edit date and time */
    is_whitelist,                       /* is whitelist set */
    whitelist                           /* whitelist to download a file users */
};

struct sess_t
{
    com_state state;
    com_action action;
    struct sockaddr_in *addr;
    int cfd; /* client file descriptor */
    int udfd; /* upload/download file descriptor */
    int perms;
    user_t *usr;
    buf_t *buf;
};

sess_t *session_create(int cfd);
void session_delete(sess_t *sess);
int session_send_data(sess_t *sess, const void *data, size_t bytes);
int session_send_str(sess_t *sess, const char *str);
int session_upload_buffer(sess_t *sess);
int session_receive_data(sess_t *sess);
char *create_sys_filepath(const char *file);
FILE *open_sys_file(const char *file, const char *mode);
FILE *create_sys_file(const char *filepath, const char *owner);
int sfseek(FILE *file, sys_file_zones zone);
int session_open_file(sess_t *sess, const char *file, int flags);
int is_user_in_whitelist(FILE *sys_file, const char *username);
int is_whitelist_set(FILE *sys_file);

#endif /* SESSION_H */
