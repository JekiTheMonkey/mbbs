#ifndef SESSION_H
#define SESSION_H

#include "def.h"

#include <sys/types.h>

/* sst - Session STatus */
enum com_state {
    sst_unk,                            /* unknown */

    /* Read states */
    sst_lsn_req,                        /* listen for a request */

    /* Write states */
    sst_intro,                          /* show intro*/
    sst_inv_msg                         /* send invite message */
};

/* exst - EXit STatus */
enum exit_status {
    exst_unk,                           /* unknown */
    exst_eof,                           /* end of file */
    exst_err                            /* error */
};

struct session
{
    com_state e_com_state;
    exit_status e_exit_status;
    int fd;
    buffer *buf;
    size_t written_bytes;
};

session *session_create(int cfd);
void session_delete(session *item);

#endif /* SESSION_H */
