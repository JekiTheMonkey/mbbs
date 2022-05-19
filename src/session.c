#include "buffer.h"
#include "session.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

session *session_create(int cfd)
{
    session *sess = (session *) malloc(sizeof(session));
    ALOG(sess);
    sess->e_com_state = sst_unk;
    sess->e_exit_status = exst_unk;
    sess->buf = buffer_create(SESS_BUF_DEF_SIZE);
    sess->fd = cfd;
    sess->written_bytes = 0;
    return sess;
}

void session_delete(session *item)
{
    close(item->fd);
    buffer_delete(item->buf);

    item->fd = -1;
    item->buf = NULL;
    item->e_com_state = -1;
    item->e_exit_status = -1;
    item->written_bytes = -1;

    FREE(item);
}
