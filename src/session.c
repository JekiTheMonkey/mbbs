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
    sess->state = sst_unk;
    sess->action = cac_unk;
    sess->addr = NULL;
    sess->buf = buffer_create(SESS_BUF_DEF_SIZE);
    sess->fd = cfd;
    sess->logined = 0;
    return sess;
}

void session_delete(session *sess)
{
    close(sess->fd);
    buffer_delete(sess->buf);
    FREE(sess->addr);

    sess->state = -1;
    sess->action = -1;
    sess->addr = NULL;
    sess->buf = NULL;
    sess->fd = -1;
    sess->logined = -1;

    FREE(sess);
}
