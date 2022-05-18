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
    sess->buf = buffer_create(SESS_BUF_DEF_SIZE);
    sess->fd = cfd;
    return sess;
}

void session_delete(session *item)
{
    close(item->fd);
    buffer_delete(item->buf);
    FREE(item);
}
