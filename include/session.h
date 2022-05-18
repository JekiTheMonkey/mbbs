#ifndef SESSION_H
#define SESSION_H

#include "def.h"

struct session
{
    int fd;
    buffer *buf;
};

session *session_create(int cfd);
void session_delete(session *item);

#endif /* SESSION_H */
