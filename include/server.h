#ifndef SERVER_H
#define SERVER_H

#include "def.h"

#include <arpa/inet.h>

struct server
{
    int ls;
    buffer *sess_buf;
};

int serv_init(const serv_cfg *cfg, server *serv);
int serv_start(server *serv);

#endif /* SERVER_H */
