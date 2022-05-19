#ifndef SERVER_H
#define SERVER_H

#include "def.h"
#include "serv_cfg.h"

struct server
{
    serv_cfg *cfg;
    int ls;
    buffer *sess_buf;
    buffer *intro;
    buffer *inv_msg;
};

int serv_init(server *serv, char **argv);
int serv_start(server *serv);

#endif /* SERVER_H */
