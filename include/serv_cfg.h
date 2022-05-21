#ifndef SERV_CFG_H
#define SERV_CFG_H

#include "def.h"

#include <arpa/inet.h>

/* Simple struct that contains essential server configuration */

struct serv_cfg
{
    char *ip_s;
    char *port_s;
    char *db_dir;

    struct sockaddr_in addr;
};

void init_cfg(serv_cfg *cfg, char **argv);

#endif /* SERV_CFG_H */
