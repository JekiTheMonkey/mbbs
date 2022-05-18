#include "serv_cfg.h"
#include "def.h"
#include "log.h"
#include "utility.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void zero_cfg(serv_cfg *cfg)
{
    cfg->ip_s = NULL;
    cfg->port_s = NULL;
    cfg->db_dir = NULL;
    LOG("Server config has been inizialized with null values\n");
}

void handle_argv(serv_cfg *cfg, char **argv)
{
    char **it = (char **) &cfg->ip_s; /* 3 ptrs in cfg are alined */
    assert((void *) &cfg->db_dir - (void *) &cfg->ip_s == sizeof(void *) * 2);
    argv++;
    for (; it <= &cfg->db_dir && *argv; it++, argv++)
    {
        if (*argv)
        {
            *it = strdup(*argv);
            LOG("Arguments '%s' has been read\n", *argv);
        }
    }
    LOG("Server config has read as many arguments as provided\n");
}

void init_null_vals(serv_cfg *cfg)
{
    if (!cfg->ip_s)
    {
        cfg->ip_s = strdup((char *) default_ip);
        LOG("Server config's IP is set to default - '%s'\n", default_ip);
    }
    if (!cfg->port_s)
    {
        cfg->port_s = strdup((char *) default_port);
        LOG("Server config's port is set to default - '%s'\n", default_port);
    }
    if (!cfg->db_dir)
    {
        cfg->db_dir = strdup((char *) default_db_dir);
        LOG("Server config's database directory is set to default - '%s'\n",
            default_db_dir);
    }
}

void init_addr(serv_cfg *cfg)
{
    struct sockaddr_in *addr = &cfg->addr;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(inet_addr(cfg->ip_s));
    addr->sin_port = htons(atoi(cfg->port_s));
    LOG("Server config's address has been initiliazed - '%s::%s'\n",
        cfg->ip_s, cfg->port_s);
}

void init_cfg(serv_cfg *cfg, char **argv)
{
    LOG_E("\n");
    zero_cfg(cfg);
    handle_argv(cfg, argv);
    init_null_vals(cfg);
    init_addr(cfg);
    LOG_L("\n");
}

void delete_cfg(serv_cfg *cfg)
{
    FREE_IFEX(cfg->ip_s);
    FREE_IFEX(cfg->port_s);
    FREE_IFEX(cfg->db_dir);
    FREE(cfg);
}

void print_cfg(const serv_cfg *cfg)
{
    printf(
        "IP_s: '%s'\n"
        "Port_s: '%s'\n"
        "Database directory: '%s'\n",
        cfg->ip_s, cfg->port_s, cfg->db_dir);
}
