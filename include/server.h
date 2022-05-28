#ifndef SERVER_H
#define SERVER_H

#include "def.h"

/*
 * Server structure contains its own config, listening socket, database FD,
 * head for the list of registered users, all the pointers to active sessions
 * and intro that is shown on connection.
 *
 * It's a core structure which can be used to handle the connections with users
 * and database.
*/

struct serv_t
{
    serv_cfg_t *cfg;
    int ls;
    int db_fd;
    user_t *users;
    buf_t *sess_buf;
    buf_t *intro;
};

int serv_init(serv_t *serv, char **argv);
int serv_start(serv_t *serv);

#endif /* SERVER_H */
