#ifndef SERVER_H
#define SERVER_H

#include "def.h"
#include "serv_cfg.h"

/*
 * Server structure contains its own config, listening socket, database FD,
 * head for the list of registered users, all the pointers to active sessions
 * and intro that is shown on connection.
 *
 * It's a core structure which can be used to handle the connections with users
 * and database.
*/

struct server
{
    serv_cfg *cfg;
    int ls;
    int db_fd;
    user *users;
    buffer *sess_buf;
    buffer *intro;
};

int serv_init(server *serv, char **argv);
int serv_start(server *serv);

#endif /* SERVER_H */
