#include "server.h"

/*
 * Optional:
 * argv[1] - IP
 * argv[2] = port
 * argv[3] = database directory
 */
int main(int argc, char **argv)
{
    (void) argc;
    server serv;
    serv_init(&serv, argv);
    return serv_start(&serv);
}
