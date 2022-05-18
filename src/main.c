#include "serv_cfg.h"
#include "server.h"

int main(int argc, char **argv)
{
    (void) argc;
    serv_cfg cfg;
    server serv;

    init_cfg(&cfg, argv);
    serv_init(&cfg, &serv);
    return serv_start(&serv);
}
