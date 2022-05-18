#ifndef DEF_H
#define DEF_H

#define PERROR(msg) do { perror("msg"); exit(1); } while(0)
#define SESS_ARRAY_INIT_SIZE 32
#define SESS_BUF_DEF_SIZE 4092
#define TIME_DIFF_TO_TERMINATE 5.0

typedef struct buffer buffer;
typedef struct serv_cfg serv_cfg;
typedef struct server server;
typedef struct session session;

extern const char default_ip[];
extern const char default_port[];
extern const char default_db_dir[];


#endif /* DEF_H*/
