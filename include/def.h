#ifndef DEF_H
#define DEF_H

#define PERROR(msg) do { perror("msg"); exit(1); } while(0)
#define SESS_ARRAY_INIT_SIZE 32
#define SESS_BUF_DEF_SIZE 4092
#define TIME_DIFF_TO_TERMINATE 5.0
#define MAX_WRITE_BYTES 1024
#define LOGO \
    "   #     #    ######     ######      #####     \n" \
    "   ##   ##    #     #    #     #    #     #    \n" \
    "   # # # #    #     #    #     #    #          \n" \
    "   #  #  #    ######     ######      #####     \n" \
    "   #     #    #     #    #     #          #    \n" \
    "   #     #    #     #    #     #    #     #    \n" \
    "   #     #    ######     ######      #####     \n"

typedef struct buffer buffer;
typedef struct serv_cfg serv_cfg;
typedef struct server server;
typedef struct session session;
typedef enum com_state com_state;
typedef enum exit_status exit_status;

extern const char default_ip[];
extern const char default_port[];
extern const char default_db_dir[];
extern const char default_logo[];
extern const char default_intro[];
extern const char default_inv_msg[];


#endif /* DEF_H*/
