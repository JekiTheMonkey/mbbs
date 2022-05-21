#ifndef DEF_H
#define DEF_H

#define LOGO \
    "   #     #    ######     ######      #####     \n" \
    "   ##   ##    #     #    #     #    #     #    \n" \
    "   # # # #    #     #    #     #    #          \n" \
    "   #  #  #    ######     ######      #####     \n" \
    "   #     #    #     #    #     #          #    \n" \
    "   #     #    #     #    #     #    #     #    \n" \
    "   #     #    ######     ######      #####     \n"
#define INV_MSG "mbbs> "

#ifndef SESS_ARRAY_INIT_SIZE
#define SESS_ARRAY_INIT_SIZE 32
#endif

#ifndef SESS_BUF_DEF_SIZE
#define SESS_BUF_DEF_SIZE 4092
#endif

#ifndef TIME_DIFF_TO_TERMINATE
#define TIME_DIFF_TO_TERMINATE 5.0
#endif

#ifndef MAX_WRITE_BYTES
#define MAX_WRITE_BYTES 1024
#endif


typedef struct user user;
typedef struct buffer buffer;
typedef struct serv_cfg serv_cfg;
typedef struct server server;
typedef struct session session;
typedef enum com_state com_state;
typedef enum com_action com_action;

#define DEF_IP "0.0.0.0"
#define DEF_PORT "6666"
#define DEF_DB_DIR "mbbs_db"
#define DEF_INTRO_FILE "_intro"
#define DEF_USR_FILE "_users"

#endif /* DEF_H*/
