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
#define AUTH_KEY "mbbs-client"
#define SYS_FILE_SPC '#'

#define MAX_FILE_LEN 128

#ifndef SESS_ARRAY_INIT_SIZE
#define SESS_ARRAY_INIT_SIZE 32
#endif

#ifndef SESS_BUF_DEF_SIZE
#define SESS_BUF_DEF_SIZE 4096
#endif

#ifndef TIME_DIFF_TO_TERMINATE
#define TIME_DIFF_TO_TERMINATE 5.0
#endif

#ifndef MAX_WRITE_BYTES
#define MAX_WRITE_BYTES 4096
#endif


typedef struct user_t user_t;
typedef struct buf_t buf_t;
typedef struct serv_cfg_t serv_cfg_t;
typedef struct serv_t serv_t;
typedef struct sess_t sess_t;
typedef enum com_state com_state;
typedef enum com_action com_action;
typedef enum permissions permissions;
typedef enum sys_file_zones sys_file_zones;

#define DEF_IP "0.0.0.0"
#define DEF_PORT "6666"
#define DEF_DB_DIR "mbbs_db"
#define DEF_INTRO_FILE "_intro"
#define DEF_USR_FILE "_users"

#endif /* DEF_H*/
