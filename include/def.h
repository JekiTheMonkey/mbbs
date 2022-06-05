#ifndef DEF_H
#define DEF_H

#include <limits.h> /* NAME_MAX */
#include <stdio.h>

#ifndef NAME_MAX
    #define NAME_MAX 255
#endif

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
#define SYS_FILE_SPC_STR "#"
/* #define SYS_FILE_TMPL \ */
/*     /1* Description                      *1/ SYS_FILE_SPC " empty" \ */
/*     /1* Owner                            *1/ SYS_FILE_SPC " owner" \ */
/*     /1* Last edit                        *1/ SYS_FILE_SPC " date" \ */
/*     /1* Are everyone allowed to download *1/ SYS_FILE_SPC " no" \ */
/*     /1* Whitelist                        *1/ SYS_FILE_SPC " empty" */
#define SYS_FILE_TMPL \
    SYS_FILE_SPC_STR " empty\n" \
    SYS_FILE_SPC_STR " %s\n" \
    SYS_FILE_SPC_STR " %s\n" \
    SYS_FILE_SPC_STR " no\n" \
    SYS_FILE_SPC_STR " empty"

#define MAX_FILE_LEN 256

#ifndef SESS_ARRAY_INIT_SIZE
    #define SESS_ARRAY_INIT_SIZE 32
#endif

#ifndef SESS_BUF_SIZE
    #define SESS_BUF_SIZE 4096
#endif

#define LIST_ELEMENTS_DEF 20
#define LIST_ELEMENTS_MAX SESS_BUF_SIZE / (NAME_MAX + 10)
    /* +10 is for some extra data in each list element */

#ifndef LIST_ELEMENTS
    #if LIST_ELEMENTS_MAX > LIST_ELEMENTS_DEF
        #define LIST_ELEMENTS LIST_ELEMENTS_DEF
    #else
        #define LIST_ELEMENTS LIST_ELEMENTS_MAX
    #endif
#else
    #if LIST_ELEMENTS > LIST_ELEMENTS_MAX
        #error "LIST_ELEMENTS is too big, try a smaller value instead"
    #endif
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
