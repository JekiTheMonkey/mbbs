#define _XOPEN_SOURCE /* seekdir */
#include "buffer.h"
#include "log.h"
#include "server_cfg.h"
#include "server.h"
#include "session.h"
#include "user.h"
#include "utility.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ######################### Server related strings ######################### */
/* Service commands */
#define CMD_LOG  "login"
#define CMD_REG  "register"
#define CMD_DOW  "download"
#define CMD_UPL  "upload"
#define CMD_LST  "list"
#define CMD_DSC  "describe"
#define CMD_EXIT "close"
#define CMD_HELP "help"

/* ##################### Client & Server related strings #################### */
/* Messages to send in dialog */
#define ERR "Error: "
#define USG "Usage: "
#define HLP_MSG \
    "MBBS stands for Bulletin Board System. It's a server that allows users\n" \
    "to connect to the system using a terminal program such as telnet. Once\n" \
    "logged in,  the  user  can  perform  functions  such  as uploading and\n" \
    "downloading data,  exchanging messages with other users through public\n" \
    "message boards and via direct chatting.\n" \
    "\n" \
    "Available commands:\n" \
    "   " CMD_LOG  " \tLogin into account\n" \
    "   " CMD_REG  " \tRegister a new account\n" \
    "   " CMD_DOW  " \tDownload a file\n" \
    "   " CMD_UPL  " \tUpload a file\n" \
    "   " CMD_LST  " \tList available files\n" \
    "   " CMD_HELP " \tSee this message\n" \
    "   " CMD_EXIT " \tClose connection"

#define USR_ASK "Enter your username: "
#define USR_2LN "Username too long"
#define USR_2SH "Username too short"
#define USR_UCH "Username contains unacceptable character"
#define USR_TKN "Username is already taken"
#define USR_NFN "No user found with such username"

#define PWD_ASK "Enter your password: "
#define PWD_2LN "Password too long"
#define PWD_2SH "Password too short"
#define PWD_UCH "Password contains unacceptable character"
#define PWD_INC "Incorrect password"

#define REG_SUC "Your account has been successfully registered"
#define LOG_SUC "Successful login"
#define USR_ALN "You are already logined in"

#define DOW_USG USG "download <file> <destination>"
#define DOW_2LN ERR "Input filename is too long"
#define DOW_UDR ERR "Input filename contains an underscore as the first " \
    "character"
#define DOW_FNE ERR "File does not exist"
#define DOW_NPM ERR "You are not allowed to download this file"

#define UPL_USG USG "upload <source> <file>"
#define UPL_2LN ERR "Input filename is too long"
#define UPL_UDR ERR "Input filename contains an underscore as the first " \
    "character"
#define UPL_FEX ERR "File already exists"
#define UPL_NLN ERR "Unlogined users are not allowed to upload files"
#define UPL_NPM ERR "You are not allowed to upload files"
#define UPL_NNA ERR "This filename is not allowed"

#define LST_USG USG "list <page-number>"
#define LST_IPG ERR "Invalid page. Try natural numbers"
#define LST_2BG ERR "Invalid page. Only %d pages are available"

#define DSC_USG USG "describe <filename>"
#define DSC_FOP ERR "Failed to open file"

#define TERM_MSG "Terminating own work..."
#define LIN_2LN "Your input line is too long, bye..."
#define WRN_CLI "Only MBBS Client must be used to connect to MBBS Server"
#define UNK_MSG "mbbs: Unknown command. Try '" CMD_HELP "'"

/* --- System commands --- */
/* Server messages */
#define DMD_SIL "DMD_SIL" /* Demand silence on client side - no invite msg */
#define DOW_DET "DOW_DET" /* Download file's details */
#define UPL_ALW "UPL_ALW" /* Allow client to upload a file */
/* Client messages */
#define DOW_ACC "DOW_ACC" /* Client accepts to download a file */

/* ########################################################################## */

#define CMDMEMCMP(data, cmd) (memcmp(data, cmd, sizeof(cmd) - 1))
#define CMDLENCMP(len, cmd) (len == sizeof(cmd) - 1)
#define LOG_RET(code) do { LOG_L("\n"); return code; } while(0)
#define HDL_ERR(sess, msg) \
    do { \
        session_send_str(sess, msg "\n"); \
        return -1; \
    } while(0)
#define HDL_ERR_CHANGE_STATE(sess, sst, code, clr_buf, msg) \
    do { \
        if (clr_buf) \
            buffer_clear(sess->buf); \
        session_send_str(sess, msg "\n"); \
        sess->state = sst; \
        return code; \
    } while(0)

volatile sig_atomic_t work;
void sigint_handler(int sig_no)
{
    UNUSED1(sig_no);
    signal(SIGINT, &sigint_handler);
    LOG("SIGINT has arrived\n");
    const time_t cur_time = time(NULL);
    static time_t last_sigint_time = 0;
    if (last_sigint_time &&
        difftime(cur_time, last_sigint_time) <= TIME_DIFF_TO_TERMINATE)
    {
        LOG("Work will be terminated soon\n");
        work = 0;
    }
    last_sigint_time = cur_time;
}

void create_dir_if_not_exists(const char *path)
{
    if (access(path, F_OK))
    {
        LOG("Missing directory '%s'\n", path);
        if (mkdir(path, 0770))
            ELOG_EX("Failed to create directory '%s'", path);
        LOG("Created directory '%s'\n", path);
    }
}

void try_create_default_intro(const char *path)
{
    if (!access(path, F_OK))
        return;
    int fd = open(path, O_WRONLY | O_CREAT, 0770);
    if (fd == -1)
        ELOG_EX("Failed to open intro file");
    int res = write(fd, "\n" LOGO "\n", sizeof(LOGO) + 2);
    if (res == -1)
        ELOG("Failed to write default intro to '%s'", path);
    close(fd);
}

void alloc_intro(serv_t *serv, int intro_fd)
{
    const off_t size = lseek(intro_fd, 0, SEEK_END);
    lseek(intro_fd, 0, SEEK_SET);
    serv->intro = buffer_create(size + 1);
}

int read_intro(serv_t *serv, int intro_fd)
{
    buf_t *buf = serv->intro;
    int res = read(intro_fd, buf->ptr, buf->size);
    if (res == -1)
        PELOG_EX("Failed to read intro file");
    LOG("Read intro is '%d' bytes long\n", res);
    memset(buf->ptr + res, 0, 1); /* terminating zero */
    return res + 1;
}

void init_intro(serv_t *serv)
{
    const char path[] = DEF_INTRO_FILE;
    try_create_default_intro(path);

    int fd = open(path, O_RDONLY);
    if (fd == -1)
        ELOG_EX("Failed to open file '%s'", path);

    alloc_intro(serv, fd);
    serv->intro->used = read_intro(serv, fd);

    close(fd);
}

int create_socket()
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
        PELOG_EX("Failed to create a socket");
    LOG("Server socket has been created, its file descriptor - '%d'\n", fd);
    return fd;
}

void allow_reuse_port(int fd)
{
    int opt = 1;
    int res = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (res == -1)
        PELOG("Failed to set socket option (SO_REUSEADDR)");
    LOG("Server socket has become able to reuse a port\n");
}

void bind_socket(int fd, const struct sockaddr_in *addr)
{
    if (bind(fd, (struct sockaddr *) addr, sizeof(*addr)) == -1)
        PELOG_EX("Failed to bind a socket");
    LOG("Server socket has been binded to '%s::%d'\n",
        inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
}

void make_listening(int fd)
{
    if (listen(fd, 16) == -1)
        PELOG_EX("Failed to make a listening socket");
    LOG("Server socket has become listening\n");
}

int create_server_socket(const serv_cfg_t *cfg)
{
    int fd = create_socket();
    allow_reuse_port(fd);
    bind_socket(fd, &cfg->addr);
    make_listening(fd);
    LOG("Server socket has been created successfully\n");
    return fd;
}

void open_db_fd(serv_t *serv)
{
    const char path[] = DEF_USR_FILE;
    serv->db_fd = open(path, O_RDWR | O_CREAT, 0770);
    if (serv->db_fd == -1)
        ELOG_EX("Failed to open or create database file '%s'", path);
}

/*
 * Upload files         1 << 0
 * Remove files         1 << 1
 * Edit descriptions    1 << 2
 */
#define CHECK_FORMAT(ptr) if (!((ptr) - 1)) LOG_EX("Data is of wrong format\n")
perms_t user_read_permissions(const char *l_it, const char *r_it)
{
    perms_t perms = 0;
    int num, i, len = r_it - l_it;
    const char *tmp, *it = strnfindnth(l_it, ' ', 2, len) + 1;
    CHECK_FORMAT(it);
    len -= it - l_it;
    for (i = 0; i < 3; i++)
    {
        tmp = strnfind(it, ' ', len) + 1;
        num = atoi(it);
        assert(num == 0 || num == 1);
        perms |= num << i;
        len -= tmp - it;
        it = tmp;
    }
    return perms;
}

void read_db(serv_t *serv)
{
    perms_t perms;
    int res, used = 0, linelen, tot_bytes;
    char buf[4096], *line_l_it, *line_r_it;
    char *usr_p, *pwd_p;
    int usr_len, pwd_len;
    user_t *usr;
    while ((res = read(serv->db_fd, buf + used, sizeof(buf) - used)) > 0)
    {
        line_l_it = buf;
        used += res;
        tot_bytes = used;
        while ((line_r_it = strnfind(line_l_it, '\n', used)))
        {
            linelen = line_r_it - line_l_it;
            used -= linelen + 1; /* trailing lf  */

            usr_p = line_l_it;
            pwd_p = strnfind(line_l_it, ' ', linelen) + 1;
            CHECK_FORMAT(pwd_p);
            perms = user_read_permissions(line_l_it, line_r_it);

            usr_len = pwd_p - usr_p - 1;
            pwd_len = strfind(pwd_p, ' ') - pwd_p;
            usr_p[usr_len] = '\0';
            pwd_p[pwd_len] = '\0';
            LOG("Read username '%.*s'\n", usr_len, usr_p);
            LOG("Read password '%.*s'\n", pwd_len, pwd_p);
            LOG("Permissions: ");
#ifdef _TRACE
            print_bits((void *) &perms, 1);
#endif

            usr = user_create(usr_p, pwd_p, perms);
            user_push_back(&serv->users, usr);

            line_l_it = line_r_it + 1;
        }
        memmove(buf, buf + tot_bytes - used, used);
    }
    if (res == -1)
        ELOG_EX("Failed to read from database file");
#ifdef _TRACE
    user_print(serv->users);
#endif
}

void save_db(const serv_t *serv)
{
    LOG_E("\n");
    char buf[512];
    const user_t *it = serv->users;
    lseek(serv->db_fd, 0, SEEK_SET);
    for (; it; it = it->next)
    {
        perms_t p = it->perms;
        int res = sprintf(buf, "%s %s %d %d %d\n", it->username, it->password,
            !!(p & perms_upload), !!(p & perms_remove),
            !!(p & perms_edit_desc));
        if (write(serv->db_fd, buf, res) == -1)
            PELOG_EX("Failed to save database record");
        LOG("Write '%.*s'\n", res - 1, buf);
    }
    LOG_L("\n");
}

void init_db(serv_t *serv)
{
    serv->users = NULL;
    open_db_fd(serv);
    read_db(serv);
}

void init_sess_buf(serv_t *serv)
{
    const size_t to_alloc = SESS_ARRAY_INIT_SIZE * sizeof(sess_t *);
    serv->sess_buf = buffer_create(to_alloc);
    memset(serv->sess_buf->ptr, 0, to_alloc);
}

void change_root_dir(serv_t *serv)
{
    if (chdir(serv->cfg->db_dir) == -1)
        PELOG("Failed to change root directory");
}

void open_db_dir(serv_t *serv)
{
    serv->db_dir = opendir(".");
    if (!serv->db_dir)
        PELOG_EX("Failed to open database directory");
}

int serv_init(serv_t *serv, char **argv)
{
    LOG_E("\n");
    signal(SIGINT, &sigint_handler);

    serv->cfg = (serv_cfg_t *) malloc(sizeof(serv_cfg_t));
    init_cfg(serv->cfg, argv);
    create_dir_if_not_exists(serv->cfg->db_dir);
    change_root_dir(serv);

    init_intro(serv);

    serv->ls = create_server_socket(serv->cfg);
    init_db(serv);
    init_sess_buf(serv);
    open_db_dir(serv);

    LOG_L("Server has been initilized successfully\n");
    return 1;
}

/* ========================================================================== */
/* ========================================================================== */
/* ========================================================================== */

void set_fd(com_state state, int fd, fd_set *readfds, fd_set *writefds)
{
    switch (state)
    {
        /* Read states */
        case sst_lsn_auth:
        case sst_lsn_req:
        case sst_lsn_usr:
        case sst_lsn_pwd:
        case sst_download:
            FD_SET(fd, readfds); break;

        /* Write states */
        case sst_intro:
        case sst_help:
        case sst_ask_usr:
        case sst_ask_pwd:
        case sst_upload:
            FD_SET(fd, writefds); break;

        /* Errors */
        case sst_disc:
        case sst_err:
            return;
        default:
            LOG("Unhandeled case '%d'\n", state); exit(1);
    }
    LOG("'%d' has been added to a fd_set according to its state(%d)\n",
        fd, state);
}

int init_fds(fd_set *readfds, fd_set *writefds, const serv_t *serv)
{
    int fd, maxfd = serv->ls;
    buf_t *sess_buf = serv->sess_buf;
    sess_t **sess_arr = (sess_t **) sess_buf->ptr;
    unsigned i, size = sess_buf->used / sizeof(sess_t *);

    FD_ZERO(readfds);
    FD_ZERO(writefds);
    FD_SET(serv->ls, readfds);
    for (i = 0; i < size; i++)
    {
        LOG("Iteration '%d'. Session state '%d'\n", i + 1, sess_arr[i]->state);
        fd = sess_arr[i]->cfd;
        set_fd(sess_arr[i]->state, fd, readfds, writefds);
        if (maxfd < fd)
            maxfd = fd;
    }

    LOG("'%d' - maxfd\n", maxfd);
    return maxfd;
}

int mselect(const serv_t *serv, fd_set *readfds, fd_set *writefds)
{
    LOG_E("\n");
    int maxfd = init_fds(readfds, writefds, serv);
    int res = select(maxfd + 1, readfds, writefds, NULL, NULL);
    LOG_L("\n");
    return res;
}

int check_err(int code)
{
    return code == -1 && errno != EINTR; /* return 1 on error */
}

int accept_client(int ls, struct sockaddr_in *addr)
{
    socklen_t slen = sizeof(*addr);
    int cfd = accept(ls, (struct sockaddr *) addr, &slen);
    if (cfd == -1)
    {
        PELOG("Failed to accept a client\n");
        return 0;
    }
    printf("Client %d with IP %s::%d has been accepted\n",
        cfd, inet_ntoa(addr->sin_addr), addr->sin_port);
    return cfd;
}

void realloc_sess_buf(buf_t *sess_buf)
{
    const size_t newlen = sess_buf->size + SESS_ARRAY_INIT_SIZE;
    sess_t **sess_arr = (sess_t **) sess_buf->ptr;
    sess_arr = (sess_t **) realloc(sess_arr, newlen);
    LOG("Realloc for '%p' from '%lu' to '%lu'\n",
        sess_arr, sess_buf->size, newlen);
    memset(sess_arr + sess_buf->size, 0, SESS_ARRAY_INIT_SIZE);
    buffer_set_size(sess_buf, newlen);
}

sess_t *add_session(serv_t *serv, int cfd)
{
    buf_t *sess_buf = serv->sess_buf;
    sess_t **sess_arr = (sess_t **) sess_buf->ptr;
    size_t index = sess_buf->used / sizeof(sess_t *);

    if (cfd >= (int) sess_buf->size)
        realloc_sess_buf(sess_buf);

    assert(!sess_arr[index]);
    sess_arr[index] = session_create(cfd);
    sess_arr[index]->state = sst_lsn_auth;
    sess_buf->used += sizeof(sess_t *);

    LOG("New session has been created. Up sessions - '%lu'\n", index + 1);
    return sess_arr[index];
}

void check_listen(serv_t *serv, fd_set *readfds)
{
    if (!FD_ISSET(serv->ls, readfds))
        return;
    LOG_E("\n");
    struct sockaddr_in *cli_addr =
        (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
    int cfd = accept_client(serv->ls, cli_addr);
    if (!cfd)
        LOG_RET();
    sess_t *sess = add_session(serv, cfd);
    sess->addr = cli_addr;
    LOG_L("\n");
}

int control_buffer_fullness(sess_t *sess)
{
    const buf_t *buf = sess->buf;
    if (buf->used != buf->size)
        return 0;
    LOG("Input line is too long, terminate connection with a client\n");
    session_send_str(sess, LIN_2LN "\n");
    sess->state = sst_err;
    return 1;
}

int handle_lsn_auth(serv_t *serv, sess_t *sess)
{
    UNUSED1(serv);
    if (sess->state != sst_lsn_auth)
        return 0;

    buf_t *buf = sess->buf;
    const char *auth = (char *) buf->ptr;
    const unsigned len = buf->used;
    LOG("Authorization key: '%.*s'\n", len, auth);

    if (CMDLENCMP(len, AUTH_KEY) && !CMDMEMCMP(auth, AUTH_KEY))
        sess->state = sst_intro;
    else
    {
        session_send_str(sess, WRN_CLI "\n");
        sess->state = sst_err;
    }
    buffer_clear(buf);
    return 1;
}

int handle_req_empty(serv_t *serv, sess_t *sess)
{
    UNUSED1(serv);
    buf_t *buf = sess->buf;
    if (buf->used != 0)
        return 0;
    LOG("Use this handle...\n");
    assert(buf->used == 0);
    session_send_str(sess, ""); /* reply with silence */
    return 1;
}

int is_already_logined(sess_t *sess)
{
    if (sess->usr)
        session_send_str(sess, USR_ALN);
    return !!sess->usr;
}

int handle_req_login(serv_t *serv, sess_t *sess)
{
    UNUSED1(serv);
    buf_t *buf = sess->buf;
    if (!(buf->used >= sizeof(CMD_LOG) - 1 && !CMDMEMCMP(buf->ptr, CMD_LOG)))
        return 0;
    LOG("Use this handle...\n");
    if (is_already_logined(sess))
        return 1;
    sess->state = sst_ask_usr;
    sess->action = cac_log;
    return 1;
}

int handle_req_register(serv_t *serv, sess_t *sess)
{
    UNUSED1(serv);
    buf_t *buf = sess->buf;
    if (!(buf->used >= sizeof(CMD_REG) - 1 && !CMDMEMCMP(buf->ptr, CMD_REG)))
        return 0;
    LOG("Use this handle...\n");
    sess->state = sst_ask_usr;
    sess->action = cac_reg;
    return 1;
}

int is_allowed_to_download(sess_t *sess, FILE *sys_file)
{
    if (!is_whitelist_set(sys_file))
        return 1;
    if (sess->usr) /* logined */
        return is_user_in_whitelist(sys_file, sess->usr->username);
    return 0;
}

int download_file_checks(sess_t *sess)
{
    buf_t *buf = sess->buf;
    const unsigned req_len = buf->used;
    const unsigned cmd_len = sizeof(CMD_DOW) - 1;
    const char *filename = buffer_get_argv_n(buf, 2);
    buffer_append(buf, "\0", 1);
    LOG("File: '%s'\n", filename);

    if (req_len == cmd_len)
        HDL_ERR(sess, DOW_USG);
    if (req_len - cmd_len - 1 > MAX_FILE_LEN)
        HDL_ERR(sess, DOW_2LN);
    if (*filename == '_')
        HDL_ERR(sess, DOW_UDR);
    LOG("Request syntax analyze has been finished with success\n");

    FILE *sys_file = open_sys_file(filename, "r");
    if (!sys_file)
        HDL_ERR(sess, DOW_FNE);
    if (!is_allowed_to_download(sess, sys_file))
    {
        fclose(sys_file);
        HDL_ERR(sess, DOW_NPM);
    }
    fclose(sys_file);
    return 1;
}

int handle_req_download(serv_t *serv, sess_t *sess)
{
    UNUSED1(serv);
    buf_t *buf = sess->buf;
    if (!(buf->used >= sizeof(CMD_DOW) - 1 && !CMDMEMCMP(buf->ptr, CMD_DOW)))
        return 0;
    LOG("Use this handle...\n");
    if (download_file_checks(sess) == -1)
        return -1;
    int fd = open_file(buffer_get_argv_n(buf, 2), O_RDONLY, 0);
    if (fd == -1)
        HDL_ERR(sess, DOW_FNE);
    sess->udfd = fd;
    const size_t size = get_file_len(sess->udfd);
    LOG("File size: %lu\n", size);
    assert(buf->size > 64);
    buf->used = sprintf((char *) buf->ptr, DOW_DET "%lu", size);

    session_upload_buffer(sess);
    sess->state = sst_lsn_req;
    return 1;
}

int is_filename_allowed(const char *filename)
{
    return
        !strcmp(filename, "intro") ||
        !strcmp(filename, "users") ||
        !strcmp(filename, "intro");
}

int upload_file_checks(sess_t *sess)
{
    buf_t *buf = sess->buf;
    const int argc = buffer_count_argc(buf);
    const char *filename = buffer_get_argv_n(buf, 2);
    const unsigned req_len = buf->used;
    const unsigned cmd_len = sizeof(CMD_UPL) - 1;

    buffer_append(buf, "\0", 1);
    LOG("File: '%s'\n", filename);

    if (argc != 3 || req_len == cmd_len)
        HDL_ERR(sess, UPL_USG);
    if (req_len - cmd_len - 1 > MAX_FILE_LEN)
        HDL_ERR(sess, UPL_2LN);
    if (*filename == '_')
        HDL_ERR(sess, UPL_UDR);
    if (!sess->usr)
        HDL_ERR(sess, UPL_NLN);
    if (!(sess->usr->perms & perms_upload))
        HDL_ERR(sess, UPL_NPM);
    if (file_exists(filename))
        HDL_ERR(sess, UPL_FEX);
    if (!is_filename_allowed(filename))
        HDL_ERR(sess, UPL_NNA);
    LOG("Upload request is ok\n");
    return 1;
}

int handle_req_upload(serv_t *serv, sess_t *sess)
{
    UNUSED1(serv);
    buf_t *buf = sess->buf;
    if (!(buf->used >= sizeof(CMD_UPL) - 1 && !CMDMEMCMP(buf->ptr, CMD_UPL)))
        return 0;
    LOG("Use this handle...\n");
    if (upload_file_checks(sess) == -1)
        return -1;
    const char *filename = buffer_get_argv_n(buf, 2);
    const char *end = strfind(filename, ' ');
    const unsigned len = end - filename;
    char *tmp = (char *) malloc(len + 1);
    memcpy(tmp, filename, len);
    memset(tmp + len, 0, 1);
    filename = tmp;
    const size_t size = atol(buffer_get_argv_n(buf, 3));
    /*
     * TODO Check if hard drive capacity is enough to store the file
     */

    FILE *sys_file = create_sys_file(filename, sess->usr->username);
    fclose(sys_file);
    sess->udfd = open_file(filename, O_WRONLY | O_CREAT, 0660);

    session_send_str(sess, UPL_ALW);
    sess->to_download = size;
    sess->state = sst_download;
    return 1;
}

int list_is_to_skip(const char *filename)
{
    return
        filename[0] == '_' ||
        !strcmp(filename, ".") ||
        !strcmp(filename, "..");
}

int handle_list(DIR *dir, buf_t *buf, unsigned page)
{
    struct dirent *info;
    LOG("Requested page: '%d'\n", page);
    unsigned to_skip = (page - 1) * LIST_ELEMENTS;
    while (to_skip && ((info = readdir(dir))))
        if (!list_is_to_skip(info->d_name))
            to_skip--;
    if (to_skip)
    {
        LOG("Passed page is too big\n");
        return (((page - 1) * LIST_ELEMENTS - to_skip) % LIST_ELEMENTS) + 2;
            /* page too big, return number of pages + 1 */
    }

    unsigned rem = LIST_ELEMENTS;
    unsigned i = 1;
    assert(buf->used == 0);
    buffer_appendf(buf, "---------- Files list page %d ----------\n\n", page);
    while (rem && (info = readdir(dir)))
    {
        LOG("New iteration\n");
        const char *filename = info->d_name;
        if (list_is_to_skip(filename))
            continue;
        buffer_appendf(buf, "%d. %s\n", i, filename);
        i++;
        rem--;
    }
    if (rem == LIST_ELEMENTS)
        buffer_append(buf, "Empty\n", 6);
    return 1;
}

int list_get_argument(sess_t *sess)
{
    const buf_t *buf = sess->buf;
    const char *str = (char *) buf->ptr + sizeof(CMD_LST);
    char *endptr = (char *) str + (buf->used + ((void *) str - buf->ptr));
    int res = strtol(str, &endptr, 10);
    if (endptr == str || *endptr != '\0')
        return 0;
    LOG("Page: %d\n", res);
    return res;
}

int handle_req_list(serv_t *serv, sess_t *sess)
{
    buf_t *buf = sess->buf;
    if (!(buf->used >= sizeof(CMD_LST) - 1 && !CMDMEMCMP(buf->ptr, CMD_LST)))
        return 0;
    LOG("Use this handle...\n");
    buffer_append(buf, "\0", 1);
    if (buffer_count_argc(buf) != 2)
    {
        session_send_str(sess, LST_USG "\n");
        return 1;
    }
    const int page = list_get_argument(sess);
    if (page <= 0)
    {
        session_send_str(sess, LST_IPG "\n");
        return -1;
    }
    LOG("Given page is correct\n");
    buffer_clear(buf); /* buffer will be used in handle_list */
    int res = handle_list(serv->db_dir, sess->buf, page);
    if (res > 1) /* error check. res contains max pages available */
        buffer_appendf(buf, LST_2BG "\n", res - 1);
    session_upload_buffer(sess);
    seekdir(serv->db_dir, 0);
    return res != 0 ? 1 : -1;
}

void describe_append_until_sysspc(buf_t *buf, FILE *sys_file)
{
    fseek(sys_file, 1, SEEK_CUR);
    int ch;
    while ((ch = getc(sys_file)) != SYS_FILE_SPC)
    {
        LOG("[%c] | %d\n", ch, ch);
        assert(ch != EOF);
        buffer_append(buf, (void *) &ch, 1);
    }
}

void describe_form_msg(buf_t *buf, FILE *sys_file)
{
    buffer_appendf(buf, "Description: ");
    describe_append_until_sysspc(buf, sys_file);
    buffer_appendf(buf, "Owner: ");
    describe_append_until_sysspc(buf, sys_file);
    buffer_appendf(buf, "Last edit: ");
    describe_append_until_sysspc(buf, sys_file);
}

int handle_req_describe(serv_t *serv, sess_t *sess)
{
    UNUSED1(serv);
    buf_t *buf = sess->buf;
    if (!(buf->used >= sizeof(CMD_DSC) - 1 && !CMDMEMCMP(buf->ptr, CMD_DSC)))
        return 0;
    LOG("Use this handle...\n");
    if (buffer_count_argc(buf) != 2)
    {
        session_send_str(sess, DSC_USG "\n");
        return 1;
    }
    buffer_append(buf, "\0", 1);
    buffer_move_left(buf, sizeof(CMD_DSC)); /* discard command from buffer */
    FILE *sys_file = open_sys_file((char *) buf->ptr, "r");
    if (!sys_file)
    {
        session_send_str(sess, DSC_FOP "\n");
        return -1;
    }
    fseek(sys_file, 1, SEEK_SET);
    buffer_clear(buf);
    describe_form_msg(buf, sys_file);
    session_upload_buffer(sess);
    fclose(sys_file);
    return 1;
}

int handle_req_close(serv_t *serv, sess_t *sess)
{
    UNUSED1(serv);
    buf_t *buf = sess->buf;
    if (!(buf->used >= sizeof(CMD_EXIT) - 1 && !CMDMEMCMP(buf->ptr, CMD_EXIT)))
        return 0;
    LOG("Use this handle...\n");
    session_send_str(sess, DMD_SIL TERM_MSG "\n");
    sess->state = sst_disc;
    return 1;
}

int handle_req_help(serv_t *serv, sess_t *sess)
{
    UNUSED1(serv);
    buf_t *buf = sess->buf;
    if (!(buf->used >= sizeof(CMD_HELP) - 1 && !CMDMEMCMP(buf->ptr, CMD_HELP)))
        return 0;
    LOG("Use this handle...\n");
    sess->state = sst_help;
    return 1;
}

int handle_req_dow_acc(serv_t *serv, sess_t *sess)
{
    UNUSED1(serv);
    buf_t *buf = sess->buf;
    if (!(buf->used >= sizeof(DOW_ACC) - 1 && !CMDMEMCMP(buf->ptr, DOW_ACC)))
        return 0;
    LOG("Use this handle...\n");
    sess->state = sst_upload;
    return 1;
}

#define HDL_REQ(req, serv, sess) \
    do { \
        if (handle_req_ ##req(serv, sess)) \
        { \
            buffer_clear(sess->buf); \
            return 1; \
        } \
    } while(0)

int handle_lsn_req(serv_t *serv, sess_t *sess)
{
    if (sess->state != sst_lsn_req)
        return 0;

    buf_t *buf = sess->buf;
    LOG("Request: '%.*s'\n", (int) buf->used, (char *) buf->ptr);

    HDL_REQ(empty, serv, sess);
    HDL_REQ(login, serv, sess);
    HDL_REQ(register, serv, sess);
    HDL_REQ(download, serv, sess);
    HDL_REQ(upload, serv, sess);
    HDL_REQ(list, serv, sess);
    HDL_REQ(describe, serv, sess);
    HDL_REQ(help, serv, sess);
    HDL_REQ(close, serv, sess);
    HDL_REQ(dow_acc, serv, sess);

    /* Default case */
    LOG("Unknown command has been passed\n");
    session_send_str(sess, UNK_MSG "\n");
    buffer_clear(buf);
    return 1;
}

int check_username_len(unsigned n)
{
    if (n <= 3)
        return 1;
    else if (n > 64)
        return 2;
    return 0;
}

int check_username_chs(const char *usr, unsigned bytes)
{
    for (; bytes; bytes--, usr++)
        if (!(*usr >= '!' && *usr <= '~'))
            return 1;
    return 0;
}

int check_username(sess_t *sess)
{
    const buf_t *buf = sess->buf;
    const char *username = (char *) buf->ptr;
    LOG("Given username: '%s'\n", username);
    const unsigned len = buf->last_read_bytes;
    int res = check_username_len(len);
    if (res == 1)
        HDL_ERR_CHANGE_STATE(sess, sst_lsn_usr, 1, 1, USR_2SH);
    if (res == 2)
        HDL_ERR_CHANGE_STATE(sess, sst_lsn_usr, 1, 1, USR_2LN);
    if (check_username_chs(username, len))
        HDL_ERR_CHANGE_STATE(sess, sst_lsn_usr, 1, 1, USR_UCH);
    return 0;
}

int handle_lsn_usr(serv_t *serv, sess_t *sess)
{
    UNUSED1(serv);
    if (sess->state != sst_lsn_usr)
        return 0;

    buffer_append(sess->buf, "\0", 1);
    if (check_username(sess))
        return 1;
    else
        sess->state = sst_ask_pwd;
    return 1;
}

int user_try_enter(sess_t *sess, user_t *orig_usr, const user_t *input_usr)
{
    LOG("\n");
    if (!orig_usr)
        HDL_ERR_CHANGE_STATE(sess, sst_lsn_usr, -1, 1, USR_NFN);
    if (strcmp(orig_usr->password, input_usr->password))
        HDL_ERR_CHANGE_STATE(sess, sst_lsn_usr, -2, 1, PWD_INC);
    session_send_str(sess, LOG_SUC "\n");
    sess->usr = orig_usr;
    sess->state = sst_lsn_req;
    sess->action = cac_unk;
    return 1;
}

int user_try_create(serv_t *serv, sess_t *sess, const user_t *found_usr,
    user_t *input_usr)
{
    LOG("\n");
    if (found_usr)
        HDL_ERR_CHANGE_STATE(sess, sst_lsn_usr, -1, 1, USR_TKN);
    LOG("New user has registered - '%s'\n", input_usr->username);
    input_usr = user_create(
        input_usr->username, input_usr->password, 0); /* duplicate */
    user_push_back(&serv->users, input_usr);
    session_send_str(sess, REG_SUC "\n");
    sess->state = sst_lsn_req;
    sess->action = cac_unk;
    return 1;
}

int check_password_len(unsigned len)
{
    return check_username_len(len);
}

int check_password_chs(const char *pwd, unsigned bytes)
{
    return check_username_chs(pwd, bytes);
}

int check_password(sess_t *sess)
{
    buf_t *buf = sess->buf;
    char *password = strfind((char *) sess->buf->ptr, '\0') + 1;
    const unsigned len = buf->last_read_bytes;
    assert(password != (char *) 1);
    assert(strnfind(password, '\0', len + 1) != NULL);
    LOG("Given password: '%s'\n", password);
    int res = check_password_len(len);
    if (res == 1)
        HDL_ERR_CHANGE_STATE(sess, sst_lsn_req, 1, 1, PWD_2SH);
    if (res == 2)
        HDL_ERR_CHANGE_STATE(sess, sst_lsn_req, 1, 1, PWD_2LN);
    if (check_password_chs(password, len))
        HDL_ERR_CHANGE_STATE(sess, sst_lsn_req, 1, 1, PWD_UCH);
    LOG("Password is ok\n");
    return 0;
}

int handle_lsn_pwd(serv_t *serv, sess_t *sess)
{
    if (sess->state != sst_lsn_pwd)
        return 0;

    buf_t *buf = sess->buf;
    buffer_append(buf, "\0", 1);
    LOG("\n");
    buffer_print_bin(buf);
    if (check_password(sess))
        return 1;

    user_t usr, *found;
    usr.username = (char *) buf->ptr;
    usr.password = strfind((char *) buf->ptr, '\0') + 1;
    assert(usr.password != (char *) 1);

    found = user_find(serv->users, usr.username);
    assert(sess->action == cac_log || sess->action == cac_reg);
    if (sess->action == cac_log)
        user_try_enter(sess, found, &usr);
    else
        user_try_create(serv, sess, found, &usr);
    buffer_clear(buf);
    return 1;
}

int handle_lsn_dwn(serv_t *serv, sess_t *sess)
{
    UNUSED1(serv);
    if (sess->state != sst_download)
        return 0;

    buf_t *buf = sess->buf;
    LOG("\n");
    sess->to_download -= buf->used;
    int res = write(sess->udfd, buf->ptr, buf->used);
    if (res == -1)
        PELOG("Failed to write download file");
    if (buf->used != buf->size)
    {
        LOG("A file has been downloaded successfully\n");
        assert(buf->used < buf->size);
        close(sess->udfd);
        sess->udfd = 0;
        sess->state = sst_lsn_req;
    }
    buffer_clear(buf);
    return 1;
}

int handle_str_write(sess_t *sess, const char *str, com_state cur_sst,
    com_state next_sst)
{
    if (sess->state != cur_sst)
        return 0;
    sess->state = next_sst;
    return session_send_str(sess, str);
}

int handle_buf_write(sess_t *sess, const buf_t *buf, com_state cur_sst,
    com_state next_sst)
{
    if (sess->state != cur_sst)
        return 0;
    sess->state = next_sst;
    return session_send_data(sess, buf->ptr, buf->used);
}

#define _HDL_RES(code) \
    do { \
        if (code) \
            LOG("Return value: '%d'\n", code); \
        if (code == -1) \
            LOG_RET(-1); /* disconnect */ \
        else if (code > 0) \
            LOG_RET(1); \
    } while (0)

#define HDL_LSN(lsn_to, serv, sess) \
    do { \
        res = handle_lsn_ ##lsn_to (serv, sess); \
        _HDL_RES(res); \
    } while (0)

int handle_lsn_states(serv_t *serv, sess_t *sess)
{
    LOG_E("\n");
    int res;
    HDL_LSN(auth, serv, sess);
    HDL_LSN(req, serv, sess);
    HDL_LSN(usr, serv, sess);
    HDL_LSN(pwd, serv, sess);
    HDL_LSN(dwn, serv, sess);
    LOG_L("\n");
    return 1;
}

int handle_client_read(serv_t *serv, sess_t *sess, fd_set *readfds)
{
    if (!FD_ISSET(sess->cfd, readfds))
        return 0;

    LOG_E("\n");
    buf_t *buf = sess->buf;

    if (session_receive_data(sess) <= 0)
        LOG_RET(-1);
    buffer_print_bin(buf);

    handle_lsn_states(serv, sess);
    if (control_buffer_fullness(sess))
        LOG_RET(-1);
    LOG_L("\n");
    return 1;
}

#define HDL_BWRITE(sess, buf, cur_sst, next_sst) \
    do { \
        res = handle_buf_write(sess, buf, cur_sst, next_sst); \
        _HDL_RES(res); \
    } while (0)
#define HDL_SWRITE(sess, str, cur_sst, next_sst) \
    do { \
        res = handle_str_write(sess, str, cur_sst, next_sst); \
        _HDL_RES(res); \
    } while (0)

int handle_client_upload(serv_t *serv, sess_t *sess, fd_set *readfds)
{
    UNUSED1(serv);
    if (sess->state != sst_upload || !FD_ISSET(sess->cfd, readfds))
        return 0;
    LOG_E("\n");

    buf_t *buf = sess->buf;
    assert(buf->used == 0);

    int res = read(sess->udfd, buf->ptr, buf->size);
    LOG("Read bytes %d\n", res);
    if (res == -1)
    {
        PELOG_L("Failed to read data");
        close(sess->udfd);
        sess->state = sst_err;
        return 1;
    }
    if (res != 0)
        res = session_send_data(sess, buf->ptr, res);
    else
    {
        LOG("Closing upload file\n");
        sess->state = sst_lsn_req;
        close(sess->udfd);
    }

    if (res == -1)
    {
        close(sess->udfd);
        sess->state = sst_err;
    }
    LOG_L("\n");
    return 1;
}

int handle_client_write(serv_t *serv, sess_t *sess, fd_set *writefds)
{
    if (!FD_ISSET(sess->cfd, writefds))
        return 0;
    LOG_E("\n");
    int res;
    if ((res = handle_client_upload(serv, sess, writefds)))
        _HDL_RES(res);
    HDL_BWRITE(sess, serv->intro,       sst_intro,     sst_lsn_req);
    HDL_BWRITE(sess, sess->buf,         sst_upload,    sst_upload);
    HDL_SWRITE(sess, HLP_MSG "\n",      sst_help,      sst_lsn_req);
    HDL_SWRITE(sess, DMD_SIL USR_ASK,   sst_ask_usr,   sst_lsn_usr);
    HDL_SWRITE(sess, DMD_SIL PWD_ASK,   sst_ask_pwd,   sst_lsn_pwd);
    LOG_EX("An unhandled communication state has been catched\n");
}

void move_sess_ptrs(buf_t *sess_buf, void *base_ptr)
{
    const unsigned offset = base_ptr - sess_buf->ptr;
    const unsigned to_move = sess_buf->used - offset;
    memmove(base_ptr, base_ptr + sizeof(sess_t *), to_move);
    memset(base_ptr + to_move, 0, sizeof(sess_t *));
    LOG("'%u' sessions have been moved to left\n", to_move);
}

void terminate_session(buf_t *sess_buf, sess_t **sess)
{
    const com_state exit_status = (*sess)->state;
    const int fd = (*sess)->cfd;
    assert((*sess)->state != sst_unk);
    close((*sess)->cfd);
    session_delete(*sess);
    sess_buf->used -= sizeof(sess_t *);
    move_sess_ptrs(sess_buf, (void *) sess);
    printf("Session with client %d has been terminated %s\n",
        fd, exit_status == sst_err ? "due an error" : "on his own will");
}

void check_io(serv_t *serv, fd_set *readfds, fd_set *writefds)
{
    LOG_E("\n");
    /*
     * TODO Work with it as a buffer instead of ptr to ptr
     */
    sess_t **sess_arr = (sess_t **) serv->sess_buf->ptr;
    while (*sess_arr)
    {
        sess_t *sess = *sess_arr;
        LOG("Iteration for '%p'\n", (void *) sess_arr);
        if (handle_client_read(serv, sess, readfds) ||
            handle_client_write(serv, sess, writefds))
        {
            if (sess->state == sst_disc || sess->state == sst_err)
            {
                terminate_session(serv->sess_buf, sess_arr);
                continue;
            }
        }
        sess_arr++;
    }
    LOG_L("\n");
}

int handle_events(int code, serv_t *serv, fd_set *readfds, fd_set *writefds)
{
    LOG_E("\n");
    if (was_signaled(code))
        LOG_RET(0);
    else if (check_err(code))
        LOG_RET(-1);
    check_listen(serv, readfds);
    check_io(serv, readfds, writefds);
    LOG_L("\n");
    return 1;
}

int serv_start(serv_t *serv)
{
    LOG_E("\n");
    fd_set readfds, writefds;
    work = 1; /* may be changed by SIGINT */
    while (work) /* Main loop */
    {
        /* Select events */
        int res = mselect(serv, &readfds, &writefds);
        LOG("Select has returned '%d'\n", res);

        /* Handle events */
        if (handle_events(res, serv, &readfds, &writefds) == -1)
            LOG_RET(-1);
        write(1, "\n\n", 2);
    }
    write(1, "\n" TERM_MSG "\n", sizeof(TERM_MSG) + 2);
    save_db(serv);
    close(serv->db_fd);
    LOG_L("\n");
    return 0;
}
