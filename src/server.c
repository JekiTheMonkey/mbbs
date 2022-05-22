#include "buffer.h"
#include "log.h"
#include "serv_cfg.h"
#include "server.h"
#include "session.h"
#include "user.h"
#include "utility.h"

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

#define LOG_RET(code) do { LOG_L("\n"); return code; } while(0)
#define ERR_TRY_AGAIN(sess, sst, code, clr_buf, msg) \
    do { \
        if (clr_buf) \
            buffer_clear(sess->buf); \
        session_send_str(sess, msg ". Try again.\n"); \
        sess->state = sst; \
        return code; \
    } while(0)

#define DMD_SIL "DMD_SIL" /* Demand silence on client side - no invite msg */
#define ASK_USR "Enter your username: "
#define ASK_PWD "Enter your password: "
#define CMD_LOG "login"
#define CMD_REG "register"
#define CMD_EXIT "close"
#define TERM_MSG "Terminating own work..."
#define CMD_HLP "help"
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
    "   " CMD_HLP  " \tSee this message\n" \
    "   " CMD_EXIT " \tClose connection"
#define UNK_MSG "mbbs: Unknown command. Try '" CMD_HLP

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

void print_bin(const char *buf, unsigned n)
{
    for (; n; n--, buf++)
        printf("%d %c\n", *buf, *buf <= 32 ? ' ' : *buf);
}

void print_buf_bin(buffer *buf)
{
    print_bin((char *) buf->ptr, buf->used);
}

void create_dir_if_not_exists(const char *path)
{
    if (access(path, F_OK))
    {
        LOG("Missing directory '%s'\n", path);
        if (mkdir(path, 0700))
            ELOG_EX("Failed to create directory '%s'", path);
        LOG("Created directory '%s'\n", path);
    }
}

char *get_db_file_path(const server *serv, const char *file)
{
    const unsigned db_dir_len = strlen(serv->cfg->db_dir);
    const unsigned file_len = strlen(file);
    char *path = (char *) malloc(db_dir_len + file_len + 2); /* +2 for / and \0 */
    ANLOG(path, db_dir_len + file_len);
    sprintf(path, "%s/%s", serv->cfg->db_dir, file);
    LOG("Formed filepath: '%s'\n", path);
    return path;
}

void try_create_default_intro(const char *path)
{
    if (!access(path, F_OK))
        return;
    int fd = open(path, O_WRONLY | O_CREAT, 0700);
    int res = write(fd, "\n" LOGO "\n", sizeof(LOGO) + 2);
    if (res == -1)
        ELOG("Failed to write default intro to '%s'", path);
}

void alloc_intro(server *serv, int intro_fd)
{
    const off_t size = lseek(intro_fd, 0, SEEK_END);
    lseek(intro_fd, 0, SEEK_SET);
    serv->intro = buffer_create(size + 1);
}

int read_intro(server *serv, int intro_fd)
{
    buffer *buf = serv->intro;
    int res = read(intro_fd, buf->ptr, buf->size);
    if (res == -1)
        PELOG_EX("Failed to read intro file");
    LOG("Read intro is '%d' bytes long\n", res);
    memset(buf->ptr + res, 0, 1); /* terminating zero */
    return res + 1;
}

void init_intro(server *serv)
{
    char *path = get_db_file_path(serv, DEF_INTRO_FILE);
    try_create_default_intro(path);

    int fd = open(path, O_RDONLY);
    if (fd == -1)
        ELOG_EX("Failed to open file '%s'", path);

    alloc_intro(serv, fd);
    serv->intro->used = read_intro(serv, fd);

    close(fd);
    FREE(path);
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
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
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

int create_server_socket(const serv_cfg *cfg)
{
    int fd = create_socket();
    allow_reuse_port(fd);
    bind_socket(fd, &cfg->addr);
    make_listening(fd);
    LOG("Server socket has been created successfully\n");
    return fd;
}

void open_db_fd(server *serv)
{
    char *path = get_db_file_path(serv, DEF_USR_FILE);
    serv->db_fd = open(path, O_RDWR | O_CREAT, 0700);
    if (serv->db_fd == -1)
        ELOG_EX("Failed to open or create database file '%s'", path);
    FREE(path);
}

void read_db(server *serv)
{
    int res, occupied = 0, linelen, tot_bytes;
    char buf[64], *line_l_it, *line_r_it;
    char *usr_p, *pwd_p;
    int usr_len, pwd_len;
    user *usr;
    while ((res =
        read(serv->db_fd, buf + occupied, sizeof(buf) - occupied)) > 0)
    {
        line_l_it = buf;
        occupied += res;
        tot_bytes = occupied;
        while ((line_r_it = strnfind(line_l_it, '\n', occupied)))
        {
            linelen = line_r_it - line_l_it;
            occupied -= linelen + 1; /* + 1 due trailing lf  */

            usr_p = line_l_it;
            pwd_p = strnfind(line_l_it, ' ', linelen) + 1;
            if (pwd_p == (char *) 1)
                LOG_EX("Data is of wrong format\n");

            usr_len = pwd_p - usr_p - 1;
            pwd_len = line_r_it - pwd_p;
            usr_p[usr_len] = '\0';
            pwd_p[pwd_len] = '\0';

            LOG("Read username '%.*s'\n", usr_len, usr_p);
            LOG("Read password '%.*s'\n", pwd_len, pwd_p);

            usr = user_create(usr_p, pwd_p);
            user_push_back(&serv->users, usr);

            line_l_it = line_r_it + 1;
        }
        memmove(buf, buf + tot_bytes - occupied, occupied);
    }
    if (res == -1)
        ELOG_EX("Failed to read from database file");
    user_print(serv->users);
}

void save_db(const server *serv)
{
    LOG_E("\n");
    char buf[512];
    const user *it = serv->users;
    lseek(serv->db_fd, 0, SEEK_SET);
    for (; it; it = it->next)
    {
        int res = sprintf(buf, "%s %s\n", it->username, it->password);
        if (write(serv->db_fd, buf, res) == -1)
            ELOG_EX("Failed to save database record");
        LOG("Write '%.*s'\n", res - 1, buf);
    }
    LOG_L("\n");
}

void init_db(server *serv)
{
    serv->users = NULL;
    open_db_fd(serv);
    read_db(serv);
}

void init_sess_buf(server *serv)
{
    const size_t to_alloc = SESS_ARRAY_INIT_SIZE * sizeof(session *);
    serv->sess_buf = buffer_create(to_alloc);
    memset(serv->sess_buf->ptr, 0, to_alloc);
}

int serv_init(server *serv, char **argv)
{
    LOG_E("\n");
    signal(SIGINT, &sigint_handler);

    serv->cfg = (serv_cfg *) malloc(sizeof(serv_cfg));
    init_cfg(serv->cfg, argv);
    create_dir_if_not_exists(serv->cfg->db_dir);

    init_intro(serv);

    serv->ls = create_server_socket(serv->cfg);
    init_db(serv);
    init_sess_buf(serv);

    LOG_L("Server has been initilized successfully\n");
    return 1;
}

void set_fd(com_state state, int fd, fd_set *readfds, fd_set *writefds)
{
    switch (state)
    {
        /* Read states */
        case sst_lsn_auth:
        case sst_lsn_req:
        case sst_lsn_usr:
        case sst_lsn_pwd:
            FD_SET(fd, readfds); break;

        /* Write states */
        case sst_intro:
        case sst_help:
        case sst_ask_usr:
        case sst_ask_pwd:
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

int init_fds(fd_set *readfds, fd_set *writefds, const server *serv)
{
    int fd, maxfd = serv->ls;
    buffer *sess_buf = serv->sess_buf;
    session **sess_arr = (session **) sess_buf->ptr;
    unsigned i, size = sess_buf->used / sizeof(session *);

    FD_ZERO(readfds);
    FD_ZERO(writefds);
    FD_SET(serv->ls, readfds);
    for (i = 0; i < size; i++)
    {
        LOG("Iteration '%d'. Session state '%d'\n", i + 1, sess_arr[i]->state);
        fd = sess_arr[i]->fd;
        set_fd(sess_arr[i]->state, fd, readfds, writefds);
        if (maxfd < fd)
            maxfd = fd;
    }

    LOG("'%d' - maxfd\n", maxfd);
    return maxfd;
}

int mselect(const server *serv, fd_set *readfds, fd_set *writefds)
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

void realloc_sess_buf(buffer *sess_buf)
{
    const size_t newlen = sess_buf->size + SESS_ARRAY_INIT_SIZE;
    session **sess_arr = (session **) sess_buf->ptr;
    sess_arr = (session **) realloc(sess_arr, newlen);
    LOG("Realloc for '%p' from '%lu' to '%lu'\n",
        sess_arr, sess_buf->size, newlen);
    memset(sess_arr + sess_buf->size, 0, SESS_ARRAY_INIT_SIZE);
    buffer_set_size(sess_buf, newlen);
}

session *add_session(server *serv, int cfd)
{
    buffer *sess_buf = serv->sess_buf;
    session **sess_arr = (session **) sess_buf->ptr;
    size_t index = sess_buf->used / sizeof(session *);

    if (cfd >= (int) sess_buf->size)
        realloc_sess_buf(sess_buf);

    assert(!sess_arr[index]);
    sess_arr[index] = session_create(cfd);
    sess_arr[index]->state = sst_lsn_auth;
    sess_buf->used += sizeof(session *);

    LOG("New session has been created. Up sessions - '%lu'\n", index + 1);
    return sess_arr[index];
}

void check_listen(server *serv, fd_set *readfds)
{
    if (!FD_ISSET(serv->ls, readfds))
        return;
    LOG_E("\n");
    struct sockaddr_in *cli_addr =
        (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
    int cfd = accept_client(serv->ls, cli_addr);
    if (!cfd)
        LOG_RET();
    session *sess = add_session(serv, cfd);
    sess->addr = cli_addr;
    LOG_L("\n");
}

int was_signaled(int code)
{
    return code == -1 && errno == EINTR;
}

int control_buffer_fullness(session *sess)
{
    const buffer *buf = sess->buf;
    if (buf->used != buf->size)
        return 0;
    LOG("Input line is too long, terminate connection with a client\n");
    LOG("Your input line is too long, bye...\n");
    sess->state = sst_err;
    return 1;
}

int session_receive_data(session *sess)
{
    int res;
    buffer *buf = sess->buf;
    do {
        res = read(sess->fd, buf->ptr + buf->used, buf->size - buf->used);
    } while (was_signaled(res));

    if (res == -1)
        PELOG("Failed to read");
    else if (res == 0)
        LOG("EOF has been read\n");
    if (res <= 0)
    {
        sess->state= res ? sst_err : sst_disc;
        return -1;
    }

    buf->used += res;
    buf->last_read_bytes = res;
    LOG("'%d' bytes have been read\n", res);
    return res;
}

int session_send_data(session *sess, const void *data, size_t bytes)
{
    int res;
    do {
        res = write(sess->fd, data, min(bytes, MAX_WRITE_BYTES));
    } while (was_signaled(res));
    LOG("'%d' bytes have been written\n", res);

    if (res == -1)
    {
        ELOG("Failed to write");
        sess->state = sst_err;
        return -1;
    }
    return res;
}

int session_send_str(session *sess, const char *str)
{
    return session_send_data(sess, str, strlen(str));
}

int session_upload_buffer(session *sess)
{
    return session_send_data(sess, sess->buf->ptr, sess->buf->used);
}

#define STRNCMP(lhs, rhs, len) \
    ((len) == sizeof((rhs)) - 1 && !strncmp(lhs, rhs, len))
int handle_lsn_auth(server *serv, session *sess)
{
    UNUSED1(serv);
    if (sess->state != sst_lsn_auth)
        return 0;

    buffer *buf = sess->buf;
    const char *auth = (char *) buf->ptr;
    const unsigned len = buf->used;
    LOG("Authorization key: '%.*s'\n", len, auth);

    if (STRNCMP(auth, AUTH_KEY, len))
        sess->state = sst_intro;
    else
        session_send_str(sess, "Wrong authorization key TODO Timeout\n");
    buffer_clear(buf);
    return 1;
}

int handle_lsn_req(server *serv, session *sess)
{
    UNUSED1(serv);
    if (sess->state != sst_lsn_req)
        return 0;

    buffer *buf = sess->buf;
    buffer_move_right(buf, 1); /* -lf */
    const char *req = (char *) buf->ptr;
    const unsigned len = buf->used;
    LOG("Request: '%.*s'\n", len, req);

    if (STRNCMP(req, CMD_LOG, len))
    {
        sess->state = sst_ask_usr;
        sess->action = cac_log;
    }
    else if (STRNCMP(req, CMD_REG, len))
    {
        sess->state = sst_ask_usr;
        sess->action = cac_reg;
    }
    else if (STRNCMP(req, CMD_EXIT, len))
    {
        session_send_str(sess, DMD_SIL TERM_MSG "\n");
        sess->state = sst_disc;
    }
    else if (STRNCMP(req, CMD_HLP, len))
        sess->state = sst_help;
    else
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

int check_username(session *sess)
{
    buffer *buf = sess->buf;
    char *ch_buf = (char *) buf->ptr;
    LOG("Given username: '%s'\n", ch_buf);
    const unsigned len = buf->last_read_bytes - 1; /* -lf */
    int res = check_username_len(len);
    if (res == 1)
        ERR_TRY_AGAIN(sess, sst_ask_usr, 1, 1, "Username is too short");
    if (res == 2)
        ERR_TRY_AGAIN(sess, sst_ask_usr, 1, 1, "Username is too long");
    if (check_username_chs(ch_buf, len))
        ERR_TRY_AGAIN(sess, sst_ask_usr, 1, 1,
            "Username contains unacceptable character");
    return 0;
}

int handle_lsn_usr(server *serv, session *sess)
{
    UNUSED1(serv);
    if (sess->state != sst_lsn_usr)
        return 0;

    buffer *buf = sess->buf;
    memset(buf->ptr + buf->used - 1, 0, 1); /* lf = \0 */
    if (check_username(sess))
        return 1;
    else
        sess->state = sst_ask_pwd;
    return 1;
}

int user_try_enter(session *sess, const user *orig_usr, user *input_usr)
{
    LOG("\n");
    if (!orig_usr)
        ERR_TRY_AGAIN(sess, sst_ask_usr, -1, 1,
            "No user found with such username");
    if (strcmp(orig_usr->password, input_usr->password))
        ERR_TRY_AGAIN(sess, sst_ask_usr, -2, 1, "Incorrect password");
    session_send_str(sess, "Successful login\n");
    sess->logined = 1;
    sess->state = sst_lsn_req;
    sess->action = cac_unk;
    return 1;
}

int user_try_create(server *serv, session *sess, const user *found_usr,
    user *input_usr)
{
    LOG("\n");
    if (found_usr)
        ERR_TRY_AGAIN(sess, sst_ask_usr, -1, 1, "Username is already taken");
    LOG("New user has registered - '%s'\n", input_usr->username);
    input_usr = user_create(input_usr->username, input_usr->password); /* duplicate */
    user_push_back(&serv->users, input_usr);
    session_send_str(sess, "Your account has been successfully registered.\n");
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

int check_password(session *sess)
{
    buffer *buf = sess->buf;
    char *ch_buf = strfind((char *) sess->buf->ptr, '\0') + 1;
    const unsigned len = buf->last_read_bytes - 1; /* -lf */
    assert(ch_buf != (char *) 1);
    LOG("Given password: '%s'\n", ch_buf);
    int res = check_password_len(len);
    if (res == 1)
        ERR_TRY_AGAIN(sess, sst_ask_usr, 1, 1, "Password is too short");
    if (res == 2)
        ERR_TRY_AGAIN(sess, sst_ask_usr, 1, 1, "Password is too long");
    if (check_password_chs(ch_buf, len))
        ERR_TRY_AGAIN(sess, sst_ask_usr, 1, 1,
            "Password contains unacceptable character");
    return 0;
}

int handle_lsn_pwd(server *serv, session *sess)
{
    if (sess->state != sst_lsn_pwd)
        return 0;

    buffer *buf = sess->buf;
    memset(buf->ptr + buf->used - 1, 0, 1); /* lf = \0 */
    LOG("\n");
    print_buf_bin(buf);
    if (check_password(sess))
        return 1;

    user usr, *found;
    usr.username = (char *) buf->ptr;
    usr.password = strfind((char *) buf->ptr, '\0') + 1;
    assert(usr.password != (char *) 1);

    found = user_find(serv->users, usr.username);
    assert(sess->action == cac_log || sess->action == cac_reg);
    if (sess->action == cac_log)
        user_try_enter(sess, found, &usr);
    else
        user_try_create(serv, sess, found, &usr);
    return 1;
}

int handle_str_write(session *sess, const char *str, com_state cur_sst,
    com_state next_sst)
{
    if (sess->state != cur_sst)
        return 0;
    sess->state = next_sst;
    return session_send_data(sess, str, strlen(str));
}

int handle_buf_write(session *sess, const buffer *buf, com_state cur_sst,
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

int handle_states(server *serv, session *sess)
{
    int res;
    /* TOFIX (maybe I just do something wrong) */
    /* for some reason macro processor can't implictly take AND REMEMBER
       an anonym variable, so return value is saves into 'res' variable instead */
    LOG_E("\n");
    HDL_LSN(auth, serv, sess);
    HDL_LSN(req, serv, sess);
    HDL_LSN(usr, serv, sess);
    HDL_LSN(pwd, serv, sess);
    LOG_L("\n");
    return 1;
}

int handle_client_read(server *serv, session *sess, fd_set *readfds)
{
    if (!FD_ISSET(sess->fd, readfds))
        return 0;

    LOG_E("\n");
    buffer *buf = sess->buf;

    if (session_receive_data(sess) <= 0)
        LOG_RET(-1);
    print_buf_bin(buf);

    handle_states(serv, sess);
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

int handle_client_write(server *serv, session *sess, fd_set *writefds)
{
    if (!FD_ISSET(sess->fd, writefds))
        return 0;
    int res;
    /* TOFIX (maybe I just do something wrong) */
    /* for some reason macro processor can't implictly take AND REMEMBER
       an anonym variable, so return value is saves into 'res' variable instead */
    LOG_E("\n");
    HDL_BWRITE(sess, serv->intro,       sst_intro,     sst_lsn_req);
    HDL_SWRITE(sess, HLP_MSG "\n",      sst_help,      sst_lsn_req);
    HDL_SWRITE(sess, DMD_SIL ASK_USR,   sst_ask_usr,   sst_lsn_usr);
    HDL_SWRITE(sess, DMD_SIL ASK_PWD,   sst_ask_pwd,   sst_lsn_pwd);
    LOG("An unhandled communication state has been found\n");
    exit(1);
}

void move_sess_ptrs(buffer *sess_buf, void *base_ptr)
{
    const unsigned offset = base_ptr - sess_buf->ptr;
    const unsigned to_move = sess_buf->used - offset;
    LOG("Base ptr '%p' buf_ptr '%p' offset '%u' to_move '%u'\n",
        base_ptr, sess_buf->ptr, offset, to_move);
    memmove(base_ptr, base_ptr + sizeof(session *), to_move);
    memset(base_ptr + to_move, 0, sizeof(session *));
    LOG("'%u' has been moved to left\n", to_move);
}

void terminate_session(buffer *sess_buf, session **sess)
{
    const com_state exit_status = (*sess)->state;
    const int fd = (*sess)->fd;
    assert((*sess)->state != sst_unk);
    close((*sess)->fd);
    session_delete(*sess);
    sess_buf->used -= sizeof(session *);
    move_sess_ptrs(sess_buf, (void *) sess);
    printf("Session with client %d has been terminated %s\n",
        fd, exit_status == sst_err ? "due an error" : "on his own will");
}

void check_io(server *serv, fd_set *readfds, fd_set *writefds)
{
    LOG_E("\n");
    /* TODO work with it as a buffer instead of ptr to ptr */
    session **sess_arr = (session **) serv->sess_buf->ptr;
    while (*sess_arr)
    {
        session *sess = *sess_arr;
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

int handle_events(int code, server *serv, fd_set *readfds, fd_set *writefds)
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

int serv_start(server *serv)
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
