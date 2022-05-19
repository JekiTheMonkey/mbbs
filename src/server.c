#include "server.h"
#include "log.h"
#include "serv_cfg.h"
#include "utility.h"
#include "session.h"
#include "buffer.h"

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
        if (mkdir(path, 0700))
            ELOG_EX("Failed to create directory '%s'", path);
        LOG("Created directory '%s'\n", path);
    }
}

char *init_intro_filepath(server *serv)
{
    const char intro_def_name[] = "/_intro.txt";
    const size_t db_dir_len = strlen(serv->cfg->db_dir);
    char *path = (char *) malloc(db_dir_len + sizeof(intro_def_name));
    ANLOG(path, db_dir_len + sizeof(intro_def_name));

    memcpy(path, serv->cfg->db_dir, db_dir_len);
    memcpy(path + db_dir_len, intro_def_name, sizeof(intro_def_name));

    LOG("Formed filepath: '%s'\n", path);
    return path;
}

void try_create_default_intro(const char *path)
{
    if (!access(path, F_OK))
        return;
    int fd = open(path, O_WRONLY | O_CREAT, 0700);
    int res = write(fd, default_intro, strlen(default_intro));
    if (res == -1)
        ELOG("Failed to write default intro to '%s'", path);
}

void alloc_intro(server *serv, int intro_fd)
{
    const off_t size = lseek(intro_fd, 0, SEEK_END);
    lseek(intro_fd, 0, SEEK_SET);
    serv->intro = buffer_create(size + 1);
}

void read_intro(server *serv, int intro_fd)
{
    int res = read(intro_fd, serv->intro->ptr, serv->intro->size);
    if (res == -1)
        ELOG_EX("Failed to read intro file");
    LOG("Read intro is '%d' bytes long\n", res);
    memset(serv->intro->ptr + res, 0, 1); /* terminating zero */
}

void init_intro(server *serv)
{
    char *path = init_intro_filepath(serv);
    try_create_default_intro(path);

    int fd = open(path, O_RDONLY);
    if (fd == -1)
        ELOG_EX("Failed to open file '%s'", path);

    alloc_intro(serv, fd);
    read_intro(serv, fd);

    close(fd);
    free(path);
}

void init_inv_msg(server *serv)
{
    const size_t len = strlen(default_inv_msg);
    serv->inv_msg = buffer_create(len + 1);
    memcpy(serv->inv_msg->ptr, default_inv_msg, len + 1);
    /* TODO make it possible to get inv msg from some non hardcoded source */
}

void init_sess_buf(server *serv)
{
    const size_t to_alloc = SESS_ARRAY_INIT_SIZE * sizeof(session *);
    serv->sess_buf = buffer_create(to_alloc);
    memset(serv->sess_buf->ptr, 0, to_alloc);
}

int create_socket()
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
        ELOG_EX("Failed to create a socket");
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
        PERROR("Failed to bind a socket");
    LOG("Server socket has been binded to '%s::%d'\n",
        inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
}

void make_listening(int fd)
{
    if (listen(fd, 16) == -1)
        PERROR("Failed to make a listening socket");
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

int serv_init(server *serv, char **argv)
{
    LOG_E("\n");
    signal(SIGINT, &sigint_handler);

    serv->cfg = (serv_cfg *) malloc(sizeof(serv_cfg));
    init_cfg(serv->cfg, argv);
    create_dir_if_not_exists(serv->cfg->db_dir);

    init_intro(serv);
    init_inv_msg(serv);

    serv->ls = create_server_socket(serv->cfg);
    init_sess_buf(serv);

    LOG_L("Server has been initilized successfully\n");
    return 1;
}

void set_fd(int e_com_state, int fd, fd_set *readfds, fd_set *writefds)
{
    switch (e_com_state)
    {
        case sst_intro:
        case sst_inv_msg:
            FD_SET(fd, writefds); break;
        case sst_lsn_req:
            FD_SET(fd, readfds); break;
        default:
            LOG("Default case has been triggered\n"); exit(1);
    }
    LOG("'%d' has been added to a fd_set according to its state(%d)\n",
        fd, e_com_state);
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
        LOG("Iteration '%d'\n", i + 1);
        fd = sess_arr[i]->fd;
        set_fd(sess_arr[i]->e_com_state, fd, readfds, writefds);
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
    return code == -1 && errno == EINTR; /* return 1 on error */
}

int accept_client(int ls)
{
    struct sockaddr_in cli_addr;
    socklen_t slen = sizeof(cli_addr);
    int cfd = accept(ls, (struct sockaddr *) &cli_addr, &slen);
    if (cfd == -1)
    {
        ELOG("Failed to accept a client\n");
        return 0;
    }
    printf("Client %d with IP %s::%d has been accepted\n",
        cfd, inet_ntoa(cli_addr.sin_addr), cli_addr.sin_port);
    return cfd;
}

session *add_session(server *serv, int cfd)
{
    buffer *sess_buf = serv->sess_buf;
    session **sess_arr = (session **) sess_buf->ptr;
    size_t index = sess_buf->used / sizeof(session *);

    if (sess_buf->used == sess_buf->size)
    {
        sess_arr = (session **) realloc(sess_arr,
            sess_buf->size + SESS_ARRAY_INIT_SIZE);
        LOG("Realloc for '%p' from '%lu' to '%lu'\n",
            sess_arr, sess_buf->size, sess_buf->size + SESS_ARRAY_INIT_SIZE);
    }
    if (!sess_arr[index])
        sess_arr[index] = session_create(cfd);

    session *sess = sess_arr[index];
    sess->e_com_state = sst_intro;
    sess_buf->used += sizeof(session *);

    LOG("New session has been created. Up sessions - '%lu'\n", index + 1);
    return sess;
}

void check_listen(server *serv, fd_set *readfds)
{
    if (!FD_ISSET(serv->ls, readfds))
        return;
    LOG_E("\n");
    int cfd = accept_client(serv->ls);
    if (!cfd)
    {
        LOG_L("\n");
        return;
    }
    session *sess = add_session(serv, cfd);
    UNUSED1(sess);
    LOG_L("\n");
}

int was_signaled(int code)
{
    return code == -1 && errno == EINTR;
}

void find_lfcr(const buffer *buf, char **lf, char **cr)
{
    *lf = strnfind(buf->ptr, '\n', buf->used);
    if (!lf)
        return;
    /* don't search for CR if there is no LF */
    *cr= strnfind(buf->ptr, '\r', buf->used);
}

int handle_lf(session *sess)
{
    buffer *buf = sess->buf;
    char *lf, *cr;
    find_lfcr(buf, &lf, &cr);
    if (!lf)
        return 1;
    const int drop_n_ch = !!lf + !!cr; /* telnet may send \r */

    /* Analyze request text instead */
    /* TOREMOVE */
    const size_t to_move = lf - (char *) buf->ptr + 1;
    LOG("To move '%lu'\n", to_move);

    /* int i; */
    /* for (i = 0; i < (int) to_move; i++) */
    /*     printf("%d ", ((unsigned char *)(buf->ptr))[i]); */
    /* putchar(10); */

    printf("Client(%d) said: ", sess->fd);
    printf("'%.*s'\n", (int) to_move - drop_n_ch, (char *) buf->ptr);

    buf->used -= to_move;
    memmove(buf->ptr, buf->ptr + to_move, buf->used);
    LOG("'%lu' bytes have been moved to left\n", to_move);
    sess->e_com_state = sst_inv_msg;

    if (write(sess->fd, "Ok\n", 3) == -1)
    {
        sess->e_exit_status = exst_err;
        ELOG("Failed to write to a client");
        return -1;
    }
    return 0;
}

int handle_read(session *sess, int cur_sst, int next_sst)
{
    int res;
    buffer *buf = sess->buf;
    if ((int) sess->e_com_state != cur_sst)
        return 0;

    LOG_E("\n");
    do {
        res = read(sess->fd, buf->ptr + buf->used, buf->size - buf->used);
    } while (was_signaled(res));

    if (res == -1)
        ELOG_L("Failed to read");
    else if (res == 0)
        LOG_L("EOF has been read\n");
    if (res <= 0)
    {
        sess->e_exit_status = res ? exst_err : exst_eof;
        return -1;
    }

    buf->used += res;
    LOG("'%d' bytes have been read\n", res);

    int lf = handle_lf(sess);
    if (lf == -1)
        LOG_RET(-1);
    if (lf == 1)
    {
        sess->e_com_state = next_sst;
        LOG_L("Read operation has been terminated, state has been changed\n");
    }
    else
        LOG_L("\n");

    return res;
}

#define HDL_READ(sess, cur_sst, next_sst) \
    res = handle_read(sess, cur_sst, next_sst); \
    if (res == -1) \
        LOG_RET(1); /* disconnect */ \
    else if (res > 0) \
        LOG_RET(0)

int handle_client_read(server *serv, session *sess, fd_set *readfds)
{
    if (!FD_ISSET(sess->fd, readfds))
        return 0;
    int res;

    LOG_E("\n");
    HDL_READ(sess, sst_lsn_req, 0);
    LOG_L("\n");

    return 0;

    UNUSED1(serv);
}

int handle_write(session *sess, buffer *write_buf, int cur_sst, int next_sst)
{
    int res;
    size_t written_bytes = sess->written_bytes;
    if ((int) sess->e_com_state != cur_sst)
        return 0;

    LOG_E("\n");
    assert(write_buf->size > written_bytes);
    LOG("Written bytes so far '%lu', to write '%lu'\n",
        written_bytes, write_buf->size - written_bytes);
    do {
        res = write(sess->fd, write_buf->ptr, min(MAX_WRITE_BYTES,
            write_buf->size - written_bytes));
    } while (was_signaled(res));

    if (res == -1)
    {
        ELOG_L("Failed to write");
        sess->e_exit_status = exst_err;
        return -1;
    }

    sess->written_bytes += res;
    if (res < MAX_WRITE_BYTES)
    {
        sess->written_bytes = 0;
        sess->e_com_state = next_sst;
        LOG("'%d' bytes have been written\n", res);
        LOG_L("Write operation has been terminated, state has been changed\n");
    }
    else
        LOG_L("'%d' bytes have been written\n", res);
    return res;
}

#define HDL_WRITE(sess, buf, cur_sst, next_sst) \
    res = handle_write(sess, buf, cur_sst, next_sst); \
    if (res == -1) \
        LOG_RET(1); /* disconnect */ \
    else if (res > 0) \
        LOG_RET(0);

int handle_client_write(server *serv, session *sess, fd_set *writefds)
{
    if (!FD_ISSET(sess->fd, writefds))
        return 0;
    int res;

    LOG_E("\n");
    HDL_WRITE(sess, serv->intro,   sst_intro,   sst_inv_msg);
    HDL_WRITE(sess, serv->inv_msg, sst_inv_msg, sst_lsn_req);
    LOG_L("\n");

    return 0;
}

void move_sess_ptrs(buffer *sess_buf, void *base_ptr)
{
    /* session **sess_array = (session **) sess_buf->ptr; */
    /* int i, size = sess_buf->size / sizeof(session *); */
    /* for (i = 0; i < size; i++) */
    /*     printf("'%p'\t'%p'\n", sess_array[i], &sess_array[i]); */
    /* putchar(10); */

    const size_t offset = base_ptr - sess_buf->ptr;
    const size_t to_move = sess_buf->used - offset;
    LOG("Base ptr '%p' buf_ptr '%p' offset '%lu' to_move '%lu'\n",
        base_ptr, sess_buf->ptr, offset, to_move);
    memmove(base_ptr, base_ptr + sizeof(session *), to_move);
    memset(base_ptr + to_move, 0, sizeof(session *));
    LOG("'%lu' has been moved to left\n", to_move);

    /* for (i = 0; i < size; i++) */
    /*     printf("'%p'\n", sess_array[i]); */
    /* putchar(10); */
}

void terminate_session(buffer *sess_buf, session **sess)
{
    int exit_status = (*sess)->e_exit_status;
    int fd = (*sess)->fd;
    assert((*sess)->e_exit_status != exst_unk);
    close((*sess)->fd);
    session_delete(*sess);
    sess_buf->used -= sizeof(session *);
    move_sess_ptrs(sess_buf, (void *) sess);

    printf("Session with client %d has been terminated %s\n",
        fd, exit_status == exst_err ? "due an error" : "on his own will");
}

void check_io(server *serv, fd_set *readfds, fd_set *writefds)
{
    LOG_E("\n");
    session **sess_arr = (session **) serv->sess_buf->ptr;
    while (*sess_arr)
    {
        LOG("Iteration for '%p'\n", (void *) sess_arr);
        if (handle_client_read(serv, *sess_arr, readfds) ||
            handle_client_write(serv, *sess_arr, writefds))
        {
            terminate_session(serv->sess_buf, sess_arr);
            continue;
        }
        sess_arr++;
    }
    LOG_L("\n");
}

int handle_event(int code, server *serv, fd_set *readfds, fd_set *writefds)
{
    LOG_E("\n");
    if (was_signaled(code))
        LOG_RET(0);
    else if (check_err(code))
        LOG_RET(1);
    check_listen(serv, readfds);
    check_io(serv, readfds, writefds);

    LOG_L("\n");
    return 0;
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
        if (handle_event(res, serv, &readfds, &writefds))
            LOG_RET(1);
        LOG("\n\n");
    }
    LOG_L("\n");
    return 0;
}
