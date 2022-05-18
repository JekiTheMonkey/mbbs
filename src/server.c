#include "server.h"
#include "log.h"
#include "serv_cfg.h"
#include "utility.h"
#include "session.h"
#include "buffer.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

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

int serv_init(const serv_cfg *cfg, server *serv)
{
    LOG_E("\n");
    signal(SIGINT, &sigint_handler);
    create_dir_if_not_exists(cfg->db_dir);
    serv->ls = create_server_socket(cfg);
    serv->sess_buf = buffer_create(SESS_ARRAY_INIT_SIZE * sizeof(session *));
    LOG_L("Server has been initilized successfully\n");
    return 1;
}

int init_readfds(fd_set *readfds, const server *serv)
{
    int fd, maxfd = serv->ls;
    buffer *sess_buf = serv->sess_buf;
    session **sess_arr = (session **) sess_buf->ptr;
    unsigned i, size = sess_buf->used;
    FD_ZERO(readfds);
    FD_SET(serv->ls, readfds);
    for (i = 0; i < size; i++)
    {
        fd = sess_arr[i]->fd;
        FD_SET(fd, readfds);
        if (maxfd < fd)
            maxfd = fd;
        LOG("'%d' has been added to readfds\n", fd);
    }
    LOG("'%d' - maxfd\n", maxfd);
    return maxfd;
}

int mselect(const server *serv, fd_set *readfds, fd_set *writefds)
{
    LOG_E("\n");
    int maxfd = init_readfds(readfds, serv);
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
        LOG("Failed to accept a client: %s\n", strerror(errno));
        return 0;
    }
    LOG("New client(%d) has been accepted. %s::%d\n",
        cfd, inet_ntoa(cli_addr.sin_addr), cli_addr.sin_port);
    return cfd;
}

session *add_session(server *serv, int cfd)
{
    buffer *sess_buf = serv->sess_buf;
    session **sess_arr = (session **) sess_buf->ptr;

    if (sess_buf->used == sess_buf->size)
        sess_arr = (session **) realloc(sess_arr,
            sess_buf->size + SESS_ARRAY_INIT_SIZE);
    if (!sess_arr[sess_buf->used])
        sess_arr[sess_buf->used] = session_create(cfd);

    session *sess = sess_arr[sess_buf->used];
    sess_buf->used++;

    LOG("New session has been created. Up sessions - '%lu'\n", sess_buf->used);
    return sess;
}

void check_listen(server *serv, fd_set *readfds)
{
    if (!FD_ISSET(serv->ls, readfds))
        return;
    int cfd = accept_client(serv->ls);
    if (!cfd)
        return;
    session *sess = add_session(serv, cfd);
    UNUSED1(sess);
    /*
     *  show_intro();
     *  show_menu();
     */
}

int was_signaled(int code)
{
    return code == -1 && errno == EINTR;
}

int handle_lf(session *sess)
{
    buffer *buf = sess->buf;
    const char *lf = strnfind(buf->ptr, '\n', buf->used);
    if (!lf)
        return 0;

    const size_t diff = lf - (char *) buf->ptr;
    buf->used -= diff;
    memmove(buf->ptr, buf->ptr + diff, buf->used);

    if (write(sess->fd, "Ok\n", 3) == -1)
    {
        LOG("Failed to write to a client\n");
        return 1;
    }
    return 0;
}

int read_client(session *sess)
{
    ssize_t res;
    buffer *buf = sess->buf;
    do {
        res = read(sess->fd, buf->ptr + buf->used, buf->size - buf->used);
    } while (was_signaled(res));

    if (res == -1)
        LOG("Failed to read: %s\n", strerror(errno));
    else if (res == 0)
        LOG("EOF has been read\n");
    if (res <= 0)
        return res;

    buf->used += res;
    LOG("'%ld' bytes have been read\n", res);

    if (handle_lf(sess))
        return -1;

    return 1;
}

void terminate_session(int code, buffer *sess_array, unsigned sess_n)
{
    session *sess = ((session **) sess_array->ptr)[sess_n];
    close(sess->fd);
    session_delete(sess);
    sess_array->used--;
    LOG("'%lu' has been moved to left\n",
        (sess_array->used - sess_n) * sizeof(session *));
    memmove(sess, sess + 1, (sess_array->used - sess_n) * sizeof(session *));
    LOG("A session has been terminated %s\n",
        code == -1 ? "due an error" : "on own will");
}

int handle_client_read(server *serv, unsigned sess_n, fd_set *readfds)
{
    session *sess = ((session **) serv->sess_buf->ptr)[sess_n];
    if (!FD_ISSET(sess->fd, readfds))
        return 0;

    int res = read_client(sess);
    if (res <= 0)
        terminate_session(res, serv->sess_buf, sess_n);
    return res <= 0; /* return 1 on disconnect */
}

void check_read(server *serv, fd_set *readfds)
{
    unsigned i = 0;;
    while (i < serv->sess_buf->used)
    {
        if (handle_client_read(serv, i ,readfds))
            continue; /* it has been iterated in handle_client_read function */
        i++;
    }
}

int handle_event(int code, server *serv, fd_set *readfds, fd_set *writefds)
{
    LOG_E("\n");
    if (was_signaled(code))
    {
        LOG_L("\n");
        return 0;
    }
    else if (check_err(code))
    {
        LOG_L("\n");
        return 1;
    }
    check_listen(serv, readfds);
    check_read(serv, readfds);

    LOG_L("\n");
    return 0;

    UNUSED1(writefds);
}

int serv_start(server *serv)
{
    LOG_E("\n");
    fd_set readfds, writefds;
    work = 1;
    while (work)
    {
        /* Select events */
        int res = mselect(serv, &readfds, &writefds);
        LOG("Select has returned '%d'\n", res);
        /* Handle events */
        if (handle_event(res, serv, &readfds, &writefds))
        {
            LOG_L("\n");
            return 1;
        }
    }
    LOG_L("\n");
    return 0;
}

int serv_end(server *serv)
{
    /* close all FDs, deallocate all buffers */
    close(serv->ls);
    return 0;
}
