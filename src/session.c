#include "buffer.h"
#include "log.h"
#include "server.h"
#include "session.h"
#include "user.h"
#include "utility.h"

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

sess_t *session_create(int cfd)
{
    sess_t *sess = (sess_t *) malloc(sizeof(sess_t));
    ALOG(sess);
    sess->state = sst_unk;
    sess->action = cac_unk;
    sess->addr = NULL;
    sess->cfd = cfd;
    sess->udfd = 0;
    sess->perms = 0;
    sess->usr = NULL;
    sess->buf = buffer_create(SESS_BUF_DEF_SIZE);
    return sess;
}

void session_delete(sess_t *sess)
{
    close(sess->cfd);
    buffer_delete(sess->buf);
    FREE(sess->addr);

    sess->state = -1;
    sess->action = -1;
    sess->addr = NULL;
    sess->cfd = -1;
    sess->udfd = -1;
    sess->perms = -1;
    sess->usr = NULL;
    sess->buf = NULL;

    FREE(sess);
}

int session_send_data(sess_t *sess, const void *data, size_t bytes)
{
    assert(bytes != 0);
    int res;
    do {
        res = write(sess->cfd, data, min(bytes, MAX_WRITE_BYTES));
    } while (was_signaled(res));
    LOG("'%d' bytes have been sent\n", res);

    if (res == -1)
    {
        ELOG("Failed to write");
        sess->state = sst_err;
        return -1;
    }
    return res;
}

int session_send_str(sess_t *sess, const char *str)
{
    return session_send_data(sess, str, strlen(str));
}

int session_upload_buffer(sess_t *sess)
{
    return session_send_data(sess, sess->buf->ptr, sess->buf->used);
}

int session_receive_data(sess_t *sess)
{
    int res;
    buf_t *buf = sess->buf;
    do {
        res = read(sess->cfd, buf->ptr + buf->used, buf->size - buf->used);
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

/* Doesn't support nested files, i.e. paths with directories in them */
char *create_perms_filepath(const char *file)
{
    const unsigned bytes = strlen(file) + 2;
    char *pfile = (char *) malloc(bytes);
    ANLOG(pfile, bytes);
    sprintf(pfile, "_%s", file);
    return pfile;
}

int open_perms_file(const char *path,
    int flag, int perms)
{
    char *filepath = create_perms_filepath(path);
    int fd = open_file(filepath, flag, perms);
    FREE(filepath);
    if (fd == -1)
        return -1;
    return fd;
}

/* System File SEEK */
int sfseek(int fd, sys_file_zones zone)
{
    if (!zone)
        return 0;
    int res, bytes = 0;
    char buf[4096], *it_l, *it_r;
    while ((res = read(fd, buf, sizeof(buf))) > 0)
    {
        it_l = buf;
        for (; zone; zone--)
        {
            it_r = strnfind(it_l, SYS_FILE_SPC, res);
            if (!it_r)
                break;
            bytes += it_r - it_l;
            it_l = it_r;
        }
    }
    if (res == -1)
        PELOG("Failed to read from system file");
    return bytes;
}

int is_user_in_whitelist(int fd, const char *username)
{
    int res, used = 0, diff;
    char buf[4096], *found;
    while ((res = read(fd, buf, sizeof(buf) - used)) > 0)
    {
        found = strstr(buf, username);
        if (found)
            return 1;
        found = strrnfind(buf, ' ', res);
        diff = found ? buf - found : 0;
        used = res - diff;
        if (found)
            memmove(buf, found, used);
    }
    if (res == -1)
        PELOG("Failed to read from system file");
    return 0;
}

int session_open_file(sess_t *sess, const char *path, int flags)
{
    int fd = open_perms_file(path, O_RDWR, 0);
    if (fd == -1)
        return -2; /* error: file couldn't be opened */
    sfseek(fd, whitelist);
    if (!is_user_in_whitelist(fd, sess->usr->username))
    {
        close(fd);
        return -1; /* user is not is whitelist */
    }
    close(fd);
    open_file(path, flags, 0);
    return 1; /* is allowed */
}
