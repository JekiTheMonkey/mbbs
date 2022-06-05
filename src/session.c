#include "buffer.h"
#include "log.h"
#include "server.h"
#include "session.h"
#include "user.h"
#include "utility.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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
    sess->buf = buffer_create(SESS_BUF_SIZE);
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
char *create_sys_filepath(const char *filepath)
{
    const unsigned bytes = strlen(filepath) + 2;
    char *pfile = (char *) malloc(bytes);
    ANLOG(pfile, bytes);
    sprintf(pfile, "_%s", filepath);
    return pfile;
}

FILE *open_sys_file(const char *filepath, const char *mode)
{
    char *sys_filepath = create_sys_filepath(filepath);
    LOG("Trying to open '%s'...", sys_filepath);
    FILE *sys_file = fopen(sys_filepath, mode);
    FREE(sys_filepath);
    return sys_file;
}

FILE *create_sys_file(const char *filepath, const char *owner)
{
    char *sys_filepath = create_sys_filepath(filepath);
    assert(!file_exists(sys_filepath));
    FREE(sys_filepath);

    char buf[4096];
    char tbuf[128];

    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    strftime(tbuf, sizeof(tbuf), "%d %h %y %I:%M %p", tm);
    LOG("%s\n", tbuf);

    FILE *sys_file = open_sys_file(filepath, "w");
    int res = sprintf(buf, SYS_FILE_TMPL, owner, tbuf);
    fwrite(buf, 1, res, sys_file);
    LOG("New system file has been created\n");

    return sys_file;
}

/* System File SEEK */
int sfseek(FILE *sys_file, sys_file_zones zone)
{
    if (!zone)
        return 0;
    LOG_E("\n");
    int res, bytes = ftell(sys_file);
    char buf[4096], *it_l, *it_r;
    while ((res = fread(buf, 1, sizeof(buf), sys_file)) > 0)
    {
        it_l = buf;
        for (; zone; zone--)
        {
            it_r = strnfind(it_l, SYS_FILE_SPC, res);
            if (!it_r)
            {
                bytes += res - (it_l - buf);
                break;
            }
            bytes += it_r - it_l + 1;
            it_l = it_r + 1; /* skip space */
        }
    }
    fseek(sys_file, bytes, SEEK_SET);
    if (ferror(sys_file))
        PELOG("Failed to read from system file");
    LOG_L("\n");
    return bytes;
}

int is_user_in_whitelist(FILE *sys_file, const char *username)
{
    int res, used = 0, diff, pos = ftell(sys_file);
    char buf[4096], *found;
    fseek(sys_file, 0, SEEK_SET);
    sfseek(sys_file, whitelist);
    while ((res = fread(buf, 1, sizeof(buf) - used, sys_file)) > 0)
    {
        LOG("'%d' bytes have been read\n", res);
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
    fseek(sys_file, pos, SEEK_SET);
    return 0;
}

int is_whitelist_set(FILE *sys_file)
{
    int pos = ftell(sys_file);
    fseek(sys_file, 0, SEEK_SET);
    sfseek(sys_file, is_whitelist);
    fseek(sys_file, 1, SEEK_CUR); /* skip space */
    int ch, i = 0;
    char buf[8];
    for (; (ch = getc(sys_file)) != '\n'; i++)
    {
        LOG("%c | %d\n", ch > 32 ? ch : ' ', ch);
        assert(ch != EOF);
        assert(i < (int) sizeof(buf));
        buf[i] = ch;
    }
    LOG("Token: '%.*s'\n", i, buf);
    fseek(sys_file, pos, SEEK_SET);
    return strnicmp(buf, "yes", i);
}

/* int session_open_file(sess_t *sess, const char *path, int flags) */
/* { */
/*     FILE *fd = open_perms_file(path, "r"); */
/*     if (!fd) */
/*         return -2; /1* error: file couldn't be opened *1/ */
/*     sfseek(fd, whitelist); */
/*     if (!is_user_in_whitelist(fd, sess->usr->username)) */
/*     { */
/*         close(fd); */
/*         return -1; /1* user is not is whitelist *1/ */
/*     } */
/*     close(fd); */
/*     open_file(path, flags, 0); */
/*     return 1; /1* is allowed *1/ */
/* } */
