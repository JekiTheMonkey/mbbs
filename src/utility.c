#include "utility.h"
#include "log.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

char *strdup(char *src)
{
    size_t len;
    char *cpy = NULL;
    if (src)
    {
        len = strlen(src);
        cpy = (char *) malloc(len);
        ANLOG(cpy, len);
        strcpy(cpy, src);
    }
    return cpy;
}

char *strndup(char *src, size_t n)
{
    char *cpy = NULL;
    if (src)
    {
        cpy = (char *) malloc(n);
        ANLOG(cpy, n);
        strncpy(cpy, src, n);
    }
    return cpy;
}

void create_dir_if_not_exists(const char *path)
{
    if (access(path, F_OK))
    {
        LOG("Missing directory '%s'\n", path);
        if (mkdir(path, 0700))
        {
            fprintf(stderr, "Failed to create directory '%s': %s\n",
                path, strerror(errno));
            exit(1);
        }
        LOG("Created directory '%s'\n", path);
    }
}

size_t strncount(const char *str, char ch, size_t n)
{
    size_t count = 0;
    for (; n; str++, n--)
        if (*str == ch)
            count++;
    return count;
}

char *strnfind(const char *str, char ch, size_t n)
{
    for (; n; n--, str++)
        if (*str == ch)
            return (char *) str;
    return NULL;
}

char *strnfindl(const char *str, char *chs, size_t n_ch, size_t n)
{
    size_t j;
    for (; n; n--, str++)
    {
        for (j = 0; j < n_ch; j++)
            if (*str == chs[j])
                return (char *) str;
    }
    return NULL;
}
