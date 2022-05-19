#include "utility.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int min(int lhs, int rhs)
{
    return lhs > rhs ? rhs : lhs;
}

int max(int lhs, int rhs)
{
    return lhs > rhs ? lhs : rhs;
}

char *strdup(char *src)
{
    size_t len;
    char *cpy = NULL;
    if (src)
    {
        len = strlen(src);
        cpy = (char *) malloc(len + 1);
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
