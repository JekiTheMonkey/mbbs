#ifndef UTILITY_H
#define UTILITY_H

#include <sys/types.h>

char *strdup(char *src);
char *strndup(char *src, size_t n);
void create_dir_if_not_exists(const char *path);

size_t strncount(const char *str, char ch, size_t n);
char *strnfind(const char *str, char ch, size_t n);
char *strnfindl(const char *str, char *chs, size_t n_ch, size_t n);

#endif /* UTILITY_H */
