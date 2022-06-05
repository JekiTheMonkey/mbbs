#ifndef USER_H
#define USER_H

#include "def.h"

/*
 * Simple linked list with essential user data
 */

enum perms_t {
    perms_upload        = 1 << 0,       /* upload files */
    perms_remove        = 1 << 1,       /* remove files */
    perms_edit_desc     = 1 << 2,       /* edit descriptions */
};

struct user_t
{
    char *username;
    char *password;
    perms_t perms;
    user_t *next;
};

user_t *user_create(const char *username, const char *password, perms_t perms);
void user_push_back(user_t **head, user_t *user);
user_t *user_find(const user_t *head, const char *username);
void user_print(const user_t *head);
void user_remove(user_t **head, user_t *user);
void user_delete(user_t *user);

#endif /* USER_H */
