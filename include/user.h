#ifndef USER_H
#define USER_H

#include "def.h"

/* Simple linked list with essential user data */

struct user_t
{
    char *username;
    char *password;
    user_t *next;
};

user_t *user_create(const char *username, const char *password);
void user_push_back(user_t **head, user_t *user);
user_t *user_find(const user_t *head, const char *username);
void user_print(const user_t *head);
void user_remove(user_t **head, user_t *user);
void user_delete(user_t *user);

#endif /* USER_H */
