#ifndef USER_H
#define USER_H

#include "def.h"

/* Simple linked list with essential user data */

struct user
{
    char *username;
    char *password;
    user *next;
};

user *user_create(const char *username, const char *password);
void user_push_back(user **head, user *item);
user *user_find(const user *head, const char *username);
void user_print(const user *head);
void user_remove(user **head, user *item);
void user_delete(user *usr);

#endif /* USER_H */
