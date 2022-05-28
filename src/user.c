#include "user.h"
#include "log.h"
#include "utility.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

user_t *user_create(const char *username, const char *password)
{
    user_t *item = (user_t *) malloc(sizeof(user_t));
    ALOG(item);
    item->username = strdup((char *) username);
    item->password = strdup((char *) password);
    item->next = NULL;
    return item;
}

void user_push_back(user_t **head, user_t *user)
{
    if (!*head)
    {
        *head = user;
        return;
    }
    else
        user_push_back(&(*head)->next, user);
}

user_t *user_find(const user_t *head, const char *username)
{
    if (!head)
        return NULL;
    if (!strcmp(head->username, username))
        return (user_t *) head;
    else
        return user_find((user_t *) head->next, username);
}

void user_print(const user_t *head)
{
    if (!head)
        return;
    printf("'%p' '%s' '%s'\n", (void *) head, head->username, head->password);
    user_print(head->next);
}

void user_remove(user_t **head, user_t *user)
{
    if (!*head)
        return;
    if ((*head)->next != user)
        user_remove(&(*head)->next, user);
    else
    {
        (*head)->next = user->next;
        user_delete(user);
    }
}

void user_delete(user_t *user)
{
    /* Avoid user data be inside RAM after it has been used */
    memset(user->username, 0, strlen(user->username));
    memset(user->password, 0, strlen(user->password));
    FREE(user->username);
    FREE(user->password);
    FREE(user);
}
