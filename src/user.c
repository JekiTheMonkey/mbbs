#include "user.h"
#include "log.h"
#include "utility.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

user *user_create(const char *username, const char *password)
{
    user *item = (user *) malloc(sizeof(user));
    ALOG(item);
    item->username = strdup((char *) username);
    item->password = strdup((char *) password);
    item->next = NULL;
    return item;
}

void user_push_back(user **head, user *item)
{
    if (!*head)
    {
        *head = item;
        return;
    }
    else
        user_push_back(&(*head)->next, item);
}

user *user_find(const user *head, const char *username)
{
    if (!head)
        return NULL;
    if (!strcmp(head->username, username))
        return (user *) head;
    else
        return user_find((user *) head->next, username);
}

void user_print(const user *head)
{
    if (!head)
        return;
    printf("'%p' '%s' '%s'\n", (void *) head, head->username, head->password);
    user_print(head->next);
}

void user_remove(user **head, user *item)
{
    if (!*head)
        return;
    if ((*head)->next != item)
        user_remove(&(*head)->next, item);
    else
    {
        (*head)->next = item->next;
        user_delete(item);
    }
}

void user_delete(user *usr)
{
    /* Avoid user data be inside RAM after it has been used */
    memset(usr->username, 0, strlen(usr->username));
    memset(usr->password, 0, strlen(usr->password));
    FREE(usr->username);
    FREE(usr->password);
    FREE(usr);
}
