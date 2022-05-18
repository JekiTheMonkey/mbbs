#ifndef BUFFER_H
#define BUFFER_H

#include "def.h"

#include <sys/types.h>

struct buffer
{
    void *ptr;
    const size_t size;
    size_t used;
};

buffer *buffer_create(size_t size);
void buffer_delete(buffer *buf);

#endif /* !BUFFER_H */
