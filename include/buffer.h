#ifndef BUFFER_H
#define BUFFER_H

#include "def.h"

#include <sys/types.h>

/*
 * Buffer is a simple struct that holds a raw pointer to some data which has
 * to be cast to the right type. It's useful due its ability to remember how
 * many bytes have been used and the overal size.
 */

struct buffer
{
    void *ptr;
    const size_t size;
    size_t used;
};

buffer *buffer_create(size_t size);
void buffer_delete(buffer *buf);
void buffer_set_size(buffer *buf, size_t size);

#endif /* !BUFFER_H */
