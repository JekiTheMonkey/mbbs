#include "buffer.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>

buffer *buffer_create(size_t size)
{
    buffer *buf = (buffer *) malloc(sizeof(buffer));
    ALOG(buf);
    buf->ptr = (void *) malloc(size);
    ANLOG(buf->ptr, size);
    buf->used = 0;
    buffer_set_size(buf, size);
    return buf;
}

void buffer_delete(buffer *buf)
{
    FREE(buf->ptr);
}

void buffer_set_size(buffer *buf, size_t size)
{
    size_t *s_p = (size_t *) &buf->size;
    *s_p = size;
}
