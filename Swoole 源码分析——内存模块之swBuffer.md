# Swoole 源码分析——内存模块之swBuffer

## 前言

`swoole` 中数据的接受与发送(例如 `reactor` 线程接受客户端消息、发送给客户端的消息、接受到的来自 `worker` 的消息、要发送给 `worker` 的消息等等)都要涉及到缓冲区，`swoole` 中的缓冲区实现是 `swBuffer`，实际上是一个单链表。

## `swBuffer` 的数据结构

- `swBuffer` 数据结构中 `trunk_num` 是链表元素的个数，`trunk_size` 是 `swBuffer` 缓冲区创建时，链表元素约定的大小(实际大小不一定是这个值)，`length` 是实际上缓冲区占用的内存总大小。
- `swBuffer_trunk` 中的 `type` 有三种，分别应用于：缓存数据、发送文件、提醒连接关闭三种情景。`length` 指的是元素的内存大小。

```c
enum swBufferChunk
{
    SW_CHUNK_DATA,
    SW_CHUNK_SENDFILE,
    SW_CHUNK_CLOSE,
};

typedef struct _swBuffer_trunk
{
    uint32_t type;
    uint32_t length;
    uint32_t offset;
    union
    {
        void *ptr;
        struct
        {
            uint32_t val1;
            uint32_t val2;
        } data;
    } store;
    uint32_t size;
    void (*destroy)(struct _swBuffer_trunk *chunk);
    struct _swBuffer_trunk *next;
} swBuffer_trunk;

typedef struct _swBuffer
{
    int fd;
    uint8_t trunk_num; //trunk数量
    uint16_t trunk_size;
    uint32_t length;
    swBuffer_trunk *head;
    swBuffer_trunk *tail;
} swBuffer;

```

## `swBuffer` 的创建

`swBuffer` 的创建很简单，只是初始化整个 `swBuffer` 的 `header` 头元素而已：

```c
swBuffer* swBuffer_new(int trunk_size)
{
    swBuffer *buffer = sw_malloc(sizeof(swBuffer));
    if (buffer == NULL)
    {
        swWarn("malloc for buffer failed. Error: %s[%d]", strerror(errno), errno);
        return NULL;
    }

    bzero(buffer, sizeof(swBuffer));
    buffer->trunk_size = trunk_size;

    return buffer;
}

```

## `swBuffer` 内存的申请

`swBuffer` 内存的申请逻辑也很简单，按照传入的 `size` 参数为链表元素申请内存，初始化成员变量，然后将链表元素放到链表的尾部即可：

```c
int swBuffer_append(swBuffer *buffer, void *data, uint32_t size)
{
    swBuffer_trunk *chunk = swBuffer_new_trunk(buffer, SW_CHUNK_DATA, size);
    if (chunk == NULL)
    {
        return SW_ERR;
    }

    buffer->length += size;
    chunk->length = size;

    memcpy(chunk->store.ptr, data, size);

    swTraceLog(SW_TRACE_BUFFER, "trunk_n=%d|size=%d|trunk_len=%d|trunk=%p", buffer->trunk_num, size,
            chunk->length, chunk);

    return SW_OK;
}

swBuffer_trunk *swBuffer_new_trunk(swBuffer *buffer, uint32_t type, uint32_t size)
{
    swBuffer_trunk *chunk = sw_malloc(sizeof(swBuffer_trunk));
    if (chunk == NULL)
    {
        swWarn("malloc for trunk failed. Error: %s[%d]", strerror(errno), errno);
        return NULL;
    }

    bzero(chunk, sizeof(swBuffer_trunk));

    //require alloc memory
    if (type == SW_CHUNK_DATA && size > 0)
    {
        void *buf = sw_malloc(size);
        if (buf == NULL)
        {
            swWarn("malloc(%d) for data failed. Error: %s[%d]", size, strerror(errno), errno);
            sw_free(chunk);
            return NULL;
        }
        chunk->size = size;
        chunk->store.ptr = buf;
    }

    chunk->type = type;
    buffer->trunk_num ++;

    if (buffer->head == NULL)
    {
        buffer->tail = buffer->head = chunk;
    }
    else
    {
        buffer->tail->next = chunk;
        buffer->tail = chunk;
    }

    return chunk;
}
```

## 获取 `swBuffer` 的元素

从 `swBuffer` 缓冲区拿数据只能从 `head` 中获取：

```c
#define swBuffer_get_trunk(buffer)   (buffer->head)

``` 

## `swBuffer` 元素的 `pop` 

获取了缓冲区的元素之后，就要相应删除 `head` 链表元素:


```c
void swBuffer_pop_trunk(swBuffer *buffer, swBuffer_trunk *chunk)
{
    if (chunk->next == NULL)
    {
        buffer->head = NULL;
        buffer->tail = NULL;
        buffer->length = 0;
        buffer->trunk_num = 0;
    }
    else
    {
        buffer->head = chunk->next;
        buffer->length -= chunk->length;
        buffer->trunk_num--;
    }
    if (chunk->type == SW_CHUNK_DATA)
    {
        sw_free(chunk->store.ptr);
    }
    if (chunk->destroy)
    {
        chunk->destroy(chunk);
    }
    sw_free(chunk);
}

```

## `swBuffer` 缓冲区的销毁

```c
int swBuffer_free(swBuffer *buffer)
{
    volatile swBuffer_trunk *chunk = buffer->head;
    void * *will_free_trunk;  //free the point
    while (chunk != NULL)
    {
        if (chunk->type == SW_CHUNK_DATA)
        {
            sw_free(chunk->store.ptr);
        }
        will_free_trunk = (void *) chunk;
        chunk = chunk->next;
        sw_free(will_free_trunk);
    }
    sw_free(buffer);
    return SW_OK;
}

```