# Swoole 源码分析——基础模块之 Channel 队列

## 前言

内存数据结构 `Channel`，类似于 `Go` 的 `chan` 通道，底层基于 `共享内存 + Mutex` 互斥锁实现，可实现用户态的高性能内存队列。`Channel` 可用于多进程环境下，底层在读取写入时会自动加锁，应用层不需要担心数据同步问题。

`channel` 在之前的文章中出现过，当时用于 `manager` 和 `worker` 进程之间进行通信的重要数据结构，主要用于 `worker` 进程通知 `manager` 进程重启相应 `worker` 进程。


## `channel` 数据结构

`channel` 数据结构的属性比较多，`head` 是队列的头部位置，`tail` 是队列的尾部位置，`size` 是申请的队列内存大小，`maxlen` 是每个队列元素的大小，`head_tag` 和 `tail_tag` 用于指定队列的头尾是否循环被重置回头部。`bytes` 是当前 `channel` 队列占用的内存大小，`flag` 用来指定是否使用共享内存、是否使用锁、是否使用 `pipe` 通知。`mem` 是 `channel` 的内存首地址。 

```c
typedef struct _swChannel_item
{
    int length;
    char data[0];
} swChannel_item;

typedef struct _swChannel
{
    off_t head;
    off_t tail;
    size_t size;
    char head_tag;
    char tail_tag;
    int num;
    int max_num;
    /**
     * Data length, excluding structure
     */
    size_t bytes;
    int flag;
    int maxlen;
    /**
     * memory point
     */
    void *mem;
    swLock lock;
    swPipe notify_fd;
} swChannel;
```

## `channel` 队列

### `swChannel_new` 创建队列

创建队列就是根据 `flags` 来初始化队列的各个属性，值得注意的是 `maxlen`，当申请内存的时候会多申请这些内存，用来防止内存越界。

```c
swChannel* swChannel_new(size_t size, int maxlen, int flags)
{
    assert(size >= maxlen);
    int ret;
    void *mem;

    //use shared memory
    if (flags & SW_CHAN_SHM)
    {
        mem = sw_shm_malloc(size + sizeof(swChannel) + maxlen);
    }
    else
    {
        mem = sw_malloc(size + sizeof(swChannel) + maxlen);
    }

    if (mem == NULL)
    {
        swWarn("swChannel_create: malloc(%ld) failed.", size);
        return NULL;
    }
    swChannel *object = mem;
    mem += sizeof(swChannel);

    bzero(object, sizeof(swChannel));

    //overflow space
    object->size = size;
    object->mem = mem;
    object->maxlen = maxlen;
    object->flag = flags;

    //use lock
    if (flags & SW_CHAN_LOCK)
    {
        //init lock
        if (swMutex_create(&object->lock, 1) < 0)
        {
            swWarn("mutex init failed.");
            return NULL;
        }
    }
    //use notify
    if (flags & SW_CHAN_NOTIFY)
    {
        ret = swPipeNotify_auto(&object->notify_fd, 1, 1);
        if (ret < 0)
        {
            swWarn("notify_fd init failed.");
            return NULL;
        }
    }
    return object;
}

```

### `swChannel_push` 入队

入队的时候，首先要先加锁，然后调用 `swChannel_in`。

`swChannel_in` 逻辑很简单，向队列的尾部推送数据，如果当前 `channel` 尾部被重置，`head` 还未被重置，就需要先判断剩余的内存是否够用。

如果当前 `channel` 尾部未被重置，就可以放心的追加元素，因为 `object->size` 和真正申请的内存之前还有 `maxlen` 可以富余，不必考虑内存越界的问题。

```c
int swChannel_push(swChannel *object, void *in, int data_length)
{
    assert(object->flag & SW_CHAN_LOCK);
    object->lock.lock(&object->lock);
    int ret = swChannel_in(object, in, data_length);
    object->lock.unlock(&object->lock);
    return ret;
}

#define swChannel_full(ch) ((ch->head == ch->tail && ch->tail_tag != ch->head_tag) || (ch->bytes + sizeof(int) * ch->num == ch->size))
int swChannel_in(swChannel *object, void *in, int data_length)
{
    assert(data_length <= object->maxlen);
    if (swChannel_full(object))
    {
        return SW_ERR;
    }
    swChannel_item *item;
    int msize = sizeof(item->length) + data_length;

    if (object->tail < object->head)
    {
        //no enough memory space
        if ((object->head - object->tail) < msize)
        {
            return SW_ERR;
        }
        item = object->mem + object->tail;
        object->tail += msize;
    }
    else
    {
        item = object->mem + object->tail;
        object->tail += msize;
        if (object->tail >= object->size)
        {
            object->tail = 0;
            object->tail_tag = 1 - object->tail_tag;
        }
    }
    object->num++;
    object->bytes += data_length;
    item->length = data_length;
    memcpy(item->data, in, data_length);
    return SW_OK;
}

```


### `swChannel_push` 出队

`swChannel_push` 出队的逻辑比较简单，获取队列头部位置，然后拷贝首部数据即可。当 `head` 超过 `size` 值，即可重置 `head`。

```c
int swChannel_pop(swChannel *object, void *out, int buffer_length)
{
    assert(object->flag & SW_CHAN_LOCK);
    object->lock.lock(&object->lock);
    int n = swChannel_out(object, out, buffer_length);
    object->lock.unlock(&object->lock);
    return n;
}

#define swChannel_empty(ch) (ch->num == 0)

int swChannel_out(swChannel *object, void *out, int buffer_length)
{
    if (swChannel_empty(object))
    {
        return SW_ERR;
    }

    swChannel_item *item = object->mem + object->head;
    assert(buffer_length >= item->length);
    memcpy(out, item->data, item->length);
    object->head += (item->length + sizeof(item->length));
    if (object->head >= object->size)
    {
        object->head = 0;
        object->head_tag = 1 - object->head_tag;
    }
    object->num--;
    object->bytes -= item->length;
    return item->length;
}

```