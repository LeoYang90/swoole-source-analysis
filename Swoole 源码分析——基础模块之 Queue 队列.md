# Swoole 源码分析——基础模块之 Queue 队列

## 前言

`swoole` 的底层队列有两种：进程间通信 `IPC` 的消息队列 `swMsgQueue`，与环形队列 `swRingQueue`。`IPC` 的消息队列用于 `task_worker` 进程接受投递消息，环形队列用于 `SW_MODE_THREAD` 线程模式下 `task_worker` 接受投递消息的方法。


## `swMsgQueue` 消息队列数据结构

`swoole` 使用的消息队列并不是 `POSIX` 下的 `mq_xx` 系统函数，而是 `SystemV` 下的 `msgxxx` 系列函数，原因猜测是 `systemv` 系统函数可以指定 `mtype`，也就是消息的类型，这样就可以实现对指定的 `task_worker` 的投放。

`swMsgQueue` 的数据结构比较简单，`blocking` 指定消息队列是否是阻塞式，`msg_id` 是创建的消息队列的 `id`，`flags` 也是指定阻塞式还是非阻塞式，`perms` 指定消息队列的权限。

```c
typedef struct _swMsgQueue
{
    int blocking;
    int msg_id;
    int flags;
    int perms;
} swMsgQueue;

```

## `swMsgQueue` 消息队列

### `swMsgQueue` 消息队列的创建

创建消息队列就是调用 `msgget` 函数，这个函数的 `msg_key` 就是 `server` 端配置的 `message_queue_key`，`task` 队列在 `server` 结束后不会销毁，重新启动程序后，`task` 进程仍然会接着处理队列中的任务。如果不设置该值，那么程序会自动生成： `ftok($php_script_file, 1)`

```c
void swMsgQueue_set_blocking(swMsgQueue *q, uint8_t blocking)
{
    if (blocking == 0)
    {
        q->flags = q->flags | IPC_NOWAIT;
    }
    else
    {
        q->flags = q->flags & (~IPC_NOWAIT);
    }
}

int swMsgQueue_create(swMsgQueue *q, int blocking, key_t msg_key, int perms)
{
    if (perms <= 0 || perms >= 01000)
    {
        perms = 0666;
    }
    int msg_id;
    msg_id = msgget(msg_key, IPC_CREAT | perms);
    if (msg_id < 0)
    {
        swSysError("msgget() failed.");
        return SW_ERR;
    }
    else
    {
        bzero(q, sizeof(swMsgQueue));
        q->msg_id = msg_id;
        q->perms = perms;
        q->blocking = blocking;
        swMsgQueue_set_blocking(q, blocking);
    }
    return 0;
}

```

### `swMsgQueue` 消息队列的发送

消息队列的发送主要利用 `msgsnd` 函数，`flags` 指定发送是阻塞式还是非阻塞式，在 `task_worker` 进程中都是采用阻塞式发送的方法。

```c
int swMsgQueue_push(swMsgQueue *q, swQueue_data *in, int length)
{
    int ret;

    while (1)
    {
        ret = msgsnd(q->msg_id, in, length, q->flags);
        if (ret < 0)
        {
            SwooleG.error = errno;
            if (errno == EINTR)
            {
                continue;
            }
            else if (errno == EAGAIN)
            {
                return -1;
            }
            else
            {
                swSysError("msgsnd(%d, %d, %ld) failed.", q->msg_id, length, in->mtype);
                return -1;
            }
        }
        else
        {
            return ret;
        }
    }
    return 0;
}


```

### `swMsgQueue` 消息队列的接受

消息队列的接受是利用 `msgrcv` 函数，其中 `mtype` 是消息的类型，该参数会取出指定类型的消息，如果 `task_ipc_mode` 设定的是争抢模式，该值会统一为 0，否则该值就是消息发送目的 `task_worker` 的 `id`。

`task_worker` 进程的主循环会阻塞在本函数中，直到有消息到达。

```c
int swMsgQueue_pop(swMsgQueue *q, swQueue_data *data, int length)
{
    int ret = msgrcv(q->msg_id, data, length, data->mtype, q->flags);
    if (ret < 0)
    {
        SwooleG.error = errno;
        if (errno != ENOMSG && errno != EINTR)
        {
            swSysError("msgrcv(%d, %d, %ld) failed.", q->msg_id, length, data->mtype);
        }
    }
    return ret;
}
```


## `swRingQueue` 环形队列的数据结构

环形队列在之前的文章中从来没有出现，因为该队列是用于 `SW_MODE_THREAD` 模式下的 `worker` 线程中。由于并不是进程间的通讯，而是线程间的通讯，因此效率会更高。

`swoole` 的环形队列有两种，一种是普通的环形队列，另一种是线程安全的环形队列，本文只会讲线程安全的环形队列，

`swoole` 为了环形队列更加高效，并没有使用线程锁，而是使用了无锁结构，只会利用 `atomic` 原子锁。

值得注意的是数据结构中的 `flags`，该值只会是 0-4 中的一个，该值都是利用原子锁来改动，以此来实现互斥的作用。

```c
typedef struct _swRingQueue
{
	void **data; /* 队列空间 */
	char *flags; 
	// 0：push ready 1: push now
	// 2：pop ready; 3: pop now
	uint size; /* 队列总尺寸 */
	uint num; /* 队列当前入队数量 */
	uint head; /* 头部，出队列方向*/
	uint tail; /* 尾部，入队列方向*/

} swRingQueue;
```


## `swRingQueue` 环形队列

### `swRingQueue` 环形队列的创建

环形队列的创建很简单，就是初始化队列数据结构中的各种属性。

```c
int swRingQueue_init(swRingQueue *queue, int buffer_size)
{
    queue->size = buffer_size;
    queue->flags = (char *)sw_malloc(queue->size);
    if (queue->flags == NULL)
    {
        return -1;
    }
    queue->data = (void **)sw_calloc(queue->size, sizeof(void*));
    if (queue->data == NULL)
    {
        sw_free(queue->flags);
        return -1;
    }
    queue->head = 0;
    queue->tail = 0;
    memset(queue->flags, 0, queue->size);
    memset(queue->data, 0, queue->size * sizeof(void*));
    return 0;
}
```

### `swRingQueue` 环形队列的消息入队

发送消息首先要确定环形队列的队尾。`queue->flags` 是一个数组，里面存储着所有的队列元素当前的状态。如果当前队尾元素的状态不是 `0`，说明已经有其他线程对该队列元素进行操作，我们当前线程暂时不能对当前队尾进行操作，要等其他线程将队尾元素向后移动一位，我们才能进行更新。

当线程将当前队尾的状态从 0 改变为 1 之后，我们就要立刻更新队尾的 `offset`，让其他线程继续入队数据。接着将数据放入 `queue->data`，仅仅将数据的地址保存即可。

最后，将 `cur_tail_flag_index` 原子加 1，将队列元素状态改为待读；将 `queue->num` 原子加 1

```c
int swRingQueue_push(swRingQueue *queue, void * ele)
{
    if (!(queue->num < queue->size))
    {
        return -1;
    }
    int cur_tail_index = queue->tail;
    char * cur_tail_flag_index = queue->flags + cur_tail_index;
    //TODO Scheld
    while (!sw_atomic_cmp_set(cur_tail_flag_index, 0, 1))
    {
        cur_tail_index = queue->tail;
        cur_tail_flag_index = queue->flags + cur_tail_index;
    }

    // 两个入队线程之间的同步
    //TODO 取模操作可以优化
    int update_tail_index = (cur_tail_index + 1) % queue->size;

    // 如果已经被其他的线程更新过，则不需要更新；
    // 否则，更新为 (cur_tail_index+1) % size;
    sw_atomic_cmp_set(&queue->tail, cur_tail_index, update_tail_index);

    // 申请到可用的存储空间
    *(queue->data + cur_tail_index) = ele;

    sw_atomic_fetch_add(cur_tail_flag_index, 1);
    sw_atomic_fetch_add(&queue->num, 1);
    return 0;
}

```


### `swRingQueue` 环形队列的消息出队

与入队相反，出队需要确定当前队列的队首位置，如果队首的状态不是 2，那么说明有其他线程已经进行了出队操作，等待其他线程更新队首位置即可。

获取到队首元素之后，要立刻更新队首的新位置，然后将数据的首地址传递给 `ele`，然后将队首元素状态复原，减少队列的 `num`。


```c
int swRingQueue_pop(swRingQueue *queue, void **ele)
{
    if (!(queue->num > 0))
        return -1;
    int cur_head_index = queue->head;
    char * cur_head_flag_index = queue->flags + cur_head_index;

    while (!sw_atomic_cmp_set(cur_head_flag_index, 2, 3))
    {
        cur_head_index = queue->head;
        cur_head_flag_index = queue->flags + cur_head_index;
    }
    //TODO 取模操作可以优化
    int update_head_index = (cur_head_index + 1) % queue->size;
    sw_atomic_cmp_set(&queue->head, cur_head_index, update_head_index);
    *ele = *(queue->data + cur_head_index);

    sw_atomic_fetch_sub(cur_head_flag_index, 3);
    sw_atomic_fetch_sub(&queue->num, 1);
    return 0;
}


```