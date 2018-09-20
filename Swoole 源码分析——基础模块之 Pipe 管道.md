# Swoole 源码分析——基础模块之 Pipe 管道

## 前言

管道是进程间通信 `IPC` 的最基础的方式，管道有两种类型：命名管道和匿名管道，匿名管道专门用于具有血缘关系的进程之间，完成数据传递，命名管道可以用于任何两个进程之间。`swoole` 中的管道都是匿名管道。

在 `swoole` 中，有三种不同类型的管道，其中 `swPipeBase` 是最基础的管道，`swPipeUnsock` 是利用 `socketpair` 实现的管道，`swPipeEventfd` 是 `eventfd` 实现的管道。`swoole` 并没有使用 `FIFO` 命名管道。

## `Pipe` 数据结构

不管哪种类型的管道，其基础都是 `swPipe`，该结构体包含一个具体的 `pipe` 类 `object`，代表着是否阻塞的 `blocking`，超时时间 `timeout`，还有对管道的操作函数`read`、`write`、`getfd`、`close`

```c
typedef struct _swPipe
{
    void *object;
    int blocking;
    double timeout;

    int (*read)(struct _swPipe *, void *recv, int length);
    int (*write)(struct _swPipe *, void *send, int length);
    int (*getFd)(struct _swPipe *, int master);
    int (*close)(struct _swPipe *);
} swPipe;

```

## `swPipeBase` 匿名管道

### `swPipeBase` 数据结构

数据结构非常简单，就是一个数组，存放着 `pipe` 的读端和写端。值得注意的是，`swPipeBase` 是半全工的管道，也就是说 `pipes[0]` 只能用于读，`pipes[1]` 只能用于写。

当多个进程共享这个管道的时候，所有的进程读取都需要 `read` 读端 `pipes[0]`，进程写入消息都要 `write` 写端 `pipes[1]`。

因此使用这个匿名管道的时候，一般情形是一个进程只负责写，另一个进程只负责读，只能单向传递消息，不能双向传递，否则很有可能读到了自己刚刚发送的消息。

```c
typedef struct _swPipeBase
{
    int pipes[2];
} swPipeBase;

```

### `swPipeBase` 的创建

创建匿名管道就是调用 `pipe` 函数，程序自动设置管道为非阻塞式。

```c
int swPipeBase_create(swPipe *p, int blocking)
{
    int ret;
    swPipeBase *object = sw_malloc(sizeof(swPipeBase));
    if (object == NULL)
    {
        return -1;
    }
    p->blocking = blocking;
    ret = pipe(object->pipes);
    if (ret < 0)
    {
        swWarn("pipe() failed. Error: %s[%d]", strerror(errno), errno);
        sw_free(object);
        return -1;
    }
    else
    {
        //Nonblock
        swSetNonBlock(object->pipes[0]);
        swSetNonBlock(object->pipes[1]);
        p->timeout = -1;
        p->object = object;
        p->read = swPipeBase_read;
        p->write = swPipeBase_write;
        p->getFd = swPipeBase_getFd;
        p->close = swPipeBase_close;
    }
    return 0;
}

```

### `swPipeBase_read` 管道的读

由于匿名管道被设置为非阻塞式，无法实现超时等待写入。如果想要阻塞式的向管道写入数据，设置一定超时时间，就需要利用 `poll` 函数。当 `pipefd` 可读时，`poll` 立刻返回，或者达到超时时间。

```c
static int swPipeBase_read(swPipe *p, void *data, int length)
{
    swPipeBase *object = p->object;
    if (p->blocking == 1 && p->timeout > 0)
    {
        if (swSocket_wait(object->pipes[0], p->timeout * 1000, SW_EVENT_READ) < 0)
        {
            return SW_ERR;
        }
    }
    return read(object->pipes[0], data, length);
}

int swSocket_wait(int fd, int timeout_ms, int events)
{
    struct pollfd event;
    event.fd = fd;
    event.events = 0;

    if (events & SW_EVENT_READ)
    {
        event.events |= POLLIN;
    }
    if (events & SW_EVENT_WRITE)
    {
        event.events |= POLLOUT;
    }
    while (1)
    {
        int ret = poll(&event, 1, timeout_ms);
        if (ret == 0)
        {
            return SW_ERR;
        }
        else if (ret < 0 && errno != EINTR)
        {
            swWarn("poll() failed. Error: %s[%d]", strerror(errno), errno);
            return SW_ERR;
        }
        else
        {
            return SW_OK;
        }
    }
    return SW_OK;
}
```

### `swPipeBase_write` 管道的写入

管道的写入直接调用 `write` 即可，非阻塞式 `IO` 会立刻返回结果。

```c
static int swPipeBase_write(swPipe *p, void *data, int length)
{
    swPipeBase *this = p->object;
    return write(this->pipes[1], data, length);
}

```

### `swPipeBase_getFd`

本函数用于获取管道的读端或者写端。

```c
static int swPipeBase_getFd(swPipe *p, int isWriteFd)
{
    swPipeBase *this = p->object;
    return (isWriteFd == 0) ? this->pipes[0] : this->pipes[1];
}

```

### `swPipeBase_close` 关闭管道

```c
static int swPipeBase_close(swPipe *p)
{
    int ret1, ret2;
    swPipeBase *this = p->object;
    ret1 = close(this->pipes[0]);
    ret2 = close(this->pipes[1]);
    sw_free(this);
    return 0 - ret1 - ret2;
}

```

## `swPipeEventfd` 管道

### `swPipeEventfd` 数据结构

数据结构中仅仅存放 `eventfd` 函数返回的文件描述符。

和 `pipe` 管道不同的是，`eventfd` 只有一个文件描述符，读和写都是对这个文件描述符进行操作。

该管道同样也是只适用于进程间单向通信。

```c
typedef struct _swPipeEventfd
{
    int event_fd;
} swPipeEventfd;

```

### `swPipeEventfd_read` 管道的读取

类似于匿名管道，`eventfd` 也不支持超时等待，因此还是利用 `poll` 函数进行超时等待。

由于 `eventfd` 可能是阻塞式，因此 `read` 时可能会被信号打断。

```c
static int swPipeEventfd_read(swPipe *p, void *data, int length)
{
    int ret = -1;
    swPipeEventfd *object = p->object;

    //eventfd not support socket timeout
    if (p->blocking == 1 && p->timeout > 0)
    {
        if (swSocket_wait(object->event_fd, p->timeout * 1000, SW_EVENT_READ) < 0)
        {
            return SW_ERR;
        }
    }

    while (1)
    {
        ret = read(object->event_fd, data, sizeof(uint64_t));
        if (ret < 0 && errno == EINTR)
        {
            continue;
        }
        break;
    }
    return ret;
}

```

### `swPipeEventfd_write` 管道的写入

写入和读取的过程类似，注意被信号打断后继续循环即可。

```c
static int swPipeEventfd_write(swPipe *p, void *data, int length)
{
    int ret;
    swPipeEventfd *this = p->object;
    while (1)
    {
        ret = write(this->event_fd, data, sizeof(uint64_t));
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
        }
        break;
    }
    return ret;
}

```

### `swPipeEventfd_getFd` 


```c
static int swPipeEventfd_getFd(swPipe *p, int isWriteFd)
{
    return ((swPipeEventfd *) (p->object))->event_fd;
}

```

### `swPipeEventfd_close` 关闭管道


```c
static int swPipeEventfd_close(swPipe *p)
{
    int ret;
    ret = close(((swPipeEventfd *) (p->object))->event_fd);
    sw_free(p->object);
    return ret;
}

```

## `swPipeUnsock` 管道

### `swPipeUnsock` 数据结构

不同于 `pipe` 的匿名管道，`swPipeUnsock` 管道是双向通信的管道。

因此两个进程利用 `swPipeUnsock` 管道进行通信的时候，独占一个 `sock`，也就是说 `A` 进程读写都是用 `socks[0]`，`B` 进程读写都是用 `socks[1]`，`socks[0]` 写入的消息会在 `socks[1]` 读出来，反之，`socks[0]` 读出的消息是 `sock[1]` 写入的，这样就实现了两个进程的双向通信。

```c
typedef struct _swPipeUnsock
{
    /**
     * master : socks[1]
     * worker : socks[0]
     */
    int socks[2];
    /**
     * master pipe is closed
     */
    uint8_t pipe_master_closed;
    /**
     * worker pipe is closed
     */
    uint8_t pipe_worker_closed;
} swPipeUnsock;
```

### `swPipeUnsock` 的创建

`swPipeUnsock` 的创建主要是调用 `socketpair` 函数，`protocol` 决定了创建的 `socket` 是 `SOCK_DGRAM` 类型还是 `SOCK_STREAM` 类型。

```c
int swPipeUnsock_create(swPipe *p, int blocking, int protocol)
{
    int ret;
    swPipeUnsock *object = sw_malloc(sizeof(swPipeUnsock));
    if (object == NULL)
    {
        swWarn("malloc() failed.");
        return SW_ERR;
    }
    bzero(object, sizeof(swPipeUnsock));
    p->blocking = blocking;
    ret = socketpair(AF_UNIX, protocol, 0, object->socks);
    if (ret < 0)
    {
        swWarn("socketpair() failed. Error: %s [%d]", strerror(errno), errno);
        sw_free(object);
        return SW_ERR;
    }
    else
    {
        //Nonblock
        if (blocking == 0)
        {
            swSetNonBlock(object->socks[0]);
            swSetNonBlock(object->socks[1]);
        }

        int sbsize = SwooleG.socket_buffer_size;
        swSocket_set_buffer_size(object->socks[0], sbsize);
        swSocket_set_buffer_size(object->socks[1], sbsize);

        p->object = object;
        p->read = swPipeUnsock_read;
        p->write = swPipeUnsock_write;
        p->getFd = swPipeUnsock_getFd;
        p->close = swPipeUnsock_close;
    }
    return 0;
}

int swSocket_set_buffer_size(int fd, int buffer_size)
{
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size)) < 0)
    {
        swSysError("setsockopt(%d, SOL_SOCKET, SO_SNDBUF, %d) failed.", fd, buffer_size);
        return SW_ERR;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size)) < 0)
    {
        swSysError("setsockopt(%d, SOL_SOCKET, SO_RCVBUF, %d) failed.", fd, buffer_size);
        return SW_ERR;
    }
    return SW_OK;
}
```

### `swPipeUnsock_getFd` 函数

同样的获取管道文件描述符根据 `master` 来决定。

```c
static int swPipeUnsock_getFd(swPipe *p, int master)
{
    swPipeUnsock *this = p->object;
    return master == 1 ? this->socks[1] : this->socks[0];
}

``` 

### `swPipeUnsock_close` 关闭管道

关闭管道就是调用 `close` 来依次关闭两个 `socket`.

```c
static int swPipeUnsock_close(swPipe *p)
{
    swPipeUnsock *object = p->object;
    int ret = swPipeUnsock_close_ext(p, 0);
    sw_free(object);
    return ret;
}

int swPipeUnsock_close_ext(swPipe *p, int which)
{
    int ret1 = 0, ret2 = 0;
    swPipeUnsock *object = p->object;

    if (which == SW_PIPE_CLOSE_MASTER)
    {
        if (object->pipe_master_closed)
        {
            return SW_ERR;
        }
        ret1 = close(object->socks[1]);
        object->pipe_master_closed = 1;
    }
    else if (which == SW_PIPE_CLOSE_WORKER)
    {
        if (object->pipe_worker_closed)
        {
            return SW_ERR;
        }
        ret1 = close(object->socks[0]);
        object->pipe_worker_closed = 1;
    }
    else
    {
        ret1 = swPipeUnsock_close_ext(p, SW_PIPE_CLOSE_MASTER);
        ret2 = swPipeUnsock_close_ext(p, SW_PIPE_CLOSE_WORKER);
    }

    return 0 - ret1 - ret2;
}
```


## 管道的应用

### `tasker` 模块

当调用 `taskwait` 函数后，投递的 `worker` 进程会阻塞在 `serv->task_notify[SwooleWG.id]` 管道的读取中，`tasker` 模块处理完毕后，会向 `serv->task_notify[source_worker_id]` 管道写入数据。

这个就是 `pipe` 函数或者 `eventfd` 创建的匿名管道的用途，用于单向的进程通信（`tasker` 进程向 `worker` 进程传递数据）。

```c
static inline int swPipeNotify_auto(swPipe *p, int blocking, int semaphore)
{
#ifdef HAVE_EVENTFD
    return swPipeEventfd_create(p, blocking, semaphore, 0);
#else
    return swPipeBase_create(p, blocking);
#endif
}

```

### `worker` 模块

`manager` 负责为 `worker` 进程创建 `pipe_master` 与 `pipe_worker`。用于 `reactor` 线程与 `worker` 进程直接进行通信。

```c
int swManager_start(swFactory *factory)
{
   ...
   
   for (i = 0; i < serv->worker_num; i++)
    {
        if (swPipeUnsock_create(&object->pipes[i], 1, SOCK_DGRAM) < 0)
        {
            return SW_ERR;
        }
        serv->workers[i].pipe_master = object->pipes[i].getFd(&object->pipes[i], SW_PIPE_MASTER);
        serv->workers[i].pipe_worker = object->pipes[i].getFd(&object->pipes[i], SW_PIPE_WORKER);
        serv->workers[i].pipe_object = &object->pipes[i];
        swServer_store_pipe_fd(serv, serv->workers[i].pipe_object);
    }
   
   ...

}
```

当 `reactor` 线程启动的时候，会将 `pipe_master` 加入 `reactor` 的监控当中。

```c
static int swReactorThread_loop(swThreadParam *param)
{

   ...
    
   for (i = 0; i < serv->worker_num; i++)
   {
       if (i % serv->reactor_num == reactor_id)
       {
           pipe_fd = serv->workers[i].pipe_master;
           
           swSetNonBlock(pipe_fd);
           reactor->add(reactor, pipe_fd, SW_FD_PIPE);

           if (thread->notify_pipe == 0)
           {
               thread->notify_pipe = serv->workers[i].pipe_worker;
           }
       
       }
   
   }
   ...
}

```

在 `worker` 进程中，会将 `pipe_worker` 作为另一端 `socket` 放入 `worker` 的 `reactor` 事件循环中进行监控。


```c
int swWorker_loop(swFactory *factory, int worker_id)
{
    ...
    
    int pipe_worker = worker->pipe_worker;

    swSetNonBlock(pipe_worker);
    SwooleG.main_reactor->ptr = serv;
    SwooleG.main_reactor->add(SwooleG.main_reactor, pipe_worker, SW_FD_PIPE | SW_EVENT_READ);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_PIPE, swWorker_onPipeReceive);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_WRITE, swReactor_onWrite);
    
    ...


}


```

### `tasker` 进程

`tasker` 进程中管道的创建是 `swProcessPool_create` 函数完成的。

```c
int swProcessPool_create(swProcessPool *pool, int worker_num, int max_request, key_t msgqueue_key, int ipc_mode)
{
    ...
    
    else if (ipc_mode == SW_IPC_UNIXSOCK)
    {
        pool->pipes = sw_calloc(worker_num, sizeof(swPipe));
        if (pool->pipes == NULL)
        {
            swWarn("malloc[2] failed.");
            return SW_ERR;
        }

        swPipe *pipe;
        int i;
        for (i = 0; i < worker_num; i++)
        {
            pipe = &pool->pipes[i];
            if (swPipeUnsock_create(pipe, 1, SOCK_DGRAM) < 0)
            {
                return SW_ERR;
            }
            pool->workers[i].pipe_master = pipe->getFd(pipe, SW_PIPE_MASTER);
            pool->workers[i].pipe_worker = pipe->getFd(pipe, SW_PIPE_WORKER);
            pool->workers[i].pipe_object = pipe;
        }
    }
    
    ...
}
```
向 `tasker` 进程发布任务的时候，会调用 `swProcessPool_dispatch` 函数，进而会向 `pipe_master` 管道写入任务数据。

```c
int swProcessPool_dispatch(swProcessPool *pool, swEventData *data, int *dst_worker_id)
{
    ...
    
    ret = swWorker_send2worker(worker, data, sendn, SW_PIPE_MASTER | SW_PIPE_NONBLOCK);
    
    ...
}

int swWorker_send2worker(swWorker *dst_worker, void *buf, int n, int flag)
{
    int pipefd, ret;

    if (flag & SW_PIPE_MASTER)
    {
        pipefd = dst_worker->pipe_master;
    }
    else
    {
        pipefd = dst_worker->pipe_worker;
    }
    
    ...
    
    if ((flag & SW_PIPE_NONBLOCK) && SwooleG.main_reactor)
    {
        return SwooleG.main_reactor->write(SwooleG.main_reactor, pipefd, buf, n);
    }
    else
    {
        ret = swSocket_write_blocking(pipefd, buf, n);
    }

    return ret;


}

```

`tasker` 进程并没有 `reactor` 事件循环，只会阻塞在某个系统调用中，如果 `tasker` 进程采用的是 `unix socket` 进行投递任务的时候，就会阻塞在对管道的 `read` 当中。

```c
static int swProcessPool_worker_loop(swProcessPool *pool, swWorker *worker)
{
    ...
    
    while (SwooleG.running > 0 && task_n > 0)
    {
        ...
        
        else
        {
            n = read(worker->pipe_worker, &out.buf, sizeof(out.buf));
            if (n < 0 && errno != EINTR)
            {
                swSysError("[Worker#%d] read(%d) failed.", worker->id, worker->pipe_worker);
            }
        }
        
        ...
    }

    ...
}


```


