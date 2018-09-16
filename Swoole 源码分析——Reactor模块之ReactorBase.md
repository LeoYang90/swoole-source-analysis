# Swoole 源码分析——Reactor模块之ReactorBase

## 前言

作为一个网络框架，最为核心的就是消息的接受与发送。高效的 `reactor` 模式一直是众多网络框架的首要选择，本节主要讲解 `swoole` 中的 `reactor` 模块。

[UNP 学习笔记——IO 复用](https://laravel-china.org/articles/14025/unp-learning-notes-io-reuse)

## `Reactor` 的数据结构

- `Reactor` 的数据结构比较复杂，首先 `object` 是具体 `Reactor` 对象的首地址，`ptr` 是拥有 `Reactor` 对象的类的指针，
- `event_num` 存放现有监控的 `fd` 个数，`max_event_num` 存放允许持有的最大事件数目，`flag` 为标记位，
- `id` 用于存放对应 `reactor` 的 `id`，`running` 用于标记该 `reactor` 是否正在运行，一般是创建时会被置为 1，`start` 标记着 `reactor` 是否已经被启动，一般是进行 `wait` 监控时被置为 1，`once` 标志着 `reactor` 是否是仅需要一次性监控，`check_timer` 标志着是否要检查定时任务
- `singal_no`：每次 `reactor` 由于 `fd` 的就绪返回时，`reactor` 都会检查这个 `singal_no`，如果这个值不为空，那么就会调用相应的信号回调函数
- `disable_accept` 标志着是否接受新的连接，这个只有主 `reactor` 中才会设置为 0，其他 `reactor` 线程不需要接受新的连接，只需要接受数据即可
- `check_signalfd` 标志着是否需要检查 `signalfd`
- `thread` 用于标记当前是使用 `reactor` 多线程模式还是多进程模式，一般都会使用多线程模式
- `timeout_msec` 用于记录每次 `reactor->wait` 的超时
- `max_socket` 记录着 `reactor` 中最大的连接数，与 `max_connection` 的值一致; `socket_list` 是 `reactor` 多线程模式的监听的 `socket`，与 `connection_list` 保持一致； `socket_array` 是 `reactor` 多进程模式中的监听的 `fd`
- `handle` 是默认就绪的回调函数，`write_handle` 是写就绪的回调函数, `error_handle` 包含错误就绪的回调函数
- `timewheel`、`heartbeat_interval`、`last_heartbeat_time` 是心跳检测，专门剔除空闲连接
- `last_malloc_trim_time` 记录了上次返还给系统的时间，`swoole` 会定期的通过 `malloc_trim` 函数返回空闲的内存空间
 
```
struct _swReactor
{
    void *object;
    void *ptr;  //reserve

    /**
     * last signal number
     */
    int singal_no;

    uint32_t event_num;
    uint32_t max_event_num;

    uint32_t check_timer :1;
    uint32_t running :1;
    uint32_t start :1;
    uint32_t once :1;

    /**
     * disable accept new connection
     */
    uint32_t disable_accept :1;

    uint32_t check_signalfd :1;

    /**
     * multi-thread reactor, cannot realloc sockets.
     */
    uint32_t thread :1;

	/**
	 * reactor->wait timeout (millisecond) or -1
	 */
	int32_t timeout_msec;

	uint16_t id; //Reactor ID
	uint16_t flag; //flag

    uint32_t max_socket;

#ifdef SW_USE_MALLOC_TRIM
    time_t last_malloc_trim_time;
#endif

#ifdef SW_USE_TIMEWHEEL
    swTimeWheel *timewheel;
    uint16_t heartbeat_interval;
    time_t last_heartbeat_time;
#endif

    /**
     * for thread
     */
    swConnection *socket_list;

    /**
     * for process
     */
    swArray *socket_array;

    swReactor_handle handle[SW_MAX_FDTYPE];        //默认事件
    swReactor_handle write_handle[SW_MAX_FDTYPE];  //扩展事件1(一般为写事件)
    swReactor_handle error_handle[SW_MAX_FDTYPE];  //扩展事件2(一般为错误事件,如socket关闭)

    int (*add)(swReactor *, int fd, int fdtype);
    int (*set)(swReactor *, int fd, int fdtype);
    int (*del)(swReactor *, int fd);
    int (*wait)(swReactor *, struct timeval *);
    void (*free)(swReactor *);

    int (*setHandle)(swReactor *, int fdtype, swReactor_handle);
    swDefer_callback *defer_callback_list;
    swDefer_callback idle_task;
    swDefer_callback future_task;

    void (*onTimeout)(swReactor *);
    void (*onFinish)(swReactor *);
    void (*onBegin)(swReactor *);

    void (*enable_accept)(swReactor *);
    int (*can_exit)(swReactor *);

    int (*write)(swReactor *, int, void *, int);
    int (*close)(swReactor *, int);
    int (*defer)(swReactor *, swCallback, void *);
};

```

## `reactor` 的创建

- `reactor` 的创建主要是调用 `swReactorEpoll_create` 函数
- `setHandle` 函数是为监听的 `fd` 设置回调函数，包括读就绪、写就绪、错误
- `onFinish` 是每次调用 `epoll` 函数返回后，处理具体逻辑后，最后调用的回调函数
- `onTimeout` 是每次调用 `epoll` 函数超时后的回调函数 
- `write` 函数是利用 `reactor` 向 `socket` 发送数据的接口
- `defer` 函数用于添加 `defer_callback_list` 成员变量，这个成员变量是回调函数列表，`epoll` 函数超时和  `onFinish` 都会循环 `defer_callback_list` 里面的回调函数
- `socket_array` 是监听的 `fd` 列表

```
int swReactor_create(swReactor *reactor, int max_event)
{
    int ret;
    bzero(reactor, sizeof(swReactor));

#ifdef HAVE_EPOLL
    ret = swReactorEpoll_create(reactor, max_event);

    reactor->running = 1;

    reactor->setHandle = swReactor_setHandle;

    reactor->onFinish = swReactor_onFinish;
    reactor->onTimeout = swReactor_onTimeout;

    reactor->write = swReactor_write;
    reactor->defer = swReactor_defer;
    reactor->close = swReactor_close;

    reactor->socket_array = swArray_new(1024, sizeof(swConnection));
    if (!reactor->socket_array)
    {
        swWarn("create socket array failed.");
        return SW_ERR;
    }

    return ret;
}

```

## `reactor` 的函数

### `reactor` 设置文件就绪回调函数 `swReactor_setHandle`

- `reactor` 中设置的 `fd` 由两部分构成，一种是 `swFd_type`，标识着文件描述符的类型，一种是 `swEvent_type` 标识着文件描述符感兴趣的读写事件

```
enum swFd_type
{
    SW_FD_TCP             = 0, //tcp socket
    SW_FD_LISTEN          = 1, //server socket
    SW_FD_CLOSE           = 2, //socket closed
    SW_FD_ERROR           = 3, //socket error
    SW_FD_UDP             = 4, //udp socket
    SW_FD_PIPE            = 5, //pipe
    SW_FD_STREAM          = 6, //stream socket
    SW_FD_WRITE           = 7, //fd can write
    SW_FD_TIMER           = 8, //timer fd
    SW_FD_AIO             = 9, //linux native aio
    SW_FD_SIGNAL          = 11, //signalfd
    SW_FD_DNS_RESOLVER    = 12, //dns resolver
    SW_FD_INOTIFY         = 13, //server socket
    SW_FD_USER            = 15, //SW_FD_USER or SW_FD_USER+n: for custom event
    SW_FD_STREAM_CLIENT   = 16, //swClient stream
    SW_FD_DGRAM_CLIENT    = 17, //swClient dgram
};

enum swEvent_type
{
    SW_EVENT_DEAULT = 256,
    SW_EVENT_READ = 1u << 9,
    SW_EVENT_WRITE = 1u << 10,
    SW_EVENT_ERROR = 1u << 11,
    SW_EVENT_ONCE = 1u << 12,
};
```
- `swReactor_fdtype` 用于从文件描述符中提取 `swFd_type`，也就是文件描述符的类型：

```
static sw_inline int swReactor_fdtype(int fdtype)
{
    return fdtype & (~SW_EVENT_READ) & (~SW_EVENT_WRITE) & (~SW_EVENT_ERROR);
}
```
- `swReactor_event_read`、`swReactor_event_write`、`swReactor_event_error` 这三个函数与 `swFd_type` 正相反，是从文件描述符中提取读写事件	

```
static sw_inline int swReactor_event_read(int fdtype)
{
    return (fdtype < SW_EVENT_DEAULT) || (fdtype & SW_EVENT_READ);
}

static sw_inline int swReactor_event_write(int fdtype)
{
    return fdtype & SW_EVENT_WRITE;
}

static sw_inline int swReactor_event_error(int fdtype)
{
    return fdtype & SW_EVENT_ERROR;
}

```

- `swReactor_setHandle` 用于为文件描述符 `_fdtype` 设定读就绪、写就绪的回调函数

```
int swReactor_setHandle(swReactor *reactor, int _fdtype, swReactor_handle handle)
{
    int fdtype = swReactor_fdtype(_fdtype);

    if (fdtype >= SW_MAX_FDTYPE)
    {
        swWarn("fdtype > SW_MAX_FDTYPE[%d]", SW_MAX_FDTYPE);
        return SW_ERR;
    }

    if (swReactor_event_read(_fdtype))
    {
        reactor->handle[fdtype] = handle;
    }
    else if (swReactor_event_write(_fdtype))
    {
        reactor->write_handle[fdtype] = handle;
    }
    else if (swReactor_event_error(_fdtype))
    {
        reactor->error_handle[fdtype] = handle;
    }
    else
    {
        swWarn("unknow fdtype");
        return SW_ERR;
    }

    return SW_OK;
}

```

### `reactor` 添加 `defer` 函数

- `defer` 函数会在每次事件循环结束或超时的时候调用
- `swReactor_defer` 函数会为 `defer_callback_list` 添加新的回调函数

```
static int swReactor_defer(swReactor *reactor, swCallback callback, void *data)
{
    swDefer_callback *cb = sw_malloc(sizeof(swDefer_callback));
    if (!cb)
    {
        swWarn("malloc(%ld) failed.", sizeof(swDefer_callback));
        return SW_ERR;
    }
    cb->callback = callback;
    cb->data = data;
    LL_APPEND(reactor->defer_callback_list, cb);
    return SW_OK;
}

```

### `reactor` 超时回调函数

`epoll` 在设置的时间内没有返回的话，也会自动返回，这个时候就会调用超时回调函数：

```
static void swReactor_onTimeout(swReactor *reactor)
{
    swReactor_onTimeout_and_Finish(reactor);

    if (reactor->disable_accept)
    {
        reactor->enable_accept(reactor);
        reactor->disable_accept = 0;
    }
}

```
- `swReactor_onTimeout_and_Finish` 函数用于在超时、`finish` 等情况下调用
- 这个函数首先会检查是否存在定时任务，如果有定时任务就会调用 `swTimer_select` 执行回调函数
- 接下来就要执行存储在 `defer_callback_list` 的多个回调函数， 该 `list` 是事先定义好的需要 `defer` 执行的函数
- `idle_task` 是 `EventLoop` 中使用的每一轮事件循环结束时调用的函数。
- 如果当前 `reactor` 当前在 `work` 进程，那么就要调用 `swWorker_try_to_exit` 函数来判断 `event_num` 是不是为 0，如果为 0 ，那么就置 `running` 为0，停止等待事件就绪
- 如果当前 `SwooleG.serv` 为空，`swReactor_empty` 函数用于判断当前 `reactor` 是否还有事件在监听，如果没有，那么就会设置 `running` 为 0
- 判断当前时间是否可以调用 `malloc_trim` 释放空闲的内存，如果距离上次释放内存的时间超过了 `SW_MALLOC_TRIM_INTERVAL`，就更新 `last_malloc_trim_time` 并调用 `malloc_trim`

```
static void swReactor_onTimeout_and_Finish(swReactor *reactor)
{
    //check timer
    if (reactor->check_timer)
    {
        swTimer_select(&SwooleG.timer);
    }
    //defer callback
    swDefer_callback *cb, *tmp;
    swDefer_callback *defer_callback_list = reactor->defer_callback_list;
    reactor->defer_callback_list = NULL;
    LL_FOREACH(defer_callback_list, cb)
    {
        cb->callback(cb->data);
    }
    LL_FOREACH_SAFE(defer_callback_list, cb, tmp)
    {
        sw_free(cb);
    }
    //callback at the end
    if (reactor->idle_task.callback)
    {
        reactor->idle_task.callback(reactor->idle_task.data);
    }
#ifdef SW_COROUTINE
    //coro timeout
    if (!swIsMaster())
    {
        coro_handle_timeout();
    }
#endif
    //server worker
    swWorker *worker = SwooleWG.worker;
    if (worker != NULL)
    {
        if (SwooleWG.wait_exit == 1)
        {
            swWorker_try_to_exit();
        }
    }
    //not server, the event loop is empty
    if (SwooleG.serv == NULL && swReactor_empty(reactor))
    {
        reactor->running = 0;
    }

#ifdef SW_USE_MALLOC_TRIM
    if (SwooleG.serv && reactor->last_malloc_trim_time < SwooleG.serv->gs->now - SW_MALLOC_TRIM_INTERVAL)
    {
        malloc_trim(SW_MALLOC_TRIM_PAD);
        reactor->last_malloc_trim_time = SwooleG.serv->gs->now;
    }
#endif
}

```

- `swReactor_empty` 用来判断当前的 `reactor` 是否还有事件需要监听
- 可以从函数中可以看出来，如果定时任务 `timer` 里面还有等待的任务，那么就可以返回 false
- `event_num` 如果为 0，可以返回 true，结束事件循环
- 对于协程来说，还要调用 `can_exit` 来判断是否可以退出事件循环

```
int swReactor_empty(swReactor *reactor)
{
    //timer
    if (SwooleG.timer.num > 0)
    {
        return SW_FALSE;
    }

    int empty = SW_FALSE;
    //thread pool
    if (SwooleAIO.init && reactor->event_num == 1 && SwooleAIO.task_num == 0)
    {
        empty = SW_TRUE;
    }
    //no event
    else if (reactor->event_num == 0)
    {
        empty = SW_TRUE;
    }
    //coroutine
    if (empty && reactor->can_exit && reactor->can_exit(reactor))
    {
        empty = SW_TRUE;
    }
    return empty;
}

```

### `reactor` 事件循环结束函数

- 每次事件循环结束之后，都会调用 `onFinish` 函数
- 该函数主要函数调用 `swReactor_onTimeout_and_Finish`，在此之前还会检查在事件循环过程中是否有信号触发

```
static void swReactor_onFinish(swReactor *reactor)
{
    //check signal
    if (reactor->singal_no)
    {
        swSignal_callback(reactor->singal_no);
        reactor->singal_no = 0;
    }
    swReactor_onTimeout_and_Finish(reactor);
}

```

### `reactor` 事件循环关闭函数

- 当一个 `socket` 关闭的时候，会调用 `close` 函数，对应的回调函数就是 `swReactor_close`
- 该函数用于释放 `swConnection` 内部申请的内存，并调用 `close` 函数关闭连接

```
int swReactor_close(swReactor *reactor, int fd)
{
    swConnection *socket = swReactor_get(reactor, fd);
    if (socket->out_buffer)
    {
        swBuffer_free(socket->out_buffer);
    }
    if (socket->in_buffer)
    {
        swBuffer_free(socket->in_buffer);
    }
    if (socket->websocket_buffer)
    {
        swString_free(socket->websocket_buffer);
    }
    bzero(socket, sizeof(swConnection));
    socket->removed = 1;
    swTraceLog(SW_TRACE_CLOSE, "fd=%d.", fd);
    return close(fd);
}

```
- `swReactor_get` 用于从 `reactor` 中根据文件描述符获取对应 `swConnection` 对象的场景，由于 `swoole` 一般都会采用 `reactor` 多线程模式，因此基本只会执行 `return &reactor->socket_list[fd];` 这一句。
- `socket_list` 这个列表与 `connection_list` 保持一致，是事先申请的大小为 `max_connection` 的类型是 `swConnection` 的数组
- `socket_list` 中的数据有一部分是已经建立连接的 `swConnection` 的对象，有一部分仅仅是空的 `swConnection`，这个时候 `swConnection->fd` 为 0

```
static sw_inline swConnection* swReactor_get(swReactor *reactor, int fd)
{
    if (reactor->thread)
    {
        return &reactor->socket_list[fd];
    }
    swConnection *socket = (swConnection*) swArray_alloc(reactor->socket_array, fd);
    if (socket == NULL)
    {
        return NULL;
    }
    if (!socket->active)
    {
        socket->fd = fd;
    }
    return socket;
}

```

### `reactor` 的数据写入

- 如果想对一个 `socket` 写入数据，并不能简单的直接调用 `send` 函数，因为这个函数可能被信号打断（EINTR）、可能暂时不可用(EAGAIN)、可能只写入了部分数据，也有可能写入成功。因此，`reactor` 定义了一个函数专门处理写数据这一逻辑
- 首先要利用 `swReactor_get` 取出对应的 `swConnection` 对象
- 如果取出的对象 `fd` 是 0，说明这个 `fd` 文件描述符事先并没有在 `reactor` 里面进行监听
- 如果这个 `socket` 的 `out_buffer` 为空，那么就先尝试利用 `swConnection_send` 函数调用 `send` 函数，观察是否可以直接把所有数据发送成功
	- 如果返回 `EINTR`，那么说明被信号打断了，重新发送即可
	- 如果返回 `EAGAIN`，那么说明此时 `socket` 暂时不可用，此时需要将 `fd` 文件描述符的写就绪状态添加到 `reactor` 中，然后将数据拷贝到 `out_buffer` 中去
	- 如果返回写入的数据量小于 `n`，说明只写入了部分，此时需要把没有写入的部分拷贝到 `out_buffer` 中去
- 如果 `out_buffer` 不为空，那么说明此时 `socket` 不可写，那么就要将数据拷贝到 `out_buffer` 中去，等着 `reactor` 监控到写就绪之后，把 `out_buffer` 发送出去。
- 如果此时 `out_buffer` 存储空间不足，那么就要 `swYield` 让进程休眠一段时间，等待 `fd` 的写就绪状态

```
int swReactor_write(swReactor *reactor, int fd, void *buf, int n)
{
    int ret;
    swConnection *socket = swReactor_get(reactor, fd);
    swBuffer *buffer = socket->out_buffer;

    if (socket->fd == 0)
    {
        socket->fd = fd;
    }

    if (socket->buffer_size == 0)
    {
        socket->buffer_size = SwooleG.socket_buffer_size;
    }

    if (socket->nonblock == 0)
    {
        swoole_fcntl_set_option(fd, 1, -1);
        socket->nonblock = 1;
    }

    if (n > socket->buffer_size)
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_PACKAGE_LENGTH_TOO_LARGE, "data is too large, cannot exceed buffer size.");
        return SW_ERR;
    }

    if (swBuffer_empty(buffer))
    {
        if (socket->ssl_send)
        {
            goto do_buffer;
        }

        do_send:
        ret = swConnection_send(socket, buf, n, 0);

        if (ret > 0)
        {
            if (n == ret)
            {
                return ret;
            }
            else
            {
                buf += ret;
                n -= ret;
                goto do_buffer;
            }
        }
#ifdef HAVE_KQUEUE
        else if (errno == EAGAIN || errno == ENOBUFS)
#else
        else if (errno == EAGAIN)
#endif
        {
            do_buffer:
            if (!socket->out_buffer)
            {
                buffer = swBuffer_new(sizeof(swEventData));
                if (!buffer)
                {
                    swWarn("create worker buffer failed.");
                    return SW_ERR;
                }
                socket->out_buffer = buffer;
            }

            socket->events |= SW_EVENT_WRITE;

            if (socket->events & SW_EVENT_READ)
            {
                if (reactor->set(reactor, fd, socket->fdtype | socket->events) < 0)
                {
                    swSysError("reactor->set(%d, SW_EVENT_WRITE) failed.", fd);
                }
            }
            else
            {
                if (reactor->add(reactor, fd, socket->fdtype | SW_EVENT_WRITE) < 0)
                {
                    swSysError("reactor->add(%d, SW_EVENT_WRITE) failed.", fd);
                }
            }

            goto append_buffer;
        }
        else if (errno == EINTR)
        {
            goto do_send;
        }
        else
        {
            SwooleG.error = errno;
            return SW_ERR;
        }
    }
    else
    {
        append_buffer: if (buffer->length > socket->buffer_size)
        {
            if (socket->dontwait)
            {
                SwooleG.error = SW_ERROR_OUTPUT_BUFFER_OVERFLOW;
                return SW_ERR;
            }
            else
            {
                swoole_error_log(SW_LOG_WARNING, SW_ERROR_OUTPUT_BUFFER_OVERFLOW, "socket#%d output buffer overflow.", fd);
                swYield();
                swSocket_wait(fd, SW_SOCKET_OVERFLOW_WAIT, SW_EVENT_WRITE);
            }
        }

        if (swBuffer_append(buffer, buf, n) < 0)
        {
            return SW_ERR;
        }
    }
    return SW_OK;
}

```

