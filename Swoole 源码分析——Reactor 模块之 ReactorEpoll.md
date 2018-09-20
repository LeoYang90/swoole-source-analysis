# Swoole 源码分析——Reactor 模块之 ReactorEpoll

## `Epoll` 对象的创建

- 在 `linux` 中，最为高效的 `reactor` 机制就是 `epoll`。`swReactor` 的 `object` 会存储 `epoll` 的对象 `swReactorEpoll_s`。该数据结构中 `epfd` 是 `epoll` 的 `id`，`events` 用于在 `epoll_wait` 函数接受就绪的事件。
- 该函数最重要的是 `epoll_create`，该函数会创建 `epoll` 对象

```c
typedef struct swReactorEpoll_s swReactorEpoll;

struct swReactorEpoll_s
{
    int epfd;
    struct epoll_event *events;
};

int swReactorEpoll_create(swReactor *reactor, int max_event_num)
{
    //create reactor object
    swReactorEpoll *reactor_object = sw_malloc(sizeof(swReactorEpoll));
    if (reactor_object == NULL)
    {
        swWarn("malloc[0] failed.");
        return SW_ERR;
    }
    bzero(reactor_object, sizeof(swReactorEpoll));
    reactor->object = reactor_object;
    reactor->max_event_num = max_event_num;

    reactor_object->events = sw_calloc(max_event_num, sizeof(struct epoll_event));

    if (reactor_object->events == NULL)
    {
        swWarn("malloc[1] failed.");
        sw_free(reactor_object);
        return SW_ERR;
    }
    //epoll create
    reactor_object->epfd = epoll_create(512);
    if (reactor_object->epfd < 0)
    {
        swWarn("epoll_create failed. Error: %s[%d]", strerror(errno), errno);
        sw_free(reactor_object);
        return SW_ERR;
    }
    //binding method
    reactor->add = swReactorEpoll_add;
    reactor->set = swReactorEpoll_set;
    reactor->del = swReactorEpoll_del;
    reactor->wait = swReactorEpoll_wait;
    reactor->free = swReactorEpoll_free;

    return SW_OK;
}

```

## `Epoll` 添加监听

- `swReactorEpoll_event_set` 函数用于转化可读(`SW_EVENT_READ`)、可写(`SW_EVENT_WRITE `)的状态为 `epoll` 函数可用的 `EPOLLIN`、`EPOLLOUT`、`EPOLLERR`

```c
static sw_inline int swReactorEpoll_event_set(int fdtype)
{
    uint32_t flag = 0;
    if (swReactor_event_read(fdtype))
    {
        flag |= EPOLLIN;
    }
    if (swReactor_event_write(fdtype))
    {
        flag |= EPOLLOUT;
    }
    if (swReactor_event_error(fdtype))
    {
        //flag |= (EPOLLRDHUP);
        flag |= (EPOLLRDHUP | EPOLLHUP | EPOLLERR);
    }
    return flag;
}
```
- `swReactorEpoll_add` 函数用于为 `reactor` 添加新的文件描述符进行监控
- 添加 `fd` 最为重要的的是利用 `epoll_ctl` 函数的 `EPOLL_CTL_ADD` 命令。为了能够更为简便在调用 `epoll_wait` 后获取 `fd` 的类型，并不会仅仅向 `epoll_ctl` 函数添加 `fd`，而是会添加 `swFd` 类型，该数据结构中包含文件描述符和文件类型。
- `swReactor_add` 函数用于更新 `reactor->socket_list` 的 `fdtype` 与 `events`
- 最后需要自增 `event_num` 的数值

```c
typedef struct _swFd
{
    uint32_t fd;
    uint32_t fdtype;
} swFd;

static int swReactorEpoll_add(swReactor *reactor, int fd, int fdtype)
{
    swReactorEpoll *object = reactor->object;
    struct epoll_event e;
    swFd fd_;
    bzero(&e, sizeof(struct epoll_event));

    fd_.fd = fd;
    fd_.fdtype = swReactor_fdtype(fdtype);
    e.events = swReactorEpoll_event_set(fdtype);

    swReactor_add(reactor, fd, fdtype);

    memcpy(&(e.data.u64), &fd_, sizeof(fd_));
    if (epoll_ctl(object->epfd, EPOLL_CTL_ADD, fd, &e) < 0)
    {
        swSysError("add events[fd=%d#%d, type=%d, events=%d] failed.", fd, reactor->id, fd_.fdtype, e.events);
        swReactor_del(reactor, fd);
        return SW_ERR;
    }

    swTraceLog(SW_TRACE_EVENT, "add event[reactor_id=%d, fd=%d, events=%d]", reactor->id, fd, swReactor_events(fdtype));
    reactor->event_num++;

    return SW_OK;
}

static sw_inline void swReactor_add(swReactor *reactor, int fd, int type)
{
    swConnection *socket = swReactor_get(reactor, fd);
    socket->fdtype = swReactor_fdtype(type);
    socket->events = swReactor_events(type);
    socket->removed = 0;
}

```

## `Epoll` 修改监听

- 修改监听主要调用 `epoll_ctl` 的 `EPOLL_CTL_MOD` 命令

```c
static int swReactorEpoll_set(swReactor *reactor, int fd, int fdtype)
{
    swReactorEpoll *object = reactor->object;
    swFd fd_;
    struct epoll_event e;
    int ret;

    bzero(&e, sizeof(struct epoll_event));
    e.events = swReactorEpoll_event_set(fdtype);

    if (e.events & EPOLLOUT)
    {
        assert(fd > 2);
    }

    fd_.fd = fd;
    fd_.fdtype = swReactor_fdtype(fdtype);
    memcpy(&(e.data.u64), &fd_, sizeof(fd_));

    ret = epoll_ctl(object->epfd, EPOLL_CTL_MOD, fd, &e);
    if (ret < 0)
    {
        swSysError("reactor#%d->set(fd=%d|type=%d|events=%d) failed.", reactor->id, fd, fd_.fdtype, e.events);
        return SW_ERR;
    }
    swTraceLog(SW_TRACE_EVENT, "set event[reactor_id=%d, fd=%d, events=%d]", reactor->id, fd, swReactor_events(fdtype));
    //execute parent method
    swReactor_set(reactor, fd, fdtype);
    return SW_OK;
}

```
## `Epoll` 删除监听

- 修改监听主要调用 `epoll_ctl` 的 `EPOLL_CTL_DEL` 命令
- 最后需要更新 `event_num`

```c
static int swReactorEpoll_del(swReactor *reactor, int fd)
{
    swReactorEpoll *object = reactor->object;
    if (epoll_ctl(object->epfd, EPOLL_CTL_DEL, fd, NULL) < 0)
    {
        swSysError("epoll remove fd[%d#%d] failed.", fd, reactor->id);
        return SW_ERR;
    }

    swTraceLog(SW_TRACE_REACTOR, "remove event[reactor_id=%d|fd=%d]", reactor->id, fd);
    reactor->event_num = reactor->event_num <= 0 ? 0 : reactor->event_num - 1;
    swReactor_del(reactor, fd);

    return SW_OK;
}

```

## `Epoll` 监听等待就绪

- `swReactorEpoll_wait` 是 `reactor` 的核心，该函数最重要的就是调用 `epoll_wait`
- 首先需要通过 `timeo` 参数设置 `msec`，利用 `object->events` 设置 `events`
- `epoll_wait` 函数返回之后，如果 `n<0`，那么需要先检查 `erron`，如果是 `EINTR`，那么说明有信号触发，此时需要进行信号的回调函数，然后再继续事件循环。如果不是 `EINTR`，那么就要返回错误，结束事件循环
- 如果 `n == 0`，一般是由于 `epoll_wait` 已超时，此时需要调用超时回调函数
- 如果 `n > 0`，那么就要从 `events` 中取出已经就绪的 `swFd` 对象，并利用该对象的值初始化 `event`
- 接下来就要检查 `events[i].events` 的值，来判断具体是读就绪、写就绪还是发生了错误，值得注意的是 `EPOLLRDHUP` 事件，此事件代表着对端断开连接，这个是 `linux` 自从 `2.6.17` 的新特性
- 利用 `swReactor_getHandle` 函数取出对应的文件描述符类型的事件回调函数
- 事件循环的最后调用 `onFinish` 函数
- 如果设置了 `once`，说明此 `reactor` 只会循环一次，立即退出；否则，继续事件循环

```c
typedef struct _swEvent
{
    int fd;
    int16_t from_id;
    uint8_t type;
    swConnection *socket;
} swEvent;

static int swReactorEpoll_wait(swReactor *reactor, struct timeval *timeo)
{
    swEvent event;
    swReactorEpoll *object = reactor->object;
    swReactor_handle handle;
    int i, n, ret, msec;

    int reactor_id = reactor->id;
    int epoll_fd = object->epfd;
    int max_event_num = reactor->max_event_num;
    struct epoll_event *events = object->events;

    if (reactor->timeout_msec == 0)
    {
        if (timeo == NULL)
        {
            reactor->timeout_msec = -1;
        }
        else
        {
            reactor->timeout_msec = timeo->tv_sec * 1000 + timeo->tv_usec / 1000;
        }
    }

    reactor->start = 1;

    while (reactor->running > 0)
    {
        if (reactor->onBegin != NULL)
        {
            reactor->onBegin(reactor);
        }
        msec = reactor->timeout_msec;
        n = epoll_wait(epoll_fd, events, max_event_num, msec);
        if (n < 0)
        {
            if (swReactor_error(reactor) < 0)
            {
                swWarn("[Reactor#%d] epoll_wait failed. Error: %s[%d]", reactor_id, strerror(errno), errno);
                return SW_ERR;
            }
            else
            {
                continue;
            }
        }
        else if (n == 0)
        {
            if (reactor->onTimeout != NULL)
            {
                reactor->onTimeout(reactor);
            }
            continue;
        }
        for (i = 0; i < n; i++)
        {
            event.fd = events[i].data.u64;
            event.from_id = reactor_id;
            event.type = events[i].data.u64 >> 32;
            event.socket = swReactor_get(reactor, event.fd);

            //read
            if ((events[i].events & EPOLLIN) && !event.socket->removed)
            {
                handle = swReactor_getHandle(reactor, SW_EVENT_READ, event.type);
                ret = handle(reactor, &event);
                if (ret < 0)
                {
                    swSysError("EPOLLIN handle failed. fd=%d.", event.fd);
                }
            }
            //write
            if ((events[i].events & EPOLLOUT) && !event.socket->removed)
            {
                handle = swReactor_getHandle(reactor, SW_EVENT_WRITE, event.type);
                ret = handle(reactor, &event);
                if (ret < 0)
                {
                    swSysError("EPOLLOUT handle failed. fd=%d.", event.fd);
                }
            }
            //error
#ifndef NO_EPOLLRDHUP
            if ((events[i].events & (EPOLLRDHUP | EPOLLERR | EPOLLHUP)) && !event.socket->removed)
#else
            if ((events[i].events & (EPOLLERR | EPOLLHUP)) && !event.socket->removed)
#endif
            {
                //ignore ERR and HUP, because event is already processed at IN and OUT handler.
                if ((events[i].events & EPOLLIN) || (events[i].events & EPOLLOUT))
                {
                    continue;
                }
                handle = swReactor_getHandle(reactor, SW_EVENT_ERROR, event.type);
                ret = handle(reactor, &event);
                if (ret < 0)
                {
                    swSysError("EPOLLERR handle failed. fd=%d.", event.fd);
                }
            }
        }

        if (reactor->onFinish != NULL)
        {
            reactor->onFinish(reactor);
        }
        if (reactor->once)
        {
            break;
        }
    }
    return 0;
}

static sw_inline int swReactor_error(swReactor *reactor)
{
    switch (errno)
    {
    case EINTR:
        if (reactor->singal_no)
        {
            swSignal_callback(reactor->singal_no);
            reactor->singal_no = 0;
        }
        return SW_OK;
    }
    return SW_ERR;
}

static sw_inline swReactor_handle swReactor_getHandle(swReactor *reactor, int event_type, int fdtype)
{
    if (event_type == SW_EVENT_WRITE)
    {
        return (reactor->write_handle[fdtype] != NULL) ? reactor->write_handle[fdtype] : reactor->handle[SW_FD_WRITE];
    }
    else if (event_type == SW_EVENT_ERROR)
    {
        return (reactor->error_handle[fdtype] != NULL) ? reactor->error_handle[fdtype] : reactor->handle[SW_FD_CLOSE];
    }
    return reactor->handle[fdtype];
}
```
