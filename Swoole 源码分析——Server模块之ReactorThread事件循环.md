# Swoole 源码分析——Server模块之ReactorThread事件循环（上）

## 前言

经过 `php_swoole_server_before_start` 调用 `swReactorThread_create` 创建了 `serv->reactor_threads` 对象后，`swServer_start` 调用 `swReactorThread_start` 创建了 `reactor` 多线程。线程在建立之时，就会调用 `swReactorThread_loop` 函数开启 `reactor` 事件循环。

## `swServer_master_onAccept` 接受连接请求

- `swServer_start_proxy` 设置了 `main_reactor` 监听 `socket` 的事件回调函数，在 `main_reactor` 调用 `wait` 后，如果 `listen_list` 中有 `TCP` 的 `connect` 请求，`reactor` 就会调用 `swServer_master_onAccept` 函数
- `accept4`、`accept` 两个函数唯一的区别在于最后的参数，`accept4` 可以将返回的 `socket` 设置为相应的文件属性
- 如果返回的文件描述符异常
	- 如果错误是 `EAGAIN`，说明此时没有连接等待接受，那么可以返回成功，继续事件循环
	- 如果错误是 `EINTR`，说明 `accept` 被信号打断，继续调用 `accept` 即可
	- 如果错误是 `EMFILE` 或者 `ENFILE`，那么当前文件描述符已经达到最大，此时应该停止接受连接请求
- 设置 `connect_notify` 为 1，告知 `reactor` 线程需要通知 `worker` 接受新的连接
- 根据 `new_fd` 分配其该处理的 `reactor` 线程，并向该 `reactor` 线程添加该文件描述符的监控，但是值得注意的是，这时只会监听写事件，用于向客户端说明已接收 `accept` 请求，并不会监听读事件
- `swServer_connection_new` 函数用于更新 `serv->connection_list[new_fd]` 的属性

```
int swServer_master_onAccept(swReactor *reactor, swEvent *event)
{
    swServer *serv = reactor->ptr;
    swReactor *sub_reactor;
    swSocketAddress client_addr;
    socklen_t client_addrlen = sizeof(client_addr);
    swListenPort *listen_host = serv->connection_list[event->fd].object;

    int new_fd = 0, reactor_id = 0, i;

    //SW_ACCEPT_AGAIN
    for (i = 0; i < SW_ACCEPT_MAX_COUNT; i++)
    {
#ifdef HAVE_ACCEPT4
        new_fd = accept4(event->fd, (struct sockaddr *) &client_addr, &client_addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
        new_fd = accept(event->fd, (struct sockaddr *) &client_addr, &client_addrlen);
#endif
        if (new_fd < 0)
        {
            switch (errno)
            {
            case EAGAIN:
                return SW_OK;
            case EINTR:
                continue;
            default:
                if (errno == EMFILE || errno == ENFILE)
                {
                    swServer_disable_accept(reactor);
                    reactor->disable_accept = 1;
                }
                swoole_error_log(SW_LOG_ERROR, SW_ERROR_SYSTEM_CALL_FAIL, "accept() failed. Error: %s[%d]", strerror(errno), errno);
                return SW_OK;
            }
        }
#ifndef HAVE_ACCEPT4
        else
        {
            swoole_fcntl_set_option(new_fd, 1, 1);
        }
#endif

        swTrace("[Master] Accept new connection. maxfd=%d|reactor_id=%d|conn=%d", swServer_get_maxfd(serv), reactor->id, new_fd);

        //too many connection
        if (new_fd >= serv->max_connection)
        {
            swoole_error_log(SW_LOG_WARNING, SW_ERROR_SERVER_TOO_MANY_SOCKET, "Too many connections [now: %d].", new_fd);
            close(new_fd);
            return SW_OK;
        }

        if (serv->factory_mode == SW_MODE_SINGLE)
        {
            reactor_id = 0;
        }
        else
        {
            reactor_id = new_fd % serv->reactor_num;
        }

        //add to connection_list
        swConnection *conn = swServer_connection_new(serv, listen_host, new_fd, event->fd, reactor_id);
        memcpy(&conn->info.addr, &client_addr, sizeof(client_addr));
        sub_reactor = &serv->reactor_threads[reactor_id].reactor;
        conn->socket_type = listen_host->type;

#ifdef SW_USE_OPENSSL
        if (listen_host->ssl)
        {
            if (swSSL_create(conn, listen_host->ssl_context, 0) < 0)
            {
                bzero(conn, sizeof(swConnection));
                close(new_fd);
                return SW_OK;
            }
        }
        else
        {
            conn->ssl = NULL;
        }
#endif
        /*
         * [!!!] new_connection function must before reactor->add
         */
        conn->connect_notify = 1;
        if (sub_reactor->add(sub_reactor, new_fd, SW_FD_TCP | SW_EVENT_WRITE) < 0)
        {
            bzero(conn, sizeof(swConnection));
            close(new_fd);
            return SW_OK;
        }

#ifdef SW_ACCEPT_AGAIN
        continue;
#else
        break;
#endif
    }
    return SW_OK;
}


```

### `swServer_connection_new` 创建新的连接对象

- `ls` 是负责监听连接的 `swListenPort` 对象，`fd` 是已建立连接的文件描述符，`from_fd` 是负责监听连接的文件描述符，`reactor_id` 是分配给已连接的文件描述符的 `reactor`
- 如果 `ls` 设置了 `open_tcp_nodelay`，那么就要设置 `fd` 为 `TCP_NODELAY`；如果设置了接受、发送缓冲区大小，就要设置 `SO_RCVBUF`、`SO_SNDBUF`；
- 设置 `swConnection` 的 `fd`、`from_id`、`from_fd`、`connect_time`、`last_time` 等等参数
- 设置连接的 `session_id`

```
static swConnection* swServer_connection_new(swServer *serv, swListenPort *ls, int fd, int from_fd, int reactor_id)
{
    swConnection* connection = NULL;

    serv->stats->accept_count++;
    sw_atomic_fetch_add(&serv->stats->connection_num, 1);
    sw_atomic_fetch_add(&ls->connection_num, 1);

    if (fd > swServer_get_maxfd(serv))
    {
        swServer_set_maxfd(serv, fd);
    }

    connection = &(serv->connection_list[fd]);
    bzero(connection, sizeof(swConnection));

    //TCP Nodelay
    if (ls->open_tcp_nodelay)
    {
        int sockopt = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &sockopt, sizeof(sockopt)) < 0)
        {
            swSysError("setsockopt(TCP_NODELAY) failed.");
        }
        connection->tcp_nodelay = 1;
    }

    //socket recv buffer size
    if (ls->kernel_socket_recv_buffer_size > 0)
    {
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &ls->kernel_socket_recv_buffer_size, sizeof(int)))
        {
            swSysError("setsockopt(SO_RCVBUF, %d) failed.", ls->kernel_socket_recv_buffer_size);
        }
    }

    //socket send buffer size
    if (ls->kernel_socket_send_buffer_size > 0)
    {
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &ls->kernel_socket_send_buffer_size, sizeof(int)) < 0)
        {
            swSysError("setsockopt(SO_SNDBUF, %d) failed.", ls->kernel_socket_send_buffer_size);
        }
    }

    connection->fd = fd;
    connection->from_id = serv->factory_mode == SW_MODE_SINGLE ? SwooleWG.id : reactor_id;
    connection->from_fd = (sw_atomic_t) from_fd;
    connection->connect_time = serv->gs->now;
    connection->last_time = serv->gs->now;
    connection->active = 1;
    connection->buffer_size = ls->socket_buffer_size;

#ifdef SW_REACTOR_SYNC_SEND
    if (serv->factory_mode != SW_MODE_THREAD && !ls->ssl)
    {
        connection->direct_send = 1;
    }
#endif

#ifdef SW_REACTOR_USE_SESSION
    swSession *session;
    sw_spinlock(&serv->gs->spinlock);
    int i;
    uint32_t session_id = serv->gs->session_round;
    //get session id
    for (i = 0; i < serv->max_connection; i++)
    {
        session_id++;
        //SwooleGS->session_round just has 24 bits size;
        if (unlikely(session_id == 1 << 24))
        {
            session_id = 1;
        }
        session = swServer_get_session(serv, session_id);
        //vacancy
        if (session->fd == 0)
        {
            session->fd = fd;
            session->id = session_id;
            session->reactor_id = connection->from_id;
            break;
        }
    }
    serv->gs->session_round = session_id;
    sw_spinlock_release(&serv->gs->spinlock);
    connection->session_id = session_id;
#endif

    return connection;
}


```

## `swReactorThread_loop` 事件循环

- `reactor` 多线程在建立之时，就会调用 `swReactorThread_loop` 函数开启 `reactor` 事件循环。
- 从参数中获取当前 `reactor` 线程的 `id`
- 设置线程特有数据 `SwooleTG`。`factory_lock_target`、`factory_target_worker` 用于后面向 `worker` 进程传输数据时，一次只能传递一部分，下次传输数据时需要锁定对应的 `worker` 进程。
- `swServer_get_thread` 用于利用 `reactor_id` 获取对应的 `swReactorThread` 对象
- 如果设置了 `CPU_AFFINITY` 选项（将 `swoole` 的 `reactor` 线程与对应的 `worker` 进程绑定到固定的一个核上。可以避免进程/线程的运行时在多个核之间互相切换，提高 `CPU Cache` 的命中率），这时要通过 `reactor_id` 将当前线程绑定到对应的 `CPU` 核中(`worker` 进程以相同方式绑定，这样就实现了 `reactor` 线程与对应的 `worker` 进程绑定到固定的一个核上)。
- 如果开启了 `cpu_affinity_ignore` 设置(接受一个数组作为参数，例如 `array(0, 1)` 表示不使用 `CPU0`, `CPU1`，专门空出来处理网络中断。如果当前系统内核与网卡有多队列特性，网络中断会分布到多核，可以缓解网络中断的压力，这个时候不需要设置该选项)，那么就要从 `serv->cpu_affinity_available` 数组中挑选 `CPU` 进行绑定
- `swReactor_create` 创造本线程的 `reactor` 对象，并且设置 `SW_FD_PIPE` 的读写事件回调函数：`swReactorThread_onPipeReceive`、`swReactorThread_onPipeWrite`，用于与 `worker` 进程进行通信
- 如果 `server` 中存在 `UDP` 监听端口，而且该监听的 `socket` 与 `reactor_id` 相对应，那么向 `reactor` 对象添加文件描述符进行监听
- `swReactorThread_set_protocol` 用于设置 `TCP`、`UDP` 的读写回调函数: `swReactorThread_onPackage`、`swReactorThread_onWrite`、`swReactorThread_onRead` 用来接收客户端传输的信息，并且设置监听 `socket` 的 `onRead` 函数、`onPackage` 函数
- 构造 `pipe_read_list` 存储 `pipe`
- 遍历 `serv->workers`，找出与当前 `reactor` 相对应的的 `worker`，添加 `pipe_master` 文件描述符到 `reactor` 进行监控，设置其 `serv->connection_list[pipe_master]` 的 `in_buffer`、`from_id`、`object`，当前线程的 `notify_pipe`、`pipe_read_list`
- 如果开启了时间轮算法，就要创建 `reactor->timewheel` 对象，计算 `reactor->heartbeat_interval`，替代原有的 `onFinish`、`onTimeout` 回调函数。

```
static int swReactorThread_loop(swThreadParam *param)
{
    swServer *serv = SwooleG.serv;
    int ret;
    int reactor_id = param->pti;

    pthread_t thread_id = pthread_self();

    SwooleTG.factory_lock_target = 0;
    SwooleTG.factory_target_worker = -1;
    SwooleTG.id = reactor_id;
    SwooleTG.type = SW_THREAD_REACTOR;

    SwooleTG.buffer_stack = swString_new(8192);
    if (SwooleTG.buffer_stack == NULL)
    {
        return SW_ERR;
    }

    swReactorThread *thread = swServer_get_thread(serv, reactor_id);
    swReactor *reactor = &thread->reactor;

    SwooleTG.reactor = reactor;

#ifdef HAVE_CPU_AFFINITY
    //cpu affinity setting
    if (serv->open_cpu_affinity)
    {
        cpu_set_t cpu_set;
        CPU_ZERO(&cpu_set);

        if (serv->cpu_affinity_available_num)
        {
            CPU_SET(serv->cpu_affinity_available[reactor_id % serv->cpu_affinity_available_num], &cpu_set);
        }
        else
        {
            CPU_SET(reactor_id % SW_CPU_NUM, &cpu_set);
        }

        if (0 != pthread_setaffinity_np(thread_id, sizeof(cpu_set), &cpu_set))
        {
            swSysError("pthread_setaffinity_np() failed.");
        }
    }
#endif

    ret = swReactor_create(reactor, SW_REACTOR_MAXEVENTS);
    if (ret < 0)
    {
        return SW_ERR;
    }

    swSignal_none();

    reactor->ptr = serv;
    reactor->id = reactor_id;
    reactor->thread = 1;
    reactor->socket_list = serv->connection_list;
    reactor->max_socket = serv->max_connection;

    reactor->onFinish = NULL;
    reactor->onTimeout = NULL;
    reactor->close = swReactorThread_close;

    reactor->setHandle(reactor, SW_FD_CLOSE, swReactorThread_onClose);
    reactor->setHandle(reactor, SW_FD_PIPE | SW_EVENT_READ, swReactorThread_onPipeReceive);
    reactor->setHandle(reactor, SW_FD_PIPE | SW_EVENT_WRITE, swReactorThread_onPipeWrite);

    //listen UDP
    if (serv->have_udp_sock == 1)
    {
        swListenPort *ls;
        LL_FOREACH(serv->listen_list, ls)
        {
            if (ls->type == SW_SOCK_UDP || ls->type == SW_SOCK_UDP6 || ls->type == SW_SOCK_UNIX_DGRAM)
            {
                if (ls->sock % serv->reactor_num != reactor_id)
                {
                    continue;
                }
                if (ls->type == SW_SOCK_UDP)
                {
                    serv->connection_list[ls->sock].info.addr.inet_v4.sin_port = htons(ls->port);
                }
                else
                {
                    serv->connection_list[ls->sock].info.addr.inet_v6.sin6_port = htons(ls->port);
                }
                serv->connection_list[ls->sock].fd = ls->sock;
                serv->connection_list[ls->sock].socket_type = ls->type;
                serv->connection_list[ls->sock].object = ls;
                ls->thread_id = thread_id;
                reactor->add(reactor, ls->sock, SW_FD_UDP);
            }
        }
    }

    //set protocol function point
    swReactorThread_set_protocol(serv, reactor);

    int i = 0, pipe_fd;
#ifdef SW_USE_RINGBUFFER
    int j = 0;
#endif

    if (serv->factory_mode == SW_MODE_PROCESS)
    {
#ifdef SW_USE_RINGBUFFER
        thread->pipe_read_list = sw_calloc(serv->reactor_pipe_num, sizeof(int));
        if (thread->pipe_read_list == NULL)
        {
            swSysError("thread->buffer_pipe create failed");
            return SW_ERR;
        }
#endif

        for (i = 0; i < serv->worker_num; i++)
        {
            if (i % serv->reactor_num == reactor_id)
            {
                pipe_fd = serv->workers[i].pipe_master;

                //for request
                swBuffer *buffer = swBuffer_new(sizeof(swEventData));
                if (!buffer)
                {
                    swWarn("create buffer failed.");
                    break;
                }
                serv->connection_list[pipe_fd].in_buffer = buffer;

                //for response
                swSetNonBlock(pipe_fd);
                reactor->add(reactor, pipe_fd, SW_FD_PIPE);

                if (thread->notify_pipe == 0)
                {
                    thread->notify_pipe = serv->workers[i].pipe_worker;
                }

                /**
                 * mapping reactor_id and worker pipe
                 */
                serv->connection_list[pipe_fd].from_id = reactor_id;
                serv->connection_list[pipe_fd].fd = pipe_fd;
                serv->connection_list[pipe_fd].object = sw_malloc(sizeof(swLock));

                /**
                 * create pipe lock
                 */
                if (serv->connection_list[pipe_fd].object == NULL)
                {
                    swWarn("create pipe mutex lock failed.");
                    break;
                }
                swMutex_create(serv->connection_list[pipe_fd].object, 0);

#ifdef SW_USE_RINGBUFFER
                thread->pipe_read_list[j] = pipe_fd;
                j++;
#endif
            }
        }
    }

#ifdef SW_USE_TIMEWHEEL
    if (serv->heartbeat_idle_time > 0)
    {
        if (serv->heartbeat_idle_time < SW_TIMEWHEEL_SIZE)
        {
            reactor->timewheel = swTimeWheel_new(serv->heartbeat_idle_time);
            reactor->heartbeat_interval = 1;
        }
        else
        {
            reactor->timewheel = swTimeWheel_new(SW_TIMEWHEEL_SIZE);
            reactor->heartbeat_interval = serv->heartbeat_idle_time / SW_TIMEWHEEL_SIZE;
        }
        reactor->last_heartbeat_time = 0;
        if (reactor->timewheel == NULL)
        {
            swSysError("thread->timewheel create failed.");
            return SW_ERR;
        }
        reactor->timeout_msec = reactor->heartbeat_interval * 1000;
        reactor->onFinish = swReactorThread_onReactorCompleted;
        reactor->onTimeout = swReactorThread_onReactorCompleted;
    }
#endif

    //wait other thread
#ifdef HAVE_PTHREAD_BARRIER
    pthread_barrier_wait(&serv->barrier);
#else
    SW_START_SLEEP;
#endif
    //main loop
    reactor->wait(reactor, NULL);
    //shutdown
    reactor->free(reactor);

#ifdef SW_USE_TIMEWHEEL
    if (reactor->timewheel)
    {
        swTimeWheel_free(reactor->timewheel);
    }
#endif

    swString_free(SwooleTG.buffer_stack);
    pthread_exit(0);
    return SW_OK;
}


void swReactorThread_set_protocol(swServer *serv, swReactor *reactor)
{
    //UDP Packet
    reactor->setHandle(reactor, SW_FD_UDP, swReactorThread_onPackage);
    //Write
    reactor->setHandle(reactor, SW_FD_TCP | SW_EVENT_WRITE, swReactorThread_onWrite);
    //Read
    reactor->setHandle(reactor, SW_FD_TCP | SW_EVENT_READ, swReactorThread_onRead);

    swListenPort *ls;
    //listen the all tcp port
    LL_FOREACH(serv->listen_list, ls)
    {
        if (swSocket_is_dgram(ls->type))
        {
            continue;
        }
        swPort_set_protocol(ls);
    }
}

```

## `swReactorThread_onWrite` 写事件回调

- 当 `master` 线程的 `main_reactor` 接受到新的请求后，就会设置相应的 `swConnection.connect_notify` 为 1，这个时候 `reactor` 线程的任务并不是向客户端发送数据，而是向 `worker` 进程发送 `SW_EVENT_CONNECT` 事件
	- 如果使用时间轮算法，那么就需要调用 `swTimeWheel_add` 将该 `swConnection` 对象添加到时间轮的监控中
	- 如果存在 `onConnect` 回调函数，就要调用 `swServer_tcp_notify` 函数向 `worker` 进程发送事件
	- 如果 `out_buffer` 缓冲区有数据，就将其数据发送给客户端
	- 如果启用了 `enable_delay_receive` 选项，那么就要把当前连接 `socket` 从 `reactor` 中删除，等待服务端调用 `$serv->confirm($fd)` 对连接进行确认；否则就要一并开启 `socket` 的可读事件，读取客户端发来的数据。
- 如果心跳检测或者时间轮算法检测到死连接，那么就会重置 `close_notify` 为 1，这个时候就要通知 `worker` 进行关闭事件
- `out_buffer` 不为空，说明此时服务端有数据需要发给客户端，数据会被存储在 `swBuffer` 这个链表数据结构中，每个链表元素是一个数据包，此时需要检验数据类型是 `SW_CHUNK_CLOSE`、`SW_CHUNK_SENDFILE` 还是其他普通数据。
- `swConnection_buffer_send` 用于发送普通数据，这个函数会尝试向 `socket` 发送一次数据，可能出现的情况有：
	- 全部发送成功：继续循环，发送下一个 `buffer`
	- 发送部分数据：继续循环，发送这一个 `buffer` 的剩余元素
	- `send_wait` 为 1：跳出循环，等待下一次可写就绪
	- 发生异常：继续循环，重新发送
	- `close_wait` 为 1：连接已关闭，关闭这个 `socket` 文件描述符的监控
- 如果发送了部分数据，重置 `overflow` 为 0
- 如果 `high_watermark` 为 1，说明此前 `out_buffer` 数据已达到高水位线，此时重新比较 `out_buffer` 数据大小，如果低于 `buffer_low_watermark`，就要通知 `worker` 进程调用 `onBufferEmpty` 回调函数。
- 如果 	`out_buffer` 为空，那么重新设置 `socket` 文件描述符的 `reactor` 监听事件，删除写就绪，只设置读就绪。这个是水平触发模式的必要步骤，避免无数据写入时，频繁地调用写就绪回调函数。


```
static int swReactorThread_onWrite(swReactor *reactor, swEvent *ev)
{
    int ret;
    swServer *serv = SwooleG.serv;
    swBuffer_trunk *chunk;
    int fd = ev->fd;

    if (serv->factory_mode == SW_MODE_PROCESS)
    {
        assert(fd % serv->reactor_num == reactor->id);
        assert(fd % serv->reactor_num == SwooleTG.id);
    }

    swConnection *conn = swServer_connection_get(serv, fd);
    if (conn == NULL || conn->active == 0)
    {
        return SW_ERR;
    }

    swTraceLog(SW_TRACE_REACTOR, "fd=%d, conn->connect_notify=%d, conn->close_notify=%d, serv->disable_notify=%d, conn->close_force=%d",
            fd, conn->connect_notify, conn->close_notify, serv->disable_notify, conn->close_force);

    if (conn->connect_notify)
    {
        conn->connect_notify = 0;
#ifdef SW_USE_TIMEWHEEL
        if (reactor->timewheel)
        {
            swTimeWheel_add(reactor->timewheel, conn);
        }
#endif
#ifdef SW_USE_OPENSSL
        if (conn->ssl)
        {
            goto listen_read_event;
        }
#endif
        //notify worker process
        if (serv->onConnect)
        {
            swServer_tcp_notify(serv, conn, SW_EVENT_CONNECT);
            if (!swBuffer_empty(conn->out_buffer))
            {
                goto _pop_chunk;
            }
        }
        //delay receive, wait resume command.
        if (serv->enable_delay_receive)
        {
            conn->listen_wait = 1;
            return reactor->del(reactor, fd);
        }
        else
        {
#ifdef SW_USE_OPENSSL
            listen_read_event:
#endif
            return reactor->set(reactor, fd, SW_EVENT_TCP | SW_EVENT_READ);
        }
    }
    else if (conn->close_notify)
    {
#ifdef SW_USE_OPENSSL
        if (conn->ssl && conn->ssl_state != SW_SSL_STATE_READY)
        {
            return swReactorThread_close(reactor, fd);
        }
#endif
        swServer_tcp_notify(serv, conn, SW_EVENT_CLOSE);
        conn->close_notify = 0;
        return SW_OK;
    }
    else if (serv->disable_notify && conn->close_force)
    {
        return swReactorThread_close(reactor, fd);
    }

    _pop_chunk: while (!swBuffer_empty(conn->out_buffer))
    {
        chunk = swBuffer_get_trunk(conn->out_buffer);
        if (chunk->type == SW_CHUNK_CLOSE)
        {
            close_fd: reactor->close(reactor, fd);
            return SW_OK;
        }
        else if (chunk->type == SW_CHUNK_SENDFILE)
        {
            ret = swConnection_onSendfile(conn, chunk);
        }
        else
        {
            ret = swConnection_buffer_send(conn);
        }

        if (ret < 0)
        {
            if (conn->close_wait)
            {
                goto close_fd;
            }
            else if (conn->send_wait)
            {
                break;
            }
        }
    }

    if (conn->overflow && conn->out_buffer->length < conn->buffer_size)
    {
        conn->overflow = 0;
    }

    if (serv->onBufferEmpty && conn->high_watermark)
    {
        swListenPort *port = swServer_get_port(serv, fd);
        if (conn->out_buffer->length <= port->buffer_low_watermark)
        {
            conn->high_watermark = 0;
            swServer_tcp_notify(serv, conn, SW_EVENT_BUFFER_EMPTY);
        }
    }

    //remove EPOLLOUT event
    if (!conn->removed && swBuffer_empty(conn->out_buffer))
    {
        reactor->set(reactor, fd, SW_FD_TCP | SW_EVENT_READ);
    }
    return SW_OK;
}


```

### `swConnection_buffer_send` 普通数据的发送

值得注意的是此函数 `conn` 中的 `socket` 文件描述符是非阻塞的，这个函数会尝试调用一次 `swConnection_send` 发送数据，可能发生的事件有：

- 全部发送成功：`swBuffer_pop_trunk` 删除当前链表元素
- 发送部分数据：增加 `offset`
- `send_wait` 为 1：告知此时 `socket` 已不可写
- 发生异常：返回错误
- `close_wait` 为 1：连接已关闭

无论是哪种情况，发送数据后都会立刻返回结果，不会阻塞导致 `reactor` 线程事件循环停滞。

```
int swConnection_buffer_send(swConnection *conn)
{
    int ret, sendn;

    swBuffer *buffer = conn->out_buffer;
    swBuffer_trunk *trunk = swBuffer_get_trunk(buffer);
    sendn = trunk->length - trunk->offset;

    if (sendn == 0)
    {
        swBuffer_pop_trunk(buffer, trunk);
        return SW_OK;
    }

    ret = swConnection_send(conn, trunk->store.ptr + trunk->offset, sendn, 0);
    if (ret < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swWarn("send to fd[%d] failed. Error: %s[%d]", conn->fd, strerror(errno), errno);
            break;
        case SW_CLOSE:
            conn->close_errno = errno;
            conn->close_wait = 1;
            return SW_ERR;
        case SW_WAIT:
            conn->send_wait = 1;
            return SW_ERR;
        default:
            break;
        }
        return SW_OK;
    }
    //trunk full send
    else if (ret == sendn || sendn == 0)
    {
        swBuffer_pop_trunk(buffer, trunk);
    }
    else
    {
        trunk->offset += ret;
    }
    return SW_OK;
}

```

## `swReactorThread_onRead` 读就绪事件回调

- 读就绪事件发生后，如果使用了时间轮算法，那么需要更新时间轮的数据
- 更新 `last_time`、`last_time_usec`
- 调用 `port->onRead` 函数。值得注意的是，这个 `onRead` 函数，是在 `reactor` 线程启动时，调用 `swPort_set_protocol` 这个函数设置的。`open_length_check`、`open_length_check` 等等不同的设置，`onRead` 也会不同。

```
static int swReactorThread_onRead(swReactor *reactor, swEvent *event)
{
    swServer *serv = reactor->ptr;
    /**
     * invalid event
     * The server has been actively closed the connection, the client also initiated off, fd has been reused.
     */
    if (event->socket->from_fd == 0)
    {
        return SW_OK;
    }
    swListenPort *port = swServer_get_port(serv, event->fd);
#ifdef SW_USE_OPENSSL
    if (swReactorThread_verify_ssl_state(reactor, port, event->socket) < 0)
    {
        return swReactorThread_close(reactor, event->fd);
    }
#endif

#ifdef SW_USE_TIMEWHEEL
    /**
     * TimeWheel update
     */
    if (reactor->timewheel && swTimeWheel_new_index(reactor->timewheel) != event->socket->timewheel_index)
    {
        swTimeWheel_update(reactor->timewheel, event->socket);
    }
#endif

    event->socket->last_time = serv->gs->now;
#ifdef SW_BUFFER_RECV_TIME
    event->socket->last_time_usec = swoole_microtime();
#endif

    return port->onRead(reactor, port, event);
}

```

### `swPort_set_protocol` 函数

- 如果开启了 `open_eof_check` 选项，将检测客户端连接发来的数据，当数据包结尾是指定的字符串时才会投递给Worker进程。否则会一直拼接数据包，直到超过缓存区或者超时才会中止。这个时候，`onRead` 函数就是 `swPort_onRead_check_eof`
- 如果开启了 `open_length_check` 选项，包长检测提供了固定包头+包体这种格式协议的解析。启用后，可以保证Worker进程onReceive每次都会收到一个完整的数据包。这个时候 `onRead` 函数就是 `swPort_onRead_check_length`
- 如果没有设置任何选项，那么发送给 `worker` 的数据包并不保证是完整的，需要用户自己去拼装。此时 `onRead` 函数就是 `swPort_onRead_raw`

```
void swPort_set_protocol(swListenPort *ls)
{
    //Thread mode must copy the data.
    //will free after onFinish
    if (ls->open_eof_check)
    {
        if (ls->protocol.package_eof_len > sizeof(ls->protocol.package_eof))
        {
            ls->protocol.package_eof_len = sizeof(ls->protocol.package_eof);
        }
        ls->protocol.onPackage = swReactorThread_dispatch;
        ls->onRead = swPort_onRead_check_eof;
    }
    else if (ls->open_length_check)
    {
        if (ls->protocol.package_length_type != '\0')
        {
            ls->protocol.get_package_length = swProtocol_get_package_length;
        }
        ls->protocol.onPackage = swReactorThread_dispatch;
        ls->onRead = swPort_onRead_check_length;
    }
    else if (ls->open_http_protocol)
    {
        if (ls->open_websocket_protocol)
        {
            ls->protocol.get_package_length = swWebSocket_get_package_length;
            ls->protocol.onPackage = swWebSocket_dispatch_frame;
            ls->protocol.package_length_size = SW_WEBSOCKET_HEADER_LEN + SW_WEBSOCKET_MASK_LEN + sizeof(uint64_t);
        }
#ifdef SW_USE_HTTP2
        else if (ls->open_http2_protocol)
        {
            ls->protocol.get_package_length = swHttp2_get_frame_length;
            ls->protocol.package_length_size = SW_HTTP2_FRAME_HEADER_SIZE;
            ls->protocol.onPackage = swReactorThread_dispatch;
        }
#endif
        ls->onRead = swPort_onRead_http;
    }
    else if (ls->open_mqtt_protocol)
    {
        ls->protocol.get_package_length = swMqtt_get_package_length;
        ls->protocol.onPackage = swReactorThread_dispatch;
        ls->onRead = swPort_onRead_check_length;
    }
    else if (ls->open_redis_protocol)
    {
        ls->protocol.onPackage = swReactorThread_dispatch;
        ls->onRead = swPort_onRead_redis;
    }
    else
    {
        ls->onRead = swPort_onRead_raw;
    }
}

```

### `swPort_onRead_raw` 函数

- `swPort_onRead_raw` 函数是最简单的发送 `worker` 进程的函数
- 调用 `swConnection_recv` 函数之后，会有三种情况
	- 发生错误
	- 未接受到数据，说明连接已关闭
	- 接受到数据
- 接受到数据之后，就要调用 `swReactorThread_dispatch` 函数将数据发送给相应的 `worker`，`task.target_worker_id` 被初始化为 -1。

```
static int swPort_onRead_raw(swReactor *reactor, swListenPort *port, swEvent *event)
{
    int n;
    swDispatchData task;
    swConnection *conn =  event->socket;

    n = swConnection_recv(conn, task.data.data, SW_BUFFER_SIZE, 0);
    if (n < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swSysError("recv from connection#%d failed.", event->fd);
            return SW_OK;
        case SW_CLOSE:
            conn->close_errno = errno;
            goto close_fd;
        default:
            return SW_OK;
        }
    }
    else if (n == 0)
    {
        close_fd: swReactorThread_onClose(reactor, event);
        return SW_OK;
    }
    else
    {
        task.data.info.fd = event->fd;
        task.data.info.from_id = event->from_id;
        task.data.info.len = n;
        task.data.info.type = SW_EVENT_TCP;
        task.target_worker_id = -1;
        return swReactorThread_dispatch(conn, task.data.data, task.data.info.len);
    }
    return SW_OK;
}

```

### `swReactorThread_dispatch` 发送数据

- `swReactorThread_dispatch` 函数负责向 `worker` 进程投递消息，`server` 的配置不同，投递的方式也不同，在本函数中可以看出，可以看出有三种区别大的配置：普通模式调度、`Stream` 模式调度、`RINGBUFFER` 共享内存池发送数据包
- 在普通模式中，会将数据包拆分为多个 `SW_BUFFER_SIZE` 大小的小包，然后通过 `pipe` 投递给 `worker` 进程，这种模式适用于 `SW_DISPATCH_ROUND`(轮循模式)、`SW_DISPATCH_FDMOD`(固定模式)、`SW_DISPATCH_QUEUE`(抢占模式)、`SW_DISPATCH_IPMOD`(IP分配)、`SW_DISPATCH_UIDMOD`(UID分配)、`SW_DISPATCH_USERFUNC`(用户自定义)
	- 这时，所有小的数据包都被打包成 `swDispatchData` 对象，其 `data.info.type` 都是 `SW_EVENT_PACKAGE_START`，只有最后一个数据包类型是 `SW_EVENT_PACKAGE_END`
	- 值得注意的是 `factory_lock_target` 这个属性，这个属性使得所有的小数据包都发送给同一个 `worker` 进程
- `Stream` 模式调度与以上的模式都不同，`worker` 也不会是由 `reactor` 线程来指定，而是由 `worker` 进程自己来 `accept`，接受 `reactor` 线程的请求。
	- 当采用 `Stream` 模式调用的时候，首先需要 `swStream_new` 新建 `swStream` 对象，然后利用 `swStream_send` 函数发送数据
	- 值得注意的是，这个时候 `task.data.info.type` 为 `SW_EVENT_PACKAGE_END`，`task.data.info.fd` 是 `conn->session_id` 而不是 `conn->fd`，`task.data.info.len` 为 0
	- 具体关于 `Stream` 模式的流程，我们在 `worker` 事件循环来讲。
- `RINGBUFFER` 共享内存池解决了大包发送的问题，数据包大小将不受限制，一次 `IPC` 就可以投递整个数据包，再也不需要拆包，然后多次调用 `send` 系统调用。
	- `RINGBUFFER` 共享内存池需要调用 `swReactorThread_alloc` 函数从 `reactor->buffer_input` 中申请内存，将数据复制到共享内存中后，将共享内存的首地址存储到 `swPackage` 对象中，再将 `swPackage` 对象打包到 `swDispatchData` 对象中。这样，`worker` 进程和 `reactor` 线程之间传递的仅仅是共享内存的首地址，无需真正传递大数据包，`worker` 进程得到首地址后只需要从共享内存中拷贝数据即可。	

```
enum swFactory_dispatch_mode
{
    SW_DISPATCH_ROUND    = 1,
    SW_DISPATCH_FDMOD    = 2,
    SW_DISPATCH_QUEUE    = 3,
    SW_DISPATCH_IPMOD    = 4,
    SW_DISPATCH_UIDMOD   = 5,
    SW_DISPATCH_USERFUNC = 6,
    SW_DISPATCH_STREAM   = 7,
};

typedef struct _swDataHead
{
    int fd;
    uint16_t len;
    int16_t from_id;
    uint8_t type;
    uint8_t flags;
    uint16_t from_fd;
#ifdef SW_BUFFER_RECV_TIME
    double time;
#endif
} swDataHead;

typedef struct _swEventData
{
    swDataHead info;
    char data[SW_BUFFER_SIZE];
} swEventData;

typedef struct
{
    long target_worker_id;
    swEventData data;
} swDispatchData;

typedef struct _swPackage
{
    void *data;
    uint32_t length;
    uint32_t id;
} swPackage;

int swReactorThread_dispatch(swConnection *conn, char *data, uint32_t length)
{
    swFactory *factory = SwooleG.factory;
    swServer *serv = factory->ptr;
    swDispatchData task;

    task.data.info.from_fd = conn->from_fd;
    task.data.info.from_id = conn->from_id;
#ifdef SW_BUFFER_RECV_TIME
    task.data.info.time = conn->last_time_usec;
#endif

    if (serv->dispatch_mode == SW_DISPATCH_STREAM)
    {
        swStream *stream = swStream_new(serv->stream_socket, 0, SW_SOCK_UNIX_STREAM);
        if (stream == NULL)
        {
            return SW_ERR;
        }
        stream->response = swReactorThread_onStreamResponse;
        stream->session_id = conn->session_id;
        swListenPort *port = swServer_get_port(serv, conn->fd);
        swStream_set_max_length(stream, port->protocol.package_max_length);

        task.data.info.fd = conn->session_id;
        task.data.info.type = SW_EVENT_PACKAGE_END;
        task.data.info.len = 0;

        if (swStream_send(stream, (char*) &task.data.info, sizeof(task.data.info)) < 0)
        {
            return SW_ERR;
        }
        if (swStream_send(stream, data, length) < 0)
        {
            stream->cancel = 1;
            return SW_ERR;
        }
        return SW_OK;
    }

    task.data.info.fd = conn->fd;

    swTrace("send string package, size=%ld bytes.", (long)length);

#ifdef SW_USE_RINGBUFFER
    swServer *serv = SwooleG.serv;
    swReactorThread *thread = swServer_get_thread(serv, SwooleTG.id);

    swPackage package;
    package.length = length;
    package.data = swReactorThread_alloc(thread, package.length);

    task.data.info.type = SW_EVENT_PACKAGE;
    task.data.info.len = sizeof(package);

    memcpy(package.data, data, package.length);
    memcpy(task.data.data, &package, sizeof(package));

    task.target_worker_id = swServer_worker_schedule(serv, conn->fd, &task.data);

    //dispatch failed, free the memory.
    if (factory->dispatch(factory, &task) < 0)
    {
        thread->buffer_input->free(thread->buffer_input, package.data);
    }
    else
    {
        return SW_OK;
    }
#else

    task.data.info.type = SW_EVENT_PACKAGE_START;
    task.target_worker_id = -1;

    /**
     * lock target
     */
    SwooleTG.factory_lock_target = 1;

    size_t send_n = length;
    size_t offset = 0;

    while (send_n > 0)
    {
        if (send_n > SW_BUFFER_SIZE)
        {
            task.data.info.len = SW_BUFFER_SIZE;
        }
        else
        {
            task.data.info.type = SW_EVENT_PACKAGE_END;
            task.data.info.len = send_n;
        }

        task.data.info.fd = conn->fd;
        memcpy(task.data.data, data + offset, task.data.info.len);

        send_n -= task.data.info.len;
        offset += task.data.info.len;

        swTrace("dispatch, type=%d|len=%d\n", task.data.info.type, task.data.info.len);

        if (factory->dispatch(factory, &task) < 0)
        {
            break;
        }
    }

    /**
     * unlock
     */
    SwooleTG.factory_target_worker = -1;
    SwooleTG.factory_lock_target = 0;

#endif
    return SW_OK;
}

```

### `swReactorThread_alloc` 申请共享内存

- 共享内存是从 `buffer_input` 中获取而来，但是如果客户端发送的数据太快太多，`worker` 进程来不及消费，那么共享内存就会不足
- 当共享内存不足的时候，就需要调用 `swReactorThread_yield` 方法，暂停向 `worker` 发送数据，转而让 `reactor` 线程去处理 `worker` 进程发送过来的消息。
- 如果 `reactor` 线程处理完消息，`worker` 进程还没有释放共享内存，并且次数达到 `SW_RINGBUFFER_WARNING `,那么就需要 `sleep`
- `pipe_read_list` 是绑定到本 `reactor` 线程的 `pipe_master` 列表，与 `reactor` 线程绑定的 `worker` 处理消息之后，会向这个 `pipe_master` 发送消息

```
static sw_inline void* swReactorThread_alloc(swReactorThread *thread, uint32_t size)
{
    void *ptr = NULL;
    int try_count = 0;

    while (1)
    {
        ptr = thread->buffer_input->alloc(thread->buffer_input, size);
        if (ptr == NULL)
        {
            if (try_count > SW_RINGBUFFER_WARNING)
            {
                swWarn("memory pool is full. Wait memory collect. alloc(%d)", size);
                usleep(1000);
                try_count = 0;
            }
            try_count++;
            swReactorThread_yield(thread);
            continue;
        }
        break;
    }
    //debug("%p\n", ptr);
    return ptr;
}

static sw_inline void swReactorThread_yield(swReactorThread *thread)
{
    swEvent event;
    swServer *serv = SwooleG.serv;
    int i;
    for (i = 0; i < serv->reactor_pipe_num; i++)
    {
        event.fd = thread->pipe_read_list[i];
        swReactorThread_onPipeReceive(&thread->reactor, &event);
    }
    swYield();
}

```

### `swFactoryProcess_dispatch` 函数

- `swFactoryProcess_dispatch` 函数就是上面说的 `factory->dispatch` 函数，用于调度 `worker` 进程
- 本函数主要调用 `swServer_worker_schedule` 函数来进行调度，决定应该向哪个 `worker` 进程发送数据。
- `swReactorThread_send2worker` 函数用于发送数据

```
static sw_inline int swEventData_is_stream(uint8_t type)
{
    switch (type)
    {
    case SW_EVENT_TCP:
    case SW_EVENT_TCP6:
    case SW_EVENT_UNIX_STREAM:
    case SW_EVENT_PACKAGE_START:
    case SW_EVENT_PACKAGE:
    case SW_EVENT_PACKAGE_END:
    case SW_EVENT_CONNECT:
    case SW_EVENT_CLOSE:
    case SW_EVENT_PAUSE_RECV:
    case SW_EVENT_RESUME_RECV:
    case SW_EVENT_BUFFER_FULL:
    case SW_EVENT_BUFFER_EMPTY:
        return SW_TRUE;
    default:
        return SW_FALSE;
    }
}

static int swFactoryProcess_dispatch(swFactory *factory, swDispatchData *task)
{
    uint32_t send_len = sizeof(task->data.info) + task->data.info.len;
    int target_worker_id;
    swServer *serv = SwooleG.serv;
    int fd = task->data.info.fd;

    if (task->target_worker_id < 0)
    {
#ifndef SW_USE_RINGBUFFER
        if (SwooleTG.factory_lock_target)
        {
            if (SwooleTG.factory_target_worker < 0)
            {
                target_worker_id = swServer_worker_schedule(serv, fd, &task->data);
                SwooleTG.factory_target_worker = target_worker_id;
            }
            else
            {
                target_worker_id = SwooleTG.factory_target_worker;
            }
        }
        else
#endif
        {
            target_worker_id = swServer_worker_schedule(serv, fd, &task->data);
        }
    }
    else
    {
        target_worker_id = task->target_worker_id;
    }
    //discard the data packet.
    if (target_worker_id < 0)
    {
        return SW_OK;
    }

    if (swEventData_is_stream(task->data.info.type))
    {
        swConnection *conn = swServer_connection_get(serv, fd);
        if (conn == NULL || conn->active == 0)
        {
            swWarn("dispatch[type=%d] failed, connection#%d is not active.", task->data.info.type, fd);
            return SW_ERR;
        }
        //server active close, discard data.
        if (conn->closed)
        {
            //Connection has been clsoed by server
            if (!(task->data.info.type == SW_EVENT_CLOSE && conn->close_force))
            {
                return SW_OK;
            }
        }
        //converted fd to session_id
        task->data.info.fd = conn->session_id;
        task->data.info.from_fd = conn->from_fd;
    }

    return swReactorThread_send2worker((void *) &(task->data), send_len, target_worker_id);
}


```

### `swServer_worker_schedule` 调度函数

- 本函数根据 `dispatch_mode` 的不同，计算 `key` 值
- 值得注意的时候 `抢占模式`，其方法就是遍历 `worker`，获取 `worker` 进程的当前状态，找到 `SW_WORKER_IDLE` 空闲的 `worker` 进程。如果所有 `worker` 进程都是繁忙的，那么就退化为了 `SW_DISPATCH_ROUND`，不管下一个轮循的 `worker` 进程会不会第一个处理完毕，这也是 `Stream` 模式相对于其他模式的优点。

```
static sw_inline int swServer_worker_schedule(swServer *serv, int fd, swEventData *data)
{
    uint32_t key;

    //polling mode
    if (serv->dispatch_mode == SW_DISPATCH_ROUND)
    {
        key = sw_atomic_fetch_add(&serv->worker_round_id, 1);
    }
    //Using the FD touch access to hash
    else if (serv->dispatch_mode == SW_DISPATCH_FDMOD)
    {
        key = fd;
    }
    //Using the IP touch access to hash
    else if (serv->dispatch_mode == SW_DISPATCH_IPMOD)
    {
        swConnection *conn = swServer_connection_get(serv, fd);
        //UDP
        if (conn == NULL)
        {
            key = fd;
        }
        //IPv4
        else if (conn->socket_type == SW_SOCK_TCP)
        {
            key = conn->info.addr.inet_v4.sin_addr.s_addr;
        }
        //IPv6
        else
        {
#ifdef HAVE_KQUEUE
            key = *(((uint32_t *) &conn->info.addr.inet_v6.sin6_addr) + 3);
#else
            key = conn->info.addr.inet_v6.sin6_addr.s6_addr32[3];
#endif
        }
    }
    else if (serv->dispatch_mode == SW_DISPATCH_UIDMOD)
    {
        swConnection *conn = swServer_connection_get(serv, fd);
        if (conn == NULL || conn->uid == 0)
        {
            key = fd;
        }
        else
        {
            key = conn->uid;
        }
    }
    //schedule by dispatch function
    else if (serv->dispatch_mode == SW_DISPATCH_USERFUNC)
    {
        return serv->dispatch_func(serv, swServer_connection_get(serv, fd), data);
    }
    //Preemptive distribution
    else
    {
        int i;
        int found = 0;
        for (i = 0; i < serv->worker_num + 1; i++)
        {
            key = sw_atomic_fetch_add(&serv->worker_round_id, 1) % serv->worker_num;
            if (serv->workers[key].status == SW_WORKER_IDLE)
            {
                found = 1;
                break;
            }
        }
        if (unlikely(found == 0))
        {
            serv->scheduler_warning = 1;
        }
        swTraceLog(SW_TRACE_SERVER, "schedule=%d, round=%d", key, serv->worker_round_id);
        return key;
    }
    return key % serv->worker_num;
}

```

### `swReactorThread_send2worker` 函数

- `swReactorThread_send2worker` 函数尝试利用非阻塞方式使用系统调用 `write`，
- 如果失败，就根据 `target_worker_id` 获取相对应的 `reactor_id`, 将数据放入 `in_buffer` 当中，设置 `pipe_fd` 的读写就绪监控(`swReactorThread_loop` 函数中仅仅 `add`，并没有对读写就绪事件进行监控)，等待着 `pipe_master` 写就绪。

```
int swReactorThread_send2worker(void *data, int len, uint16_t target_worker_id)
{
    swServer *serv = SwooleG.serv;

    assert(target_worker_id < serv->worker_num);

    int ret = -1;
    swWorker *worker = &(serv->workers[target_worker_id]);

    //reactor thread
    if (SwooleTG.type == SW_THREAD_REACTOR)
    {
        int pipe_fd = worker->pipe_master;
        int thread_id = serv->connection_list[pipe_fd].from_id;
        swReactorThread *thread = swServer_get_thread(serv, thread_id);
        swLock *lock = serv->connection_list[pipe_fd].object;

        //lock thread
        lock->lock(lock);

        swBuffer *buffer = serv->connection_list[pipe_fd].in_buffer;
        if (swBuffer_empty(buffer))
        {
            ret = write(pipe_fd, (void *) data, len);
#ifdef HAVE_KQUEUE
            if (ret < 0 && (errno == EAGAIN || errno == ENOBUFS))
#else
            if (ret < 0 && errno == EAGAIN)
#endif
            {
                if (thread->reactor.set(&thread->reactor, pipe_fd, SW_FD_PIPE | SW_EVENT_READ | SW_EVENT_WRITE) < 0)
                {
                    swSysError("reactor->set(%d, PIPE | READ | WRITE) failed.", pipe_fd);
                }
                goto append_pipe_buffer;
            }
        }
        else
        {
            append_pipe_buffer:
            if (swBuffer_append(buffer, data, len) < 0)
            {
                swWarn("append to pipe_buffer failed.");
                ret = SW_ERR;
            }
            else
            {
                ret = SW_OK;
            }
        }
        //release thread lock
        lock->unlock(lock);
    }
    //master/udp thread
    else
    {
        int pipe_fd = worker->pipe_master;
        ret = swSocket_write_blocking(pipe_fd, data, len);
    }
    return ret;
}

```

