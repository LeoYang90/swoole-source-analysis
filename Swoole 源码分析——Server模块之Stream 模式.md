# Swoole 源码分析——Server模块之Stream 模式

## `swReactorThread_dispatch` 发送数据

`reactor` 线程会通过 `swReactorThread_dispatch` 发送数据，当采用 `stream` 发送数据的时候，会调用 `swStream_new` 新建 `stream`，利用 `swStream_send` 发送数据。

```
int swReactorThread_dispatch(swConnection *conn, char *data, uint32_t length)
{
    ...
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
    ...
}

```

### `swStream_new` 新建 `stream`

- 可以看到，`stream` 自动采用包长检测的方法
- 该函数主要功能是设置各种回调函数
- 值得注意的是 `swClient_create` 第三个参数代表是否异步。在这里设置的是 1，也就是说，无论 `connect` 还是 `send` 都是异步。

```
typedef struct _swStream
{
    swString *buffer;
    uint32_t session_id;
    uint8_t cancel;
    void (*response)(struct _swStream *stream, char *data, uint32_t length);
    swClient client;
} swStream;

swStream* swStream_new(char *dst_host, int dst_port, int type)
{
    swStream *stream = (swStream*) sw_malloc(sizeof(swStream));
    bzero(stream, sizeof(swStream));

    swClient *cli = &stream->client;
    if (swClient_create(cli, type, 1) < 0)
    {
        swStream_free(stream);
        return NULL;
    }

    cli->onConnect = swStream_onConnect;
    cli->onReceive = swStream_onReceive;
    cli->onError = swStream_onError;
    cli->onClose = swStream_onClose;
    cli->object = stream;

    cli->open_length_check = 1;
    swStream_set_protocol(&cli->protocol);

    if (cli->connect(cli, dst_host, dst_port, -1, 0) < 0)
    {
        swSysError("failed to connect to [%s:%d].", dst_host, dst_port);
        swStream_free(stream);
        return NULL;
    }
    else
    {
        return stream;
    }
}

void swStream_set_protocol(swProtocol *protocol)
{
    protocol->get_package_length = swProtocol_get_package_length;
    protocol->package_length_size = 4;
    protocol->package_length_type = 'N';
    protocol->package_body_offset = 4;
    protocol->package_length_offset = 0;
}

```

## `swStream_onConnect` 连接回调函数

- `swStream_onConnect` 不仅是连接成功的回调函数，还是每次 `onWrite` 写事件的回调函数，因此每次都需要调用 `cli->send` 函数，发送存储在 `stream->buffer` 数据。值得注意的是，每次发送数据，都要将数据长度存放在 `buffer` 的头部，否则包长检测会失败。

```
static void swStream_onConnect(swClient *cli)
{
    swStream *stream = (swStream*) cli->object;
    if (stream->cancel)
    {
        cli->close(cli);
    }
    *((uint32_t *) stream->buffer->str) = ntohl(stream->buffer->length - 4);
    if (cli->send(cli, stream->buffer->str, stream->buffer->length, 0) < 0)
    {
        cli->close(cli);
    }
    else
    {
        swString_free(stream->buffer);
        stream->buffer = NULL;
    }
}

```

## `swStream_send` 发送数据

`swStream_send` 函数并不是直接发送数据，而是将数据存储在 `stream->buffer`，等着写事件就绪之后调用 `swStream_onConnect` 发送数据。值得注意的是，每次新建 `buffer` 的时候，要预留 4 个字节来存储 `buffer` 的数据长度

```
int swStream_send(swStream *stream, char *data, size_t length)
{
    if (stream->buffer == NULL)
    {
        stream->buffer = swString_new(swoole_size_align(length + 4, SwooleG.pagesize));
        if (stream->buffer == NULL)
        {
            return SW_ERR;
        }
        stream->buffer->length = 4;
    }
    if (swString_append_ptr(stream->buffer, data, length) < 0)
    {
        return SW_ERR;
    }
    return SW_OK;
}

```

## `swStream_onReceive` 函数

`swStream_onReceive` 函数是 `stream` 读事件就绪的回调函数，`worker` 进程发送给客户端的数据将会发送到本函数。如果 `length` 为 4，说明 `worker` 只发送了一个 `length` 的空数据包，代表着 `worker` 进程已消费完毕，这时我们可以关闭 `stream`。

```
static void swStream_onReceive(swClient *cli, char *data, uint32_t length)
{
    swStream *stream = (swStream*) cli->object;
    if (length == 4)
    {
        cli->socket->close_wait = 1;
    }
    else
    {
        stream->response(stream, data + 4, length - 4);
    }
}

static void swReactorThread_onStreamResponse(swStream *stream, char *data, uint32_t length)
{
    swSendData response;
    swConnection *conn = swServer_connection_verify(SwooleG.serv, stream->session_id);
    if (!conn)
    {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_NOT_EXIST, "connection[fd=%d] does not exists.", stream->session_id);
        return;
    }
    response.info.fd = conn->session_id;
    response.info.type = SW_EVENT_TCP;
    response.info.len = 0;
    response.length = length;
    response.data = data;
    swReactorThread_send(&response);
}

```

## `swWorker_onStreamAccept` 接受连接请求

接受请求和主进程的 `reactor` 接受连接大致一致，略有不同的是 `conn->socket_type` 设置为了 `SW_SOCK_UNIX_STREAM`

```
static int swWorker_onStreamAccept(swReactor *reactor, swEvent *event)
{
    int fd = 0;
    swSocketAddress client_addr;
    socklen_t client_addrlen = sizeof(client_addr);

#ifdef HAVE_ACCEPT4
    fd = accept4(event->fd, (struct sockaddr *) &client_addr, &client_addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
    fd = accept(event->fd, (struct sockaddr *) &client_addr, &client_addrlen);
#endif
    if (fd < 0)
    {
        switch (errno)
        {
        case EINTR:
        case EAGAIN:
            return SW_OK;
        default:
            swoole_error_log(SW_LOG_ERROR, SW_ERROR_SYSTEM_CALL_FAIL, "accept() failed. Error: %s[%d]", strerror(errno),
                    errno);
            return SW_OK;
        }
    }
#ifndef HAVE_ACCEPT4
    else
    {
        swoole_fcntl_set_option(fd, 1, 1);
    }
#endif

    swConnection *conn = swReactor_get(reactor, fd);
    bzero(conn, sizeof(swConnection));
    conn->fd = fd;
    conn->active = 1;
    conn->socket_type = SW_SOCK_UNIX_STREAM;
    memcpy(&conn->info.addr, &client_addr, sizeof(client_addr));

    if (reactor->add(reactor, fd, SW_FD_STREAM | SW_EVENT_READ) < 0)
    {
        return SW_ERR;
    }

    return SW_OK;
}


```

## `swWorker_onStreamRead` 读取数据

`swWorker_onStreamRead` 读取数据核心是调用 `swProtocol_recv_check_length` 函数收取数据放入 `serv->buffer_pool` 单链表中，`swProtocol_recv_check_length` 函数我们在 `reactor` 线程的事件循环中已经了解了，我们这里不再重复，我们知道，该函数获取数据之后，会调用 `onPackage` 函数，也就是 `swWorker_onStreamPackage` 函数

```
void swStream_set_protocol(swProtocol *protocol)
{
    protocol->get_package_length = swProtocol_get_package_length;
    protocol->package_length_size = 4;
    protocol->package_length_type = 'N';
    protocol->package_body_offset = 4;
    protocol->package_length_offset = 0;
}


static int swWorker_onStreamRead(swReactor *reactor, swEvent *event)
{
    swConnection *conn = event->socket;
    swServer *serv = SwooleG.serv;
    swProtocol *protocol = &serv->stream_protocol;
    swString *buffer;

    if (!event->socket->recv_buffer)
    {
        buffer = swLinkedList_shift(serv->buffer_pool);
        if (buffer == NULL)
        {
            buffer = swString_new(8192);
            if (!buffer)
            {
                return SW_ERR;
            }

        }
        event->socket->recv_buffer = buffer;
    }
    else
    {
        buffer = event->socket->recv_buffer;
    }

    if (swProtocol_recv_check_length(protocol, conn, buffer) < 0)
    {
        swWorker_onStreamClose(reactor, event);
    }

    return SW_OK;
}

```

### `swWorker_onStreamPackage` 函数

`swWorker_onStreamPackage` 函数用于将数据包投送到 `swWorker_onTask` 函数进行消费。消费完毕会发送一个只含长度 0 的数据包，告知 `reactor` `worker` 已经结束。

```
static int swWorker_onStreamPackage(swConnection *conn, char *data, uint32_t length)
{
    swServer *serv = SwooleG.serv;
    swEventData *task = (swEventData *) (data + 4);

    serv->last_stream_fd = conn->fd;

    swString *package = swWorker_get_buffer(serv, task->info.from_id);
    uint32_t data_length = length - sizeof(task->info) - 4;
    //merge data to package buffer
    swString_append_ptr(package, data + sizeof(task->info) + 4, data_length);

    swWorker_onTask(&serv->factory, task);

    int _end = htonl(0);
    SwooleG.main_reactor->write(SwooleG.main_reactor, conn->fd, (void *) &_end, sizeof(_end));

    return SW_OK;
}

```
