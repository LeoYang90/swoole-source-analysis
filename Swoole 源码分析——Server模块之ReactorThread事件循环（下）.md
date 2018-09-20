# Swoole 源码分析——Server模块之ReactorThread事件循环（下）

## `swPort_onRead_check_eof` EOF 自动分包

- 我们前面说过，`swPort_onRead_raw` 是最简单的向 `worker` 进程发送数据包的方法，`swoole` 会将从客户端接受到的数据包，立刻发送给 `worker` 进程,用户自己把数据包拼接起来
- 如果启用了 `EOF` 自动分包，那么 `swoole` 会检测 `EOF` 符号，拼接完毕数据之后再向 `worker` 发送数据
- `swProtocol_recv_check_eof` 用于检测 `EOF` 符号，如果没有检测到数据就存储到 `buffer`。

```c
static int swPort_onRead_check_eof(swReactor *reactor, swListenPort *port, swEvent *event)
{
    swConnection *conn = event->socket;
    swProtocol *protocol = &port->protocol;
    swServer *serv = reactor->ptr;

    swString *buffer = swServer_get_buffer(serv, event->fd);
    if (!buffer)
    {
        return SW_ERR;
    }

    if (swProtocol_recv_check_eof(protocol, conn, buffer) < 0)
    {
        swReactorThread_onClose(reactor, event);
    }

    return SW_OK;
}

static sw_inline swString *swServer_get_buffer(swServer *serv, int fd)
{
    swString *buffer = serv->connection_list[fd].recv_buffer;
    if (buffer == NULL)
    {
        buffer = swString_new(SW_BUFFER_SIZE_STD);
        //alloc memory failed.
        if (!buffer)
        {
            return NULL;
        }
        serv->connection_list[fd].recv_buffer = buffer;
    }
    return buffer;
}

```

### `swProtocol_recv_check_eof` 检测 EOF

- 首先需要调用 `swConnection_recv` 函数接受客户端发来的数据，如果发生错误返回 `SW_OK`，等待 `socket` 读就绪重新读取；如果错误是 `SW_CLOSE`，那么就要返回 `SW_ERR`，然后让 `swPort_onRead_check_eof` 函数调用 `swReactorThread_onClose` 函数。
- `EOF` 自动分包也有两种方式，分别是 `open_eof_check` 和 `open_eof_split`，`open_eof_check` 只检查接收数据的末尾是否为 `EOF`，因此它的性能最好，几乎没有消耗，但是无法解决多个数据包合并的问题，比如同时发送两条带有 `EOF` 的数据，底层可能会一次全部返回;`open_eof_split` 会从左到右对数据进行逐字节对比，查找数据中的 `EOF` 进行分包，性能较差。但是每次只会返回一个数据包
- 如果采用 `open_eof_check`，那么只需要简单的 `memcmp` 对比数据包的最后字符即可，如果符合条件就会调用 `protocol->onPackage` 函数，也就是 `swReactorThread_dispatch`
- 如果采用的是 `open_eof_split` 就会比较麻烦，需要调用 `swProtocol_split_package_by_eof` 逐个去找 `EOF`
- 如果超过了 `protocol->package_max_length` 大小，那么说明一直没有发送成功，就会返回错误，结束当前连接
- 如果缓冲区不足，那么就将缓冲区扩容到 `protocol->package_max_length`，继续接受数据

```c
int swProtocol_recv_check_eof(swProtocol *protocol, swConnection *conn, swString *buffer)
{
    int recv_again = SW_FALSE;
    int buf_size;

    recv_data: buf_size = buffer->size - buffer->length;
    char *buf_ptr = buffer->str + buffer->length;

    if (buf_size > SW_BUFFER_SIZE_STD)
    {
        buf_size = SW_BUFFER_SIZE_STD;
    }

    int n = swConnection_recv(conn, buf_ptr, buf_size, 0);
    if (n < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swSysError("recv from socket#%d failed.", conn->fd);
            return SW_OK;
        case SW_CLOSE:
            conn->close_errno = errno;
            return SW_ERR;
        default:
            return SW_OK;
        }
    }
    else if (n == 0)
    {
        return SW_ERR;
    }
    else
    {
        buffer->length += n;

        if (buffer->length < protocol->package_eof_len)
        {
            return SW_OK;
        }

        if (protocol->split_by_eof)
        {
            if (swProtocol_split_package_by_eof(protocol, conn, buffer) == 0)
            {
                return SW_OK;
            }
            else
            {
                recv_again = SW_TRUE;
            }
        }
        else if (memcmp(buffer->str + buffer->length - protocol->package_eof_len, protocol->package_eof, protocol->package_eof_len) == 0)
        {
            if (protocol->onPackage(conn, buffer->str, buffer->length) < 0)
            {
                return SW_ERR;
            }
            if (conn->removed)
            {
                return SW_OK;
            }
            swString_clear(buffer);
            return SW_OK;
        }

        //over max length, will discard
        if (buffer->length == protocol->package_max_length)
        {
            swWarn("Package is too big. package_length=%d", (int )buffer->length);
            return SW_ERR;
        }

        //buffer is full, may have not read data
        if (buffer->length == buffer->size)
        {
            recv_again = SW_TRUE;
            if (buffer->size < protocol->package_max_length)
            {
                uint32_t extend_size = swoole_size_align(buffer->size * 2, SwooleG.pagesize);
                if (extend_size > protocol->package_max_length)
                {
                    extend_size = protocol->package_max_length;
                }
                if (swString_extend(buffer, extend_size) < 0)
                {
                    return SW_ERR;
                }
            }
        }
        //no eof
        if (recv_again)
        {
            goto recv_data;
        }
    }
    return SW_OK;
}

```

### `swProtocol_split_package_by_eof` 寻找 `EOF`

- 如果当前缓存中数据连 `package_eof_len` 也就是 `EOF` 的长度都不够，那么就直接返回，继续接受数据
- 根据 `package_eof` 来查找第一个 `EOF` 的位置，如果没有找到 `EOF`，那么递增 `buffer->offset`，返回继续接受数据 
- 找到了 `EOF` 之后，就要调用 `protocol->onPackage` 函数，发送给 `worker` 进程
- 接着就要从剩余的数据里面循环不断寻找 `EOF`，调用 `protocol->onPackage` 函数

```c
static sw_inline int swProtocol_split_package_by_eof(swProtocol *protocol, swConnection *conn, swString *buffer)
{
#if SW_LOG_TRACE_OPEN > 0
    static int count;
    count++;
#endif

    int eof_pos;
    if (buffer->length - buffer->offset < protocol->package_eof_len)
    {
        eof_pos = -1;
    }
    else
    {
        eof_pos = swoole_strnpos(buffer->str + buffer->offset, buffer->length - buffer->offset, protocol->package_eof, protocol->package_eof_len);
    }

    swTraceLog(SW_TRACE_EOF_PROTOCOL, "#[0] count=%d, length=%ld, size=%ld, offset=%ld.", count, buffer->length, buffer->size, (long)buffer->offset);

    //waiting for more data
    if (eof_pos < 0)
    {
        buffer->offset = buffer->length - protocol->package_eof_len;
        return buffer->length;
    }

    uint32_t length = buffer->offset + eof_pos + protocol->package_eof_len;
    swTraceLog(SW_TRACE_EOF_PROTOCOL, "#[4] count=%d, length=%d", count, length);
    if (protocol->onPackage(conn, buffer->str, length) < 0)
    {
        return SW_ERR;
    }
    if (conn->removed)
    {
        return SW_OK;
    }

    //there are remaining data
    if (length < buffer->length)
    {
        uint32_t remaining_length = buffer->length - length;
        char *remaining_data = buffer->str + length;
        swTraceLog(SW_TRACE_EOF_PROTOCOL, "#[5] count=%d, remaining_length=%d", count, remaining_length);

        while (1)
        {
            if (remaining_length < protocol->package_eof_len)
            {
                goto wait_more_data;
            }
            eof_pos = swoole_strnpos(remaining_data, remaining_length, protocol->package_eof, protocol->package_eof_len);
            if (eof_pos < 0)
            {
                wait_more_data:
                swTraceLog(SW_TRACE_EOF_PROTOCOL, "#[1] count=%d, remaining_length=%d, length=%d", count, remaining_length, length);
                memmove(buffer->str, remaining_data, remaining_length);
                buffer->length = remaining_length;
                buffer->offset = 0;
                return SW_OK;
            }
            else
            {
                length = eof_pos + protocol->package_eof_len;
                if (protocol->onPackage(conn, remaining_data, length) < 0)
                {
                    return SW_ERR;
                }
                if (conn->removed)
                {
                    return SW_OK;
                }
                swTraceLog(SW_TRACE_EOF_PROTOCOL, "#[2] count=%d, remaining_length=%d, length=%d", count, remaining_length, length);
                remaining_data += length;
                remaining_length -= length;
            }
        }
    }
    swTraceLog(SW_TRACE_EOF_PROTOCOL, "#[3] length=%ld, size=%ld, offset=%ld", buffer->length, buffer->size, (long)buffer->offset);
    swString_clear(buffer);
    return SW_OK;
}

```

## `swPort_onRead_check_length` 包长检测

- 类似地本函数也是调用 `swProtocol_recv_check_length` 来进行包长检测

```c
static int swPort_onRead_check_length(swReactor *reactor, swListenPort *port, swEvent *event)
{
    swServer *serv = reactor->ptr;
    swConnection *conn = event->socket;
    swProtocol *protocol = &port->protocol;

    swString *buffer = swServer_get_buffer(serv, event->fd);
    if (!buffer)
    {
        return SW_ERR;
    }

    if (swProtocol_recv_check_length(protocol, conn, buffer) < 0)
    {
        swTrace("Close Event.FD=%d|From=%d", event->fd, event->from_id);
        swReactorThread_onClose(reactor, event);
    }

    return SW_OK;
}

```

### `swProtocol_recv_check_length` 函数

- 进行包长检测的时候，每次读取数据之前都要先读取 `header`，从 `header` 中获取到数据包的大小后，再去读取真正的数据
- 当我们不知道包长大小的时候，`buffer->offset` 为 0，此时需要读取 `length` 大小，但是这个数据位于 `header` 的 `protocol->package_length_offset` 位置，假设 `length` 位于 `header` 的第 8 个字节；`length` 自身数据大小为 `protocol->package_length_size`，例如 `int_32` 类型，这个值就是 4，因此我们需要先读取 12 个字节，这 12 个字节的最后 4 个字节就是 `length` 的值，也就是包长。
- 将数据拿到后(此时 `recv_wait` 为 0)，调用 `protocol->get_package_length` 就可以获取 `length` 的值，根据 `buffer->offset` 的值为包长值，
	- 如果此时 `buffer->length` 已接收的数据大于这个包长，那么就调用 `onPackage` 发送给 `worker` 进程
	- 如果此时已接收的数据不足，那么 `recv_size` 就是剩余需要接受的数据大小，此时 `recv_wait` 为 1，继续接受数据
		- 如果接受到的数据已经大于包长，那么就调用 `onPackage` 发送。之后如果仍然有剩余未发送的数据，那么就 `do_get_length`；如果已经没有剩余数据了，继续去取下一个数据包。
		- 如果数据还是不够，那么就返回，等待读就绪事件

```c
int swProtocol_recv_check_length(swProtocol *protocol, swConnection *conn, swString *buffer)
{
    int package_length;
    uint32_t recv_size;
    char swap[SW_BUFFER_SIZE_STD];

    if (conn->skip_recv)
    {
        conn->skip_recv = 0;
        goto do_get_length;
    }

    do_recv:
	if (conn->active == 0)
	{
		return SW_OK;
	}
    if (buffer->offset > 0)
    {
        recv_size = buffer->offset - buffer->length;
    }
    else
    {
        recv_size = protocol->package_length_offset + protocol->package_length_size;
    }

    int n = swConnection_recv(conn, buffer->str + buffer->length, recv_size, 0);
    if (n < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swSysError("recv(%d, %d) failed.", conn->fd, recv_size);
            return SW_OK;
        case SW_CLOSE:
            conn->close_errno = errno;
            return SW_ERR;
        default:
            return SW_OK;
        }
    }
    else if (n == 0)
    {
        return SW_ERR;
    }
    else
    {
        buffer->length += n;

        if (conn->recv_wait)
        {
            if (buffer->length >= buffer->offset)
            {
                do_dispatch:
                if (protocol->onPackage(conn, buffer->str, buffer->offset) < 0)
                {
                    return SW_ERR;
                }
                if (conn->removed)
                {
                    return SW_OK;
                }
                conn->recv_wait = 0;

                int remaining_length = buffer->length - buffer->offset;
                if (remaining_length > 0)
                {
                    assert(remaining_length < sizeof(swap));
                    memcpy(swap, buffer->str + buffer->offset, remaining_length);
                    memcpy(buffer->str, swap, remaining_length);
                    buffer->offset = 0;
                    buffer->length = remaining_length;
                    goto do_get_length;
                }
                else
                {
                    swString_clear(buffer);
                    goto do_recv;
                }
            }
            else
            {
                return SW_OK;
            }
        }
        else
        {
            do_get_length: package_length = protocol->get_package_length(protocol, conn, buffer->str, buffer->length);
            //invalid package, close connection.
            if (package_length < 0)
            {
                return SW_ERR;
            }
            //no length
            else if (package_length == 0)
            {
                return SW_OK;
            }
            else if (package_length > protocol->package_max_length)
            {
                swWarn("package is too big, remote_addr=%s:%d, length=%d.", swConnection_get_ip(conn), swConnection_get_port(conn), package_length);
                return SW_ERR;
            }
            //get length success
            else
            {
                if (buffer->size < package_length)
                {
                    if (swString_extend(buffer, package_length) < 0)
                    {
                        return SW_ERR;
                    }
                }
                conn->recv_wait = 1;
                buffer->offset = package_length;

                if (buffer->length >= package_length)
                {
                    goto do_dispatch;
                }
                else
                {
                    goto do_recv;
                }
            }
        }
    }
    return SW_OK;
}

```

### `swProtocol_get_package_length` 获取包长

本函数逻辑很简单，如果长度连 `length` 都不够，那么包长信息并不在 `data` 中，直接返回继续接受数据。拿到 `length` 后，要用 `swoole_unpack` 函数转化为相应的类型即可得到包长值。

```c
int swProtocol_get_package_length(swProtocol *protocol, swConnection *conn, char *data, uint32_t size)
{
    uint16_t length_offset = protocol->package_length_offset;
    int32_t body_length;
    /**
     * no have length field, wait more data
     */
    if (size < length_offset + protocol->package_length_size)
    {
        return 0;
    }
    body_length = swoole_unpack(protocol->package_length_type, data + length_offset);
    //Length error
    //Protocol length is not legitimate, out of bounds or exceed the allocated length
    if (body_length < 0)
    {
        swWarn("invalid package, remote_addr=%s:%d, length=%d, size=%d.", swConnection_get_ip(conn), swConnection_get_port(conn), body_length, size);
        return SW_ERR;
    }
    //total package length
    return protocol->package_body_offset + body_length;
}

static sw_inline int32_t swoole_unpack(char type, void *data)
{
    switch(type)
    {
    /*-------------------------16bit-----------------------------*/
    case 'c':
        return *((int8_t *) data);
    case 'C':
        return *((uint8_t *) data);
    /*-------------------------16bit-----------------------------*/
    /**
     * signed short (always 16 bit, machine byte order)
     */
    case 's':
        return *((int16_t *) data);
    /**
     * unsigned short (always 16 bit, machine byte order)
     */
    case 'S':
        return *((uint16_t *) data);
    /**
     * unsigned short (always 16 bit, big endian byte order)
     */
    case 'n':
        return ntohs(*((uint16_t *) data));
    /**
     * unsigned short (always 32 bit, little endian byte order)
     */
    case 'v':
        return swoole_swap_endian16(ntohs(*((uint16_t *) data)));

    /*-------------------------32bit-----------------------------*/
    /**
     * unsigned long (always 32 bit, machine byte order)
     */
    case 'L':
        return *((uint32_t *) data);
    /**
     * signed long (always 32 bit, machine byte order)
     */
    case 'l':
        return *((int *) data);
    /**
     * unsigned long (always 32 bit, big endian byte order)
     */
    case 'N':
        return ntohl(*((uint32_t *) data));
    /**
     * unsigned short (always 32 bit, little endian byte order)
     */
    case 'V':
        return swoole_swap_endian32(ntohl(*((uint32_t *) data)));

    default:
        return *((uint32_t *) data);
    }
}

```

## `swReactorThread_onPipeWrite` 写事件回调

- 当 `reactor` 线程检测到相对应的 `worker` 进程的 `pipe_master` 写就绪的时候，就会调用 `swReactorThread_onPipeWrite`
- 当 `in_buffer` 不是空的话，就会循环拿出单链表的数据，调用 `swServer_connection_verify` 验证 `session_id` 是否正确，然后调用 `write` 发送数据
- 当返回的错误是 `EAGAIN` 的时候，说明 `socket` 已经不可用，返回等待下一次写就绪即可
- 值得注意的是 `write` 的返回结果不需要关心到底写入了多少，因为对于 `linux` 来说，`pipe` 可以保证 `write`  小于 `PIPE_BUF` 大小数据的原子性，不是全部写入成功，就是写入失败，不会出现写入部分数据的可能。
- 当所有的数据都发送成功后，取消写就绪监控，防止重复浪费调用

```c
static int swReactorThread_onPipeWrite(swReactor *reactor, swEvent *ev)
{
    int ret;

    swBuffer_trunk *trunk = NULL;
    swEventData *send_data;
    swConnection *conn;
    swServer *serv = reactor->ptr;
    swBuffer *buffer = serv->connection_list[ev->fd].in_buffer;
    swLock *lock = serv->connection_list[ev->fd].object;

    //lock thread
    lock->lock(lock);

    while (!swBuffer_empty(buffer))
    {
        trunk = swBuffer_get_trunk(buffer);
        send_data = trunk->store.ptr;

        //server active close, discard data.
        if (swEventData_is_stream(send_data->info.type))
        {
            //send_data->info.fd is session_id
            conn = swServer_connection_verify(serv, send_data->info.fd);
            if (conn == NULL || conn->closed)
            {
#ifdef SW_USE_RINGBUFFER
                swReactorThread *thread = swServer_get_thread(SwooleG.serv, SwooleTG.id);
                swPackage package;
                memcpy(&package, send_data->data, sizeof(package));
                thread->buffer_input->free(thread->buffer_input, package.data);
#endif
                if (conn && conn->closed)
                {
                    swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_CLOSED_BY_SERVER, "Session#%d is closed by server.", send_data->info.fd);
                }
                swBuffer_pop_trunk(buffer, trunk);
                continue;
            }
        }

        ret = write(ev->fd, trunk->store.ptr, trunk->length);
        if (ret < 0)
        {
            //release lock
            lock->unlock(lock);
#ifdef HAVE_KQUEUE
            return (errno == EAGAIN || errno == ENOBUFS) ? SW_OK : SW_ERR;
#else
            return errno == EAGAIN ? SW_OK : SW_ERR;
#endif
        }
        else
        {
            swBuffer_pop_trunk(buffer, trunk);
        }
    }

    //remove EPOLLOUT event
    if (swBuffer_empty(buffer))
    {
        if (SwooleG.serv->connection_list[ev->fd].from_id == SwooleTG.id)
        {
            ret = reactor->set(reactor, ev->fd, SW_FD_PIPE | SW_EVENT_READ);
        }
        else
        {
            ret = reactor->del(reactor, ev->fd);
        }
        if (ret < 0)
        {
            swSysError("reactor->set(%d) failed.", ev->fd);
        }
    }

    //release lock
    lock->unlock(lock);

    return SW_OK;
}

```

## `swReactorThread_onPipeReceive` 读事件就绪

- 从 `worker` 进程返回的数据有三种：`SW_RESPONSE_SMALL`(少量数据)、`SW_RESPONSE_SHM`(大数据包存储在共享内存中)、`SW_RESPONSE_TMPFILE`(临时文件)
- 需要将从 `worker` 接受到的 `swEventData` 对象转化为 `swSendData`
- 对于大数据包，`worker` 并不会将数据通过 `socket` 来传递，而是将 `work_id` 发送过来，数据存放在 `worker->send_shm` 中
- 如果是临时文件，`worker` 发送过来的数据是临时文件的名字，需要调用 `swTaskWorker_large_unpack` 将文件内容读取到 `SwooleTG.buffer_stack` 中去
- `swReactorThread_send` 函数用于向客户端发送数据

```c
typedef struct _swSendData
{
    swDataHead info;
    /**
     * for big package
     */
    uint32_t length;
    char *data;
} swSendData;

typedef struct
{
	int length;
	int worker_id;
} swPackage_response;

static int swReactorThread_onPipeReceive(swReactor *reactor, swEvent *ev)
{
    int n;
    swEventData resp;
    swSendData _send;

    swPackage_response pkg_resp;
    swWorker *worker;

#ifdef SW_REACTOR_RECV_AGAIN
    while (1)
#endif
    {
        n = read(ev->fd, &resp, sizeof(resp));
        if (n > 0)
        {
            memcpy(&_send.info, &resp.info, sizeof(resp.info));
            //pipe data
            if (_send.info.from_fd == SW_RESPONSE_SMALL)
            {
                _send.data = resp.data;
                _send.length = resp.info.len;
                swReactorThread_send(&_send);
            }
            //use send shm
            else if (_send.info.from_fd == SW_RESPONSE_SHM)
            {
                memcpy(&pkg_resp, resp.data, sizeof(pkg_resp));
                worker = swServer_get_worker(SwooleG.serv, pkg_resp.worker_id);

                _send.data = worker->send_shm;
                _send.length = pkg_resp.length;

                swReactorThread_send(&_send);
                worker->lock.unlock(&worker->lock);
            }
            //use tmp file
            else if (_send.info.from_fd == SW_RESPONSE_TMPFILE)
            {
                swString *data = swTaskWorker_large_unpack(&resp);
                if (data == NULL)
                {
                    return SW_ERR;
                }
                _send.data = data->str;
                _send.length = data->length;
                swReactorThread_send(&_send);
            }
            //reactor thread exit
            else if (_send.info.from_fd == SW_RESPONSE_EXIT)
            {
                reactor->running = 0;
                return SW_OK;
            }
            //will never be here
            else
            {
                abort();
            }
        }
        else if (errno == EAGAIN)
        {
            return SW_OK;
        }
        else
        {
            swWarn("read(worker_pipe) failed. Error: %s[%d]", strerror(errno), errno);
            return SW_ERR;
        }
    }

    return SW_OK;
}

static sw_inline swString* swTaskWorker_large_unpack(swEventData *task_result)
{
    swPackage_task _pkg;
    memcpy(&_pkg, task_result->data, sizeof(_pkg));

    int tmp_file_fd = open(_pkg.tmpfile, O_RDONLY);
    if (tmp_file_fd < 0)
    {
        swSysError("open(%s) failed.", _pkg.tmpfile);
        return NULL;
    }
    if (SwooleTG.buffer_stack->size < _pkg.length && swString_extend_align(SwooleTG.buffer_stack, _pkg.length) < 0)
    {
        close(tmp_file_fd);
        return NULL;
    }
    if (swoole_sync_readfile(tmp_file_fd, SwooleTG.buffer_stack->str, _pkg.length) < 0)
    {
        close(tmp_file_fd);
        return NULL;
    }
    close(tmp_file_fd);
    if (!(swTask_type(task_result) & SW_TASK_PEEK))
    {
        unlink(_pkg.tmpfile);
    }
    SwooleTG.buffer_stack->length = _pkg.length;
    return SwooleTG.buffer_stack;
}
```

### `swReactorThread_send` 函数

- 首先要获取连接的 `session_id`，利用 `session_id` 获取 `swConnection` 对象，进而拿到负责该连接的 `reactor` 对象
- `SW_EVENT_CONFIRM` 代表 `worker` 确认接收该连接（当服务端使用 `enable_delay_receive` 选项时）
- 当调用 `swoole_server->pause` 函数时，`BASE` 模式会调用本函数，将不会读取客户端数据，去除 `reactor` 对读就绪事件的监听
- 类似地 `swoole_server->resume` 函数用于恢复当前连接，重新将读就绪放入 `reactor` 的监听事件中
- 如果 `conn->out_buffer` 为空，那么就尝试向 `socket` 写数据，如果没有全部写入成功，那么就将数据放入 `conn->out_buffer` 中去，并开启事件监听
- 如果 `conn->out_buffe` 数据量过大，需要设置 `conn->high_watermark` 为 1，调用 `onBufferFull` 回调

```c
int swReactorThread_send(swSendData *_send)
{
    swServer *serv = SwooleG.serv;
    uint32_t session_id = _send->info.fd;
    void *_send_data = _send->data;
    uint32_t _send_length = _send->length;

    swConnection *conn;
    if (_send->info.type != SW_EVENT_CLOSE)
    {
        conn = swServer_connection_verify(serv, session_id);
    }
    else
    {
        conn = swServer_connection_verify_no_ssl(serv, session_id);
    }

    int fd = conn->fd;
    swReactor *reactor;

    {
        reactor = &(serv->reactor_threads[conn->from_id].reactor);
        assert(fd % serv->reactor_num == reactor->id);
        assert(fd % serv->reactor_num == SwooleTG.id);
    }

    /**
     * Reset send buffer, Immediately close the connection.
     */
    if (_send->info.type == SW_EVENT_CLOSE && (conn->close_reset || conn->removed))
    {
        goto close_fd;
    }
    else if (_send->info.type == SW_EVENT_CONFIRM)
    {
        reactor->add(reactor, conn->fd, conn->fdtype | SW_EVENT_READ);
        conn->listen_wait = 0;
        return SW_OK;
    }
    /**
     * pause recv data
     */
    else if (_send->info.type == SW_EVENT_PAUSE_RECV)
    {
        if (conn->events & SW_EVENT_WRITE)
        {
            return reactor->set(reactor, conn->fd, conn->fdtype | SW_EVENT_WRITE);
        }
        else
        {
            return reactor->del(reactor, conn->fd);
        }
    }
    /**
     * resume recv data
     */
    else if (_send->info.type == SW_EVENT_RESUME_RECV)
    {
        if (conn->events & SW_EVENT_WRITE)
        {
            return reactor->set(reactor, conn->fd, conn->fdtype | SW_EVENT_READ | SW_EVENT_WRITE);
        }
        else
        {
            return reactor->add(reactor, conn->fd, conn->fdtype | SW_EVENT_READ);
        }
    }

    if (swBuffer_empty(conn->out_buffer))
    {
        /**
         * close connection.
         */
        if (_send->info.type == SW_EVENT_CLOSE)
        {
            close_fd:
            reactor->close(reactor, fd);
            return SW_OK;
        }
#ifdef SW_REACTOR_SYNC_SEND
        //Direct send
        if (_send->info.type != SW_EVENT_SENDFILE)
        {
            if (!conn->direct_send)
            {
                goto buffer_send;
            }

            int n;

            direct_send:
            n = swConnection_send(conn, _send_data, _send_length, 0);
            if (n == _send_length)
            {
                return SW_OK;
            }
            else if (n > 0)
            {
                _send_data += n;
                _send_length -= n;
                goto buffer_send;
            }
            else if (errno == EINTR)
            {
                goto direct_send;
            }
            else
            {
                goto buffer_send;
            }
        }
#endif
        //buffer send
        else
        {
#ifdef SW_REACTOR_SYNC_SEND
            buffer_send:
#endif
            if (!conn->out_buffer)
            {
                conn->out_buffer = swBuffer_new(SW_BUFFER_SIZE);
                if (conn->out_buffer == NULL)
                {
                    return SW_ERR;
                }
            }
        }
    }

    swBuffer_trunk *trunk;
    //close connection
    if (_send->info.type == SW_EVENT_CLOSE)
    {
        trunk = swBuffer_new_trunk(conn->out_buffer, SW_CHUNK_CLOSE, 0);
        trunk->store.data.val1 = _send->info.type;
    }
    //sendfile to client
    else if (_send->info.type == SW_EVENT_SENDFILE)
    {
        swSendFile_request *req = (swSendFile_request *) _send_data;
        swConnection_sendfile(conn, req->filename, req->offset, req->length);
    }
    //send data
    else
    {
        //connection is closed
        if (conn->removed)
        {
            swWarn("connection#%d is closed by client.", fd);
            return SW_ERR;
        }
        //connection output buffer overflow
        if (conn->out_buffer->length >= conn->buffer_size)
        {
            if (serv->send_yield)
            {
                SwooleG.error = SW_ERROR_OUTPUT_BUFFER_OVERFLOW;
            }
            else
            {
                swoole_error_log(SW_LOG_WARNING, SW_ERROR_OUTPUT_BUFFER_OVERFLOW, "connection#%d output buffer overflow.", fd);
            }
            conn->overflow = 1;
            if (serv->onBufferEmpty && serv->onBufferFull == NULL)
            {
                conn->high_watermark = 1;
            }
        }

        int _length = _send_length;
        void* _pos = _send_data;
        int _n;

        //buffer enQueue
        while (_length > 0)
        {
            _n = _length >= SW_BUFFER_SIZE_BIG ? SW_BUFFER_SIZE_BIG : _length;
            swBuffer_append(conn->out_buffer, _pos, _n);
            _pos += _n;
            _length -= _n;
        }

        swListenPort *port = swServer_get_port(serv, fd);
        if (serv->onBufferFull && conn->high_watermark == 0 && conn->out_buffer->length >= port->buffer_high_watermark)
        {
            swServer_tcp_notify(serv, conn, SW_EVENT_BUFFER_FULL);
            conn->high_watermark = 1;
        }
    }

    //listen EPOLLOUT event
    if (reactor->set(reactor, fd, SW_EVENT_TCP | SW_EVENT_WRITE | SW_EVENT_READ) < 0
            && (errno == EBADF || errno == ENOENT))
    {
        goto close_fd;
    }

    return SW_OK;
}


```

### `swConnection_sendfile` 发送文件

对于文件的发送，`swoole` 将文件的信息存储在 `swTask_sendfile` 对象中，然后将其放入 `conn->out_buffer` 中。

```c
typedef struct {
	char *filename;
	uint16_t name_len;
	int fd;
	size_t length;
	off_t offset;
} swTask_sendfile;

int swConnection_sendfile(swConnection *conn, char *filename, off_t offset, size_t length)
{
    if (conn->out_buffer == NULL)
    {
        conn->out_buffer = swBuffer_new(SW_BUFFER_SIZE);
        if (conn->out_buffer == NULL)
        {
            return SW_ERR;
        }
    }

    swBuffer_trunk error_chunk;
    swTask_sendfile *task = sw_malloc(sizeof(swTask_sendfile));
    if (task == NULL)
    {
        swWarn("malloc for swTask_sendfile failed.");
        return SW_ERR;
    }
    bzero(task, sizeof(swTask_sendfile));

    task->filename = sw_strdup(filename);
    int file_fd = open(filename, O_RDONLY);
    if (file_fd < 0)
    {
        sw_free(task->filename);
        sw_free(task);
        swSysError("open(%s) failed.", filename);
        return SW_OK;
    }
    task->fd = file_fd;
    task->offset = offset;

    struct stat file_stat;
    if (fstat(file_fd, &file_stat) < 0)
    {
        swSysError("fstat(%s) failed.", filename);
        error_chunk.store.ptr = task;
        swConnection_sendfile_destructor(&error_chunk);
        return SW_ERR;
    }
    if (offset < 0 || (length + offset > file_stat.st_size))
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_INVALID_PARAMS, "length or offset is invalid.");
        error_chunk.store.ptr = task;
        swConnection_sendfile_destructor(&error_chunk);
        return SW_OK;
    }
    if (length == 0)
    {
        task->length = file_stat.st_size;
    }
    else
    {
        task->length = length + offset;
    }

    swBuffer_trunk *chunk = swBuffer_new_trunk(conn->out_buffer, SW_CHUNK_SENDFILE, 0);
    if (chunk == NULL)
    {
        swWarn("get out_buffer trunk failed.");
        error_chunk.store.ptr = task;
        swConnection_sendfile_destructor(&error_chunk);
        return SW_ERR;
    }

    chunk->store.ptr = (void *) task;
    chunk->destroy = swConnection_sendfile_destructor;

    return SW_OK;
}

```

### `swConnection_onSendfile` 向客户端发送文件

- `HAVE_TCP_NOPUSH` 是避免 `TCP` 延迟接受的一种方法，为了避免 `Nagle` 算法造成的延迟，我们需要设置 `TCP_NODELAY` 选项和 `TCP_CORK` 选项来避免延迟接受和合并数据包（详情可以看 [Nagle 算法与 TCP socket 选项 TCP_CORK](http://senlinzhan.github.io/2017/02/10/Linux%E7%9A%84TCP-CORK/)）
- 获取到 `sendn` 后，就要调用 `swoole_sendfile` 读取文件内容，发送数据
- 发送数据结束后，再将 `TCP_CORK` 设置为 0
 

```c
static sw_inline int swSocket_tcp_nopush(int sock, int nopush)
{
    return setsockopt(sock, IPPROTO_TCP, TCP_CORK, (const void *) &nopush, sizeof(int));
}

int swConnection_onSendfile(swConnection *conn, swBuffer_trunk *chunk)
{
    int ret;
    swTask_sendfile *task = chunk->store.ptr;

#ifdef HAVE_TCP_NOPUSH
    if (task->offset == 0 && conn->tcp_nopush == 0)
    {
        /**
         * disable tcp_nodelay
         */
        if (conn->tcp_nodelay)
        {
            int tcp_nodelay = 0;
            if (setsockopt(conn->fd, IPPROTO_TCP, TCP_NODELAY, (const void *) &tcp_nodelay, sizeof(int)) == -1)
            {
                swWarn("setsockopt(TCP_NODELAY) failed. Error: %s[%d]", strerror(errno), errno);
            }
        }
        /**
         * enable tcp_nopush
         */
        if (swSocket_tcp_nopush(conn->fd, 1) == -1)
        {
            swWarn("swSocket_tcp_nopush() failed. Error: %s[%d]", strerror(errno), errno);
        }
        conn->tcp_nopush = 1;
    }
#endif

    int sendn = (task->length - task->offset > SW_SENDFILE_CHUNK_SIZE) ? SW_SENDFILE_CHUNK_SIZE : task->length - task->offset;

    {
        ret = swoole_sendfile(conn->fd, task->fd, &task->offset, sendn);
    }

    swTrace("ret=%d|task->offset=%ld|sendn=%d|filesize=%ld", ret, (long)task->offset, sendn, task->length);

    if (ret <= 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swSysError("sendfile(%s, %ld, %d) failed.", task->filename, (long)task->offset, sendn);
            swBuffer_pop_trunk(conn->out_buffer, chunk);
            return SW_OK;
        case SW_CLOSE:
            conn->close_wait = 1;
            return SW_ERR;
        case SW_WAIT:
            conn->send_wait = 1;
            return SW_ERR;
        default:
            break;
        }
    }

    //sendfile finish
    if (task->offset >= task->length)
    {
        swBuffer_pop_trunk(conn->out_buffer, chunk);

#ifdef HAVE_TCP_NOPUSH
        /**
         * disable tcp_nopush
         */
        if (swSocket_tcp_nopush(conn->fd, 0) == -1)
        {
            swWarn("swSocket_tcp_nopush() failed. Error: %s[%d]", strerror(errno), errno);
        }
        conn->tcp_nopush = 0;

        /**
         * enable tcp_nodelay
         */
        if (conn->tcp_nodelay)
        {
            int value = 1;
            if (setsockopt(conn->fd, IPPROTO_TCP, TCP_NODELAY, (const void *) &value, sizeof(int)) == -1)
            {
                swWarn("setsockopt(TCP_NODELAY) failed. Error: %s[%d]", strerror(errno), errno);
            }
        }
#endif
    }
    return SW_OK;
}

int swoole_sendfile(int out_fd, int in_fd, off_t *offset, size_t size)
{
    char buf[SW_BUFFER_SIZE_BIG];
    int readn = size > sizeof(buf) ? sizeof(buf) : size;

    int ret;
    int n = pread(in_fd, buf, readn, *offset);

    if (n > 0)
    {
        ret = write(out_fd, buf, n);
        if (ret < 0)
        {
            swSysError("write() failed.");
        }
        else
        {
            *offset += ret;
        }
        return ret;
    }
    else
    {
        swSysError("pread() failed.");
        return SW_ERR;
    }
}
```