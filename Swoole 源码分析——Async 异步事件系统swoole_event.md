# Swoole 源码分析——Async 异步事件系统 swoole_event

## 前言

对于异步的任务来说，`Server` 端的 `master` 进程与 `worker` 进程会自动将异步的事件添加到 `reactor` 的事件循环中去，`task_worker` 进程不允许存在异步任务。

对于异步的 `Client` 客户端、`swoole_process:: signal`、`swoole_timer`来说，`PHP` 代码并不存在 `reactor` 事件循环，这时候，`swoole` 就会为 `PHP` 代码创建相应的 `swoole_event` 的 `reactor` 事件循环，来模拟异步事件。

除了异步 `Server` 和 `Client` 库之外，`Swoole` 扩展还提供了直接操作底层 `epoll/kqueue` 事件循环的接口。可将其他扩展创建的 `socket`，`PHP` 代码中 `stream/socket` 扩展创建的 `socket` 等加入到 `Swoole` 的`EventLoop` 中。

只有了解了 `swoole_event` 的原理，才能更好的使用 `swoole` 中的定时器、信号、客户端等等异步事件接口。	
## `swoole_event_add` 添加异步事件

- 函数首先利用 `zend_parse_parameters` 解析传入的参数信息，并复制给 `zfd`、`cb_read` 读回调函数、`cb_write` 写回调函数，`event_flag` 监控事件。
- 利用 `swoole_convert_to_fd` 将传入的 `zfd` 转为文件描述符
- 新建 `php_reactor_fd` 对象，并对其设置文件描述符、读写回调函数
- `php_swoole_check_reactor` 检测是否存在 `reactor`，并对其进行初始化。
- 设置套接字文件描述符为非阻塞，在 `reactor` 中添加文件描述符


```
PHP_FUNCTION(swoole_event_add)
{
    zval *cb_read = NULL;
    zval *cb_write = NULL;
    zval *zfd;
    char *func_name = NULL;
    long event_flag = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|zzl", &zfd, &cb_read, &cb_write, &event_flag) == FAILURE)
    {
        return;
    }

    int socket_fd = swoole_convert_to_fd(zfd TSRMLS_CC);

    php_reactor_fd *reactor_fd = emalloc(sizeof(php_reactor_fd));
    reactor_fd->socket = zfd;
    sw_copy_to_stack(reactor_fd->socket, reactor_fd->stack.socket);
    sw_zval_add_ref(&reactor_fd->socket);

    if (cb_read!= NULL && !ZVAL_IS_NULL(cb_read))
    {
        if (!sw_zend_is_callable(cb_read, 0, &func_name TSRMLS_CC))
        {
            swoole_php_fatal_error(E_ERROR, "Function '%s' is not callable", func_name);
            efree(func_name);
            RETURN_FALSE;
        }
        efree(func_name);
        reactor_fd->cb_read = cb_read;
        sw_zval_add_ref(&cb_read);
        sw_copy_to_stack(reactor_fd->cb_read, reactor_fd->stack.cb_read);
    }
    else
    {
        reactor_fd->cb_read = NULL;
    }

    if (cb_write!= NULL && !ZVAL_IS_NULL(cb_write))
    {
        if (!sw_zend_is_callable(cb_write, 0, &func_name TSRMLS_CC))
        {
            swoole_php_fatal_error(E_ERROR, "Function '%s' is not callable", func_name);
            efree(func_name);
            RETURN_FALSE;
        }
        efree(func_name);
        reactor_fd->cb_write = cb_write;
        sw_zval_add_ref(&cb_write);
        sw_copy_to_stack(reactor_fd->cb_write, reactor_fd->stack.cb_write);
    }
    else
    {
        reactor_fd->cb_write = NULL;
    }

    php_swoole_check_reactor();
    swSetNonBlock(socket_fd); //must be nonblock

    if (SwooleG.main_reactor->add(SwooleG.main_reactor, socket_fd, SW_FD_USER | event_flag) < 0)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event_add failed.");
        RETURN_FALSE;
    }

    swConnection *socket = swReactor_get(SwooleG.main_reactor, socket_fd);
    socket->object = reactor_fd;
    socket->active = 1;
    socket->nonblock = 1;

    RETURN_LONG(socket_fd);
}

```
`sock` 可以为以下四种类型：

- `int`，就是文件描述符，包括 `swoole_client->$sock`、`swoole_process->$pipe` 或者其他 `fd`
- `stream` 资源，就是 `stream_socket_client/fsockopen` 创建的资源
- `sockets` 资源，就是 `sockets` 扩展中 `socket_create` 创建的资源，需要在编译时加入 `./configure --enable-sockets`
- `object`，`swoole_process` 或 `swoole_client`，底层自动转换为管道或客户端连接的 `socket`

从 `swoole_convert_to_fd` 中可以看到，

- `IS_LONG` 的 `if` 分支最为简单，直接转为 `long` 类型即可。
- `IS_RESOURCE` 资源类型分为两种
	- 一种是 `stream_socket_client/fsockopen`，是标准 `PHP` 创建 `socket` 的方式，这时会调用 `SW_ZEND_FETCH_RESOURCE_NO_RETURN` 将 `zfd` 转为 `php_stream` 类型，再将 `php_stream` 类型转为 `socket_fd`
	- 另一种是 `PHP` 提供的套接字，此时需要利用 `SW_ZEND_FETCH_RESOURCE_NO_RETURN` 将 `zfd` 转为 `php_socket`，`socket_fd` 就是 `php_socket` 的 `bsd_socket` 属性。
- `IS_OBJECT` 对象类型也分为两种：
	- 程序通过 `instanceof_function` 函数判断对象是 `swoole_client`，如果是则取出其 `sock` 属性对象
	- 如果对象是 `swoole_process` 对象，则取出 `pipe` 对象。

`SW_ZEND_FETCH_RESOURCE_NO_RETURN` 实际上是一个宏函数，利用的是 `zend_fetch_resource` 函数。

```
#define SW_ZEND_FETCH_RESOURCE_NO_RETURN(rsrc, rsrc_type, passed_id, default_id, resource_type_name, resource_type)        \
        (rsrc = (rsrc_type) zend_fetch_resource(Z_RES_P(*passed_id), resource_type_name, resource_type))
        
int swoole_convert_to_fd(zval *zfd TSRMLS_DC)
{
    php_stream *stream;
    int socket_fd;

#ifdef SWOOLE_SOCKETS_SUPPORT
    php_socket *php_sock;
#endif
    if (SW_Z_TYPE_P(zfd) == IS_RESOURCE)
    {
        if (SW_ZEND_FETCH_RESOURCE_NO_RETURN(stream, php_stream *, &zfd, -1, NULL, php_file_le_stream()))
        {
            if (php_stream_cast(stream, PHP_STREAM_AS_FD_FOR_SELECT | PHP_STREAM_CAST_INTERNAL, (void* )&socket_fd, 1) != SUCCESS || socket_fd < 0)
            {
                return SW_ERR;
            }
        }
        else
        {
#ifdef SWOOLE_SOCKETS_SUPPORT
            if (SW_ZEND_FETCH_RESOURCE_NO_RETURN(php_sock, php_socket *, &zfd, -1, NULL, php_sockets_le_socket()))
            {
                socket_fd = php_sock->bsd_socket;

            }
            else
            {
                swoole_php_fatal_error(E_WARNING, "fd argument must be either valid PHP stream or valid PHP socket resource");
                return SW_ERR;
            }
#else
            swoole_php_fatal_error(E_WARNING, "fd argument must be valid PHP stream resource");
            return SW_ERR;
#endif
        }
    }
    else if (SW_Z_TYPE_P(zfd) == IS_LONG)
    {
        socket_fd = Z_LVAL_P(zfd);
        if (socket_fd < 0)
        {
            swoole_php_fatal_error(E_WARNING, "invalid file descriptor passed");
            return SW_ERR;
        }
    }
    else if (SW_Z_TYPE_P(zfd) == IS_OBJECT)
    {
        zval *zsock = NULL;
        if (instanceof_function(Z_OBJCE_P(zfd), swoole_client_class_entry_ptr TSRMLS_CC))
        {
            zsock = sw_zend_read_property(Z_OBJCE_P(zfd), zfd, SW_STRL("sock")-1, 0 TSRMLS_CC);
        }
        else if (instanceof_function(Z_OBJCE_P(zfd), swoole_process_class_entry_ptr TSRMLS_CC))
        {
            zsock = sw_zend_read_property(Z_OBJCE_P(zfd), zfd, SW_STRL("pipe")-1, 0 TSRMLS_CC);
        }
        if (zsock == NULL || ZVAL_IS_NULL(zsock))
        {
            swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client or swoole_process.");
            return -1;
        }
        socket_fd = Z_LVAL_P(zsock);
    }
    else
    {
        return SW_ERR;
    }
    return socket_fd;
}

```

`php_swoole_check_reactor` 用于检测 `reactor` 是否存在。

- 从函数中可以看到，异步事件只能在 `CLI` 模式下生效，不能用于 `task_worker` 进程中。
- 如果当前进程不存在 `main_reactor`，那么就要创建 `reactor`，并且设置事件的回调函数
- 将 `swoole_event_wait` 注册为 `php` 的 `shutdown` 函数。

```
void php_swoole_check_reactor()
{
    if (likely(SwooleWG.reactor_init))
    {
        return;
    }

    if (!SWOOLE_G(cli))
    {
        swoole_php_fatal_error(E_ERROR, "async-io must be used in PHP CLI mode.");
        return;
    }

    if (swIsTaskWorker())
    {
        swoole_php_fatal_error(E_ERROR, "can't use async-io in task process.");
        return;
    }

    if (SwooleG.main_reactor == NULL)
    {
        swTraceLog(SW_TRACE_PHP, "init reactor");

        SwooleG.main_reactor = (swReactor *) sw_malloc(sizeof(swReactor));
        if (SwooleG.main_reactor == NULL)
        {
            swoole_php_fatal_error(E_ERROR, "malloc failed.");
            return;
        }
        if (swReactor_create(SwooleG.main_reactor, SW_REACTOR_MAXEVENTS) < 0)
        {
            swoole_php_fatal_error(E_ERROR, "failed to create reactor.");
            return;
        }

#ifdef SW_COROUTINE
        SwooleG.main_reactor->can_exit = php_coroutine_reactor_can_exit;
#endif

        //client, swoole_event_exit will set swoole_running = 0
        SwooleWG.in_client = 1;
        SwooleWG.reactor_wait_onexit = 1;
        SwooleWG.reactor_ready = 0;
        //only client side
        php_swoole_at_shutdown("swoole_event_wait");
    }

    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_USER | SW_EVENT_READ, php_swoole_event_onRead);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_USER | SW_EVENT_WRITE, php_swoole_event_onWrite);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_USER | SW_EVENT_ERROR, php_swoole_event_onError);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_WRITE, swReactor_onWrite);

    SwooleWG.reactor_init = 1;
}

```

## `swoole_event_set` 函数

参数与 `swoole_event_add` 完全相同。如果传入 `$fd` 在 `EventLoop` 中不存在返回 `false`，用于修改事件监听的回调函数和掩码。

最核心的是调用了 `SwooleG.main_reactor->set` 函数。

```
PHP_FUNCTION(swoole_event_set)
{
    zval *cb_read = NULL;
    zval *cb_write = NULL;
    zval *zfd;

    char *func_name = NULL;
    long event_flag = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|zzl", &zfd, &cb_read, &cb_write, &event_flag) == FAILURE)
    {
        return;
    }

    int socket_fd = swoole_convert_to_fd(zfd TSRMLS_CC);

    swConnection *socket = swReactor_get(SwooleG.main_reactor, socket_fd);

    php_reactor_fd *ev_set = socket->object;
    if (cb_read != NULL && !ZVAL_IS_NULL(cb_read))
    {
        if (!sw_zend_is_callable(cb_read, 0, &func_name TSRMLS_CC))
        {
            swoole_php_fatal_error(E_ERROR, "Function '%s' is not callable", func_name);
            efree(func_name);
            RETURN_FALSE;
        }
        else
        {
            if (ev_set->cb_read)
            {
                sw_zval_ptr_dtor(&ev_set->cb_read);
            }
            ev_set->cb_read = cb_read;
            sw_zval_add_ref(&cb_read);
            sw_copy_to_stack(ev_set->cb_read, ev_set->stack.cb_read);
            efree(func_name);
        }
    }

    if (cb_write != NULL && !ZVAL_IS_NULL(cb_write))
    {
        if (socket_fd == 0 && (event_flag & SW_EVENT_WRITE))
        {
            swoole_php_fatal_error(E_WARNING, "invalid socket fd [%d].", socket_fd);
            RETURN_FALSE;
        }
        if (!sw_zend_is_callable(cb_write, 0, &func_name TSRMLS_CC))
        {
            swoole_php_fatal_error(E_ERROR, "Function '%s' is not callable", func_name);
            efree(func_name);
            RETURN_FALSE;
        }
        else
        {
            if (ev_set->cb_write)
            {
                sw_zval_ptr_dtor(&ev_set->cb_write);
            }
            ev_set->cb_write = cb_write;
            sw_zval_add_ref(&cb_write);
            sw_copy_to_stack(ev_set->cb_write, ev_set->stack.cb_write);
            efree(func_name);
        }
    }

    if ((event_flag & SW_EVENT_READ) && ev_set->cb_read == NULL)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event: no read callback.");
        RETURN_FALSE;
    }

    if ((event_flag & SW_EVENT_WRITE) && ev_set->cb_write == NULL)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event: no write callback.");
        RETURN_FALSE;
    }

    if (SwooleG.main_reactor->set(SwooleG.main_reactor, socket_fd, SW_FD_USER | event_flag) < 0)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event_set failed.");
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

```

## `swoole_event_write` 函数

用于PHP自带 `stream/sockets` 扩展创建的 `socket`，使用 `fwrite/socket_send` 等函数向对端发送数据。当发送的数据量较大，`socket` 写缓存区已满，就会发送阻塞等待或者返回 `EAGAIN` 错误。

`swoole_event_write` 函数可以将 `stream/sockets` 资源的数据发送变成异步的，当缓冲区满了或者返回 `EAGAIN`，`swoole` 底层会将数据加入到发送队列，并监听可写。`socket` 可写时 `swoole` 底层会自动写入。

`swoole_event_write` 函数主要调用了 `SwooleG.main_reactor->write` 实现功能。

```
PHP_FUNCTION(swoole_event_write)
{
    zval *zfd;
    char *data;
    zend_size_t len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs", &zfd, &data, &len) == FAILURE)
    {
        return;
    }

    if (len <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "data empty.");
        RETURN_FALSE;
    }

    int socket_fd = swoole_convert_to_fd(zfd TSRMLS_CC);
    if (socket_fd < 0)
    {
        swoole_php_fatal_error(E_WARNING, "unknow type.");
        RETURN_FALSE;
    }

    php_swoole_check_reactor();
    if (SwooleG.main_reactor->write(SwooleG.main_reactor, socket_fd, data, len) < 0)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_TRUE;
    }
}

```

## `swoole_event_wait` 函数

`swoole_event_wait` 函数用于让整个 `PHP` 程序进入事件循环，刚刚我们可以看到，`swoole` 把这个函数注册为 `shutdown` 函数，脚本在停止之前会自动调用这个函数。如果自己想要在程序中间进行事件循环可以调用该函数。

该函数最重要的就是调用 `SwooleG.main_reactor->wait` 函数，该函数会不断 `while` 循环阻塞在 `reactor->wait` 上，直到有信号或者读写就绪事件发生。

```
PHP_FUNCTION(swoole_event_wait)
{
    if (!SwooleG.main_reactor)
    {
        return;
    }
    php_swoole_event_wait();
}

void php_swoole_event_wait()
{
    if (SwooleWG.in_client == 1 && SwooleWG.reactor_ready == 0 && SwooleG.running)
    {
        if (PG(last_error_message))
        {
            switch (PG(last_error_type))
            {
            case E_ERROR:
            case E_CORE_ERROR:
            case E_USER_ERROR:
            case E_COMPILE_ERROR:
                return;
            default:
                break;
            }
        }
        SwooleWG.reactor_ready = 1;

#ifdef HAVE_SIGNALFD
        if (SwooleG.main_reactor->check_signalfd)
        {
            swSignalfd_setup(SwooleG.main_reactor);
        }
#endif

#ifdef SW_COROUTINE
        if (COROG.active == 0)
        {
            coro_init(TSRMLS_C);
        }
#endif
        if (!swReactor_empty(SwooleG.main_reactor))
        {
            int ret = SwooleG.main_reactor->wait(SwooleG.main_reactor, NULL);
            if (ret < 0)
            {
                swoole_php_fatal_error(E_ERROR, "reactor wait failed. Error: %s [%d]", strerror(errno), errno);
            }
        }
        if (SwooleG.timer.map)
        {
            php_swoole_clear_all_timer();
        }
        SwooleWG.reactor_exit = 1;
    }
}
```

## `swoole_event_defer` 延迟执行回调函数

`swoole_event_defer` 函数会利用 `SwooleG.main_reactor->defer` 向 `reactor` 注册延迟执行的函数:

```
PHP_FUNCTION(swoole_event_defer)
{
    zval *callback;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &callback) == FAILURE)
    {
        return;
    }

    char *func_name;
    if (!sw_zend_is_callable(callback, 0, &func_name TSRMLS_CC))
    {
        swoole_php_fatal_error(E_ERROR, "Function '%s' is not callable", func_name);
        efree(func_name);
        RETURN_FALSE;
    }
    efree(func_name);

    php_swoole_check_reactor();

    php_defer_callback *defer = emalloc(sizeof(php_defer_callback));
    defer->callback = &defer->_callback;
    memcpy(defer->callback, callback, sizeof(zval));
    sw_zval_add_ref(&callback);
    SW_CHECK_RETURN(SwooleG.main_reactor->defer(SwooleG.main_reactor, php_swoole_event_onDefer, defer));
}
```

`SwooleG.main_reactor->defer` 函数就是 `swReactor_defer`。从该函数可以看出，如果调用 `defer` 的时候 `reactor` 还没有启动，那么就用定时器来实现延迟执行；如果此时 `reactor` 已经启动了，那么就添加到 `defer_tasks` 属性中。

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
    if (unlikely(reactor->start == 0))
    {
        if (unlikely(SwooleG.timer.fd == 0))
        {
            swTimer_init(1);
        }
        SwooleG.timer.add(&SwooleG.timer, 1, 0, cb, swReactor_defer_timer_callback);
    }
    else
    {
        LL_APPEND(reactor->defer_tasks, cb);
    }
    return SW_OK;
}

static void swReactor_defer_timer_callback(swTimer *timer, swTimer_node *tnode)
{
    swDefer_callback *cb = (swDefer_callback *) tnode->data;
    cb->callback(cb->data);
    sw_free(cb);
}
```
`reactor` 无论是超时还是事件循环结束，都会调用 `swReactor_onTimeout_and_Finish` 函数，该函数会调用 `reactor->defer_tasks`，执行之后就会自动删除延迟任务。

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

static void swReactor_onTimeout_and_Finish(swReactor *reactor)
{
    if (reactor->check_timer)
    {
        swTimer_select(&SwooleG.timer);
    }

    do
    {
        swDefer_callback *defer_tasks = reactor->defer_tasks;
        swDefer_callback *cb, *tmp;
        reactor->defer_tasks = NULL;
        LL_FOREACH(defer_tasks, cb)
        {
            cb->callback(cb->data);
        }
        LL_FOREACH_SAFE(defer_tasks, cb, tmp)
        {
            sw_free(cb);
        }
    } while (reactor->defer_tasks);
    
    ...
}
```
延迟任务的执行就调用回调函数：

```
static void php_swoole_event_onDefer(void *_cb)
{
    php_defer_callback *defer = _cb;

    zval *retval;
    if (sw_call_user_function_ex(EG(function_table), NULL, defer->callback, &retval, 0, NULL, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event: defer handler error");
        return;
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&defer->callback);
    efree(defer);
}
```

## `swoole_event_cycle` 循环周期回调函数

`swoole_event_cycle` 函数中如果传入的回调函数为 `null`，说明用户想要清除周期回调函数，`swoole` 将周期函数转化为 `defer` 即可。

`before` 为 1，代表用户想要在 `EventLoop` 之前调用该函数，`swoole` 会将其放在 `future_task` 中；否则将会在 `EventLoop` 之后执行，会放在 `idle_task` 中。

注意如果之前存在过周期循环函数，此次是修改周期回调函数，那么需要在此之前，要将之前的周期回调函数转为 `defer` 执行。

```
PHP_FUNCTION(swoole_event_cycle)
{
    if (!SwooleG.main_reactor)
    {
        swoole_php_fatal_error(E_WARNING, "reactor no ready, cannot swoole_event_defer.");
        RETURN_FALSE;
    }

    zval *callback;
    zend_bool before = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|b", &callback, &before) == FAILURE)
    {
        return;
    }

    if (ZVAL_IS_NULL(callback))
    {
        if (SwooleG.main_reactor->idle_task.callback == NULL)
        {
            RETURN_FALSE;
        }
        else
        {
            SwooleG.main_reactor->defer(SwooleG.main_reactor, free_callback, SwooleG.main_reactor->idle_task.data);
            SwooleG.main_reactor->idle_task.callback = NULL;
            SwooleG.main_reactor->idle_task.data = NULL;
            RETURN_TRUE;
        }
    }

    char *func_name;
    if (!sw_zend_is_callable(callback, 0, &func_name TSRMLS_CC))
    {
        swoole_php_fatal_error(E_ERROR, "Function '%s' is not callable", func_name);
        efree(func_name);
        RETURN_FALSE;
    }
    efree(func_name);

    php_defer_callback *cb = emalloc(sizeof(php_defer_callback));

    cb->callback = &cb->_callback;
    memcpy(cb->callback, callback, sizeof(zval));
    sw_zval_add_ref(&callback);

    if (before == 0)
    {
        if (SwooleG.main_reactor->idle_task.data != NULL)
        {
            SwooleG.main_reactor->defer(SwooleG.main_reactor, free_callback, SwooleG.main_reactor->idle_task.data);
        }

        SwooleG.main_reactor->idle_task.callback = php_swoole_event_onEndCallback;
        SwooleG.main_reactor->idle_task.data = cb;
    }
    else
    {
        if (SwooleG.main_reactor->future_task.data != NULL)
        {
            SwooleG.main_reactor->defer(SwooleG.main_reactor, free_callback, SwooleG.main_reactor->future_task.data);
        }

        SwooleG.main_reactor->future_task.callback = php_swoole_event_onEndCallback;
        SwooleG.main_reactor->future_task.data = cb;
        //Registration onBegin callback function
        swReactor_activate_future_task(SwooleG.main_reactor);
    }

    RETURN_TRUE;
}

static void free_callback(void* data)
{
    php_defer_callback *cb = (php_defer_callback *) data;
    sw_zval_ptr_dtor(&cb->callback);
    efree(cb);
}
```
在每次事件循环之前都要执行 `onBegin` 函数，也就是 `swReactor_onBegin`，此时会调用 `future_task`；当 `reactor` 超时（`onTimeout`）或者事件循环结束(`onFinish`)，都会调用 `swReactor_onTimeout_and_Finish `，此时会调用 `idle_task`:

```
static int swReactorEpoll_wait(swReactor *reactor, struct timeval *timeo)
{
    ...
    
    while (reactor->running > 0)
    {
        if (reactor->onBegin != NULL)
        {
            reactor->onBegin(reactor);
        }
        
        n = epoll_wait(epoll_fd, events, max_event_num, msec);
        
        ...
        
        else if (n == 0)
        {
            if (reactor->onTimeout != NULL)
            {
                reactor->onTimeout(reactor);
            }
            continue;
        }
        
        ...
        
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
static void swReactor_onBegin(swReactor *reactor)
{
    if (reactor->future_task.callback)
    {
        reactor->future_task.callback(reactor->future_task.data);
    }
}

static void swReactor_onTimeout_and_Finish(swReactor *reactor)
{
    ...
    
    if (reactor->idle_task.callback)
    {
        reactor->idle_task.callback(reactor->idle_task.data);
    }
    
    ...
}
```

真正执行回调函数的是 `php_swoole_event_onEndCallback`：

```

static void php_swoole_event_onEndCallback(void *_cb)
{
    php_defer_callback *defer = _cb;

    zval *retval;
    if (sw_call_user_function_ex(EG(function_table), NULL, defer->callback, &retval, 0, NULL, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event: defer handler error");
        return;
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

```

## `php_swoole_event_onRead` 读就绪事件回调函数

读就绪事件回调函数就是简单的调用用户的回调函数即可。

```
static int php_swoole_event_onRead(swReactor *reactor, swEvent *event)
{
    zval *retval;
    zval **args[1];
    php_reactor_fd *fd = event->socket->object;

    args[0] = &fd->socket;

    if (sw_call_user_function_ex(EG(function_table), NULL, fd->cb_read, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event: onRead handler error.");
        SwooleG.main_reactor->del(SwooleG.main_reactor, event->fd);
        return SW_ERR;
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    return SW_OK;
}
```	

## `php_swoole_event_onWrite` 写就绪事件回调函数

写就绪事件回调函数就是调用 `fd->cb_write` 回调函数，当然如果用户并没有设置该回调函数的话，就会调用 `swReactor_onWrite` 发送 `socket->out_buffer` 的数据或者自动移除写监听事件。

```
static int php_swoole_event_onWrite(swReactor *reactor, swEvent *event)
{
    zval *retval;
    zval **args[1];
    php_reactor_fd *fd = event->socket->object;


    if (!fd->cb_write)
    {
        return swReactor_onWrite(reactor, event);
    }

    args[0] = &fd->socket;

    if (sw_call_user_function_ex(EG(function_table), NULL, fd->cb_write, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event: onWrite handler error");
        SwooleG.main_reactor->del(SwooleG.main_reactor, event->fd);
        return SW_ERR;
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    return SW_OK;
}

```

## `php_swoole_event_onError` 异常事件回调函数

当 `reactor` 发现套接字发生错误后，就会自动删除该套接字的监听。

```
static int php_swoole_event_onError(swReactor *reactor, swEvent *event)
{

    int error;
    socklen_t len = sizeof(error);

    if (getsockopt(event->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event->onError[1]: getsockopt[sock=%d] failed. Error: %s[%d]", event->fd, strerror(errno), errno);
    }

    if (error != 0)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event->onError[1]: socket error. Error: %s [%d]", strerror(error), error);
    }

    efree(event->socket->object);
    event->socket->active = 0;

    SwooleG.main_reactor->del(SwooleG.main_reactor, event->fd);

    return SW_OK;
}

```

## `swoole_event_del` 删除套接字

删除套接字就是从 `reactor` 中删除监听的文件描述符 `SwooleG.main_reactor->del`

```
PHP_FUNCTION(swoole_event_del)
{
    zval *zfd;

    if (!SwooleG.main_reactor)
    {
        swoole_php_fatal_error(E_WARNING, "reactor no ready, cannot swoole_event_del.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zfd) == FAILURE)
    {
        return;
    }

    int socket_fd = swoole_convert_to_fd(zfd TSRMLS_CC);
    if (socket_fd < 0)
    {
        swoole_php_fatal_error(E_WARNING, "unknow type.");
        RETURN_FALSE;
    }

    swConnection *socket = swReactor_get(SwooleG.main_reactor, socket_fd);
    if (socket->object)
    {
        SwooleG.main_reactor->defer(SwooleG.main_reactor, free_event_callback, socket->object);
        socket->object = NULL;
    }

    int ret = SwooleG.main_reactor->del(SwooleG.main_reactor, socket_fd);
    socket->active = 0;
    SW_CHECK_RETURN(ret);
}

```
## `swoole_event_exit` 退出事件循环

退出事件循环就是将 `SwooleG.main_reactor->running` 置为 0，使得 `while` 循环为 `false`。

```
PHP_FUNCTION(swoole_event_exit)
{
    if (SwooleWG.in_client == 1)
    {
        if (SwooleG.main_reactor)
        {
            SwooleG.main_reactor->running = 0;
        }
        SwooleG.running = 0;
    }
}

```