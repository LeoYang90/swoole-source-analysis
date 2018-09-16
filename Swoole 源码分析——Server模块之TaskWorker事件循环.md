# Swoole 源码分析——Server模块之TaskWorker事件循环

## `swManager_start` 创建进程流程

`task_worker` 进程的创建可以分为三个步骤：`swServer_create_task_worker` 申请所需的内存、`swTaskWorker_init` 初始化各个属性、`swProcessPool_start` 创建进程

```
int swManager_start(swFactory *factory)
{
    swFactoryProcess *object = factory->object;
    int i;
    pid_t pid;
    swServer *serv = factory->ptr;

    if (serv->task_worker_num > 0)
    {
        if (swServer_create_task_worker(serv) < 0)
        {
            return SW_ERR;
        }

        swProcessPool *pool = &serv->gs->task_workers;
        swTaskWorker_init(pool);

        swWorker *worker;
        for (i = 0; i < serv->task_worker_num; i++)
        {
            worker = &pool->workers[i];
            if (swWorker_create(worker) < 0)
            {
                return SW_ERR;
            }
            if (serv->task_ipc_mode == SW_TASK_IPC_UNIXSOCK)
            {
                swServer_store_pipe_fd(SwooleG.serv, worker->pipe_object);
            }
        }
    }

    pid = fork();
    switch (pid)
    {
    //fork manager process
    case 0:
        if (serv->task_worker_num > 0)
        {
            swProcessPool_start(&serv->gs->task_workers);
        }
        break;

        //master process
    default:
        serv->gs->manager_pid = pid;
        break;
    case -1:
        swError("fork() failed.");
        return SW_ERR;
    }
    return SW_OK;
}

```

![](http://owql68l6p.bkt.clouddn.com/swManager_start-2.png)

## `swServer_create_task_worker` 创建 `task` 进程

- `task` 进程的调度有四种： 使用unix socket通信，默认模式；使用消息队列通信； 使用消息队列通信，并设置为争抢模式；`stream` 模式
- 不同于 `worker` 进程，`tasker` 进程由 `swProcessPool_create` 创建
- 如果是 `stream` 模式，程序还要调用 `swProcessPool_create_unix_socket` 创建一个监听的 `socket`

```
int swServer_create_task_worker(swServer *serv)
{
    key_t key = 0;
    int ipc_mode;

    if (serv->task_ipc_mode == SW_TASK_IPC_MSGQUEUE || serv->task_ipc_mode == SW_TASK_IPC_PREEMPTIVE)
    {
        key = serv->message_queue_key;
        ipc_mode = SW_IPC_MSGQUEUE;
    }
    else if (serv->task_ipc_mode == SW_TASK_IPC_STREAM)
    {
        ipc_mode = SW_IPC_SOCKET;
    }
    else
    {
        ipc_mode = SW_IPC_UNIXSOCK;
    }

    if (swProcessPool_create(&serv->gs->task_workers, serv->task_worker_num, serv->task_max_request, key, ipc_mode) < 0)
    {
        swWarn("[Master] create task_workers failed.");
        return SW_ERR;
    }
    if (ipc_mode == SW_IPC_SOCKET)
    {
        char sockfile[sizeof(struct sockaddr_un)];
        snprintf(sockfile, sizeof(sockfile), "/tmp/swoole.task.%d.sock", serv->gs->master_pid);
        if (swProcessPool_create_unix_socket(&serv->gs->task_workers, sockfile, 2048) < 0)
        {
            return SW_ERR;
        }
    }
    return SW_OK;
}

```

### `swProcessPool_create` 函数

- `swProcessPool_create` 函数主要为 `task` 进程申请内存初始化变量。首先要申请 `worker_num` 个 `worker` 的内存。
- 如果调度采用的是消息队列通信，那么首先就要创建消息队列，初始化 `pool->queue`，相关函数是 `swMsgQueue_create`
- 如果调度采用 `stream` 模式，那么就要初始化 `pool->stream`
- 如果调度采用模式的 `unixsock`，那么就要创建各个 `worker` 的 `pipe`
- 创建 `pool->map` 与 `main_loop`


```
int swProcessPool_create(swProcessPool *pool, int worker_num, int max_request, key_t msgqueue_key, int ipc_mode)
{
    bzero(pool, sizeof(swProcessPool));

    pool->worker_num = worker_num;
    pool->max_request = max_request;

    pool->workers = SwooleG.memory_pool->alloc(SwooleG.memory_pool, worker_num * sizeof(swWorker));
    if (pool->workers == NULL)
    {
        swSysError("malloc[1] failed.");
        return SW_ERR;
    }

    if (ipc_mode == SW_IPC_MSGQUEUE)
    {
        pool->use_msgqueue = 1;
        pool->msgqueue_key = msgqueue_key;

        pool->queue = sw_malloc(sizeof(swMsgQueue));
        if (pool->queue == NULL)
        {
            swSysError("malloc[2] failed.");
            return SW_ERR;
        }

        if (swMsgQueue_create(pool->queue, 1, pool->msgqueue_key, 0) < 0)
        {
            return SW_ERR;
        }
    }
    else if (ipc_mode == SW_IPC_SOCKET)
    {
        pool->use_socket = 1;
        pool->stream = sw_malloc(sizeof(swStreamInfo));
        if (pool->stream == NULL)
        {
            swWarn("malloc[2] failed.");
            return SW_ERR;
        }
        bzero(pool->stream, sizeof(swStreamInfo));
    }
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
    else
    {
        ipc_mode = SW_IPC_NONE;
    }

    pool->map = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, NULL);
    if (pool->map == NULL)
    {
        swProcessPool_free(pool);
        return SW_ERR;
    }

    pool->ipc_mode = ipc_mode;
    if (ipc_mode > SW_IPC_NONE)
    {
        pool->main_loop = swProcessPool_worker_loop;
    }

    return SW_OK;
}

```

### `swProcessPool_create_unix_socket` 函数

当调度模式是 `stream` 的时候，还有创建相应的本地 `UNIX` 域套接字 `socket`，绑定到 `/tmp/swoole.task.%d.sock` 本地 `sock` 文件上。


```
int swProcessPool_create_unix_socket(swProcessPool *pool, char *socket_file, int blacklog)
{
    if (pool->ipc_mode != SW_IPC_SOCKET)
    {
        swWarn("ipc_mode is not SW_IPC_SOCKET.");
        return SW_ERR;
    }
    pool->stream->socket_file = sw_strdup(socket_file);
    if (pool->stream->socket_file == NULL)
    {
        return SW_ERR;
    }
    pool->stream->socket = swSocket_create_server(SW_SOCK_UNIX_STREAM, pool->stream->socket_file, 0, blacklog);
    if (pool->stream->socket < 0)
    {
        return SW_ERR;
    }
    return SW_OK;
}

int swSocket_create_server(int type, char *address, int port, int backlog)
{
    int fd = swSocket_create(type);
    if (fd < 0)
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SYSTEM_CALL_FAIL, "socket() failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }

    if (swSocket_bind(fd, type, address, &port) < 0)
    {
        return SW_ERR;
    }

    if (listen(fd, backlog) < 0)
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SYSTEM_CALL_FAIL, "listen(%s:%d, %d) failed. Error: %s[%d]", address, port, backlog, strerror(errno), errno);
        return SW_ERR;
    }

    return fd;
}
```

## `swTaskWorker_init` 函数

```
void swTaskWorker_init(swProcessPool *pool)
{
    swServer *serv = SwooleG.serv;
    pool->ptr = serv;
    pool->onTask = swTaskWorker_onTask;
    pool->onWorkerStart = swTaskWorker_onStart;
    pool->onWorkerStop = swTaskWorker_onStop;
    pool->type = SW_PROCESS_TASKWORKER;
    pool->start_id = serv->worker_num;
    pool->run_worker_num = serv->task_worker_num;

    if (serv->task_ipc_mode == SW_TASK_IPC_PREEMPTIVE)
    {
        pool->dispatch_mode = SW_DISPATCH_QUEUE;
    }
}

```


## `swProcessPool_start` 进程启动

- 本函数利用 `swProcessPool_spawn` 启动所有的 `task_worker` 进程
- `fork` 子进程后，将 `task` 进程的进程 `id` 存放到 `pool->map` 中
- 在 `task` 进程中，调用 `onWorkerStart` 回调函数、`onWorkerStop` 回调函数，进行事件循环

```
int swProcessPool_start(swProcessPool *pool)
{
    if (pool->ipc_mode == SW_IPC_SOCKET && (pool->stream == NULL || pool->stream->socket == 0))
    {
        swWarn("must first listen to an tcp port.");
        return SW_ERR;
    }

    int i;
    pool->started = 1;
    pool->run_worker_num = pool->worker_num;

    for (i = 0; i < pool->worker_num; i++)
    {
        pool->workers[i].pool = pool;
        pool->workers[i].id = pool->start_id + i;
        pool->workers[i].type = pool->type;

        if (swProcessPool_spawn(pool, &(pool->workers[i])) < 0)
        {
            return SW_ERR;
        }
    }
    return SW_OK;
}

pid_t swProcessPool_spawn(swProcessPool *pool, swWorker *worker)
{
    pid_t pid = fork();
    int ret_code = 0;

    switch (pid)
    {
    //child
    case 0:
        /**
         * Process start
         */
        if (pool->onWorkerStart != NULL)
        {
            pool->onWorkerStart(pool, worker->id);
        }
        /**
         * Process main loop
         */
        if (pool->main_loop)
        {
            ret_code = pool->main_loop(pool, worker);
        }
        /**
         * Process stop
         */
        if (pool->onWorkerStop != NULL)
        {
            pool->onWorkerStop(pool, worker->id);
        }
        exit(ret_code);
        break;
    case -1:
        swWarn("fork() failed. Error: %s [%d]", strerror(errno), errno);
        break;
        //parent
    default:
        //remove old process
        if (worker->pid)
        {
            swHashMap_del_int(pool->map, worker->pid);
        }
        worker->pid = pid;
        //insert new process
        swHashMap_add_int(pool->map, pid, worker);
        break;
    }
    return pid;
}

```

### `onWorkerStart` 函数

`onWorkerStart` 函数是进程启动的回调函数，作用是设置信号处理函数，调用设置的 `serv->onWorkerStart` 函数。

```
void swTaskWorker_onStart(swProcessPool *pool, int worker_id)
{
    swServer *serv = pool->ptr;
    SwooleWG.id = worker_id;
    SwooleG.pid = getpid();

    SwooleG.use_timer_pipe = 0;
    SwooleG.use_timerfd = 0;

    swServer_close_port(serv, SW_TRUE);

    swTaskWorker_signal_init();
    swWorker_onStart(serv);

    SwooleG.main_reactor = NULL;
    swWorker *worker = swProcessPool_get_worker(pool, worker_id);
    worker->start_time = serv->gs->now;
    worker->request_count = 0;
    worker->traced = 0;
    SwooleWG.worker = worker;
    SwooleWG.worker->status = SW_WORKER_IDLE;
}

static void swTaskWorker_signal_init(void)
{
    swSignal_set(SIGHUP, NULL, 1, 0);
    swSignal_set(SIGPIPE, NULL, 1, 0);
    swSignal_set(SIGUSR1, swWorker_signal_handler, 1, 0);
    swSignal_set(SIGUSR2, NULL, 1, 0);
    swSignal_set(SIGTERM, swWorker_signal_handler, 1, 0);
    swSignal_set(SIGALRM, swSystemTimer_signal_handler, 1, 0);
#ifdef SIGRTMIN
    swSignal_set(SIGRTMIN, swWorker_signal_handler, 1, 0);
#endif
}
```

### `onWorkerStop` 函数

```
void swTaskWorker_onStop(swProcessPool *pool, int worker_id)
{
    swServer *serv = pool->ptr;
    swWorker_onStop(serv);
}

```

## `swProcessPool_worker_loop` 事件循环

- 在事件循环时，如果使用的是消息队列，那么就不断的调用 `swMsgQueue_pop` 从消息队列中取出数据。值得注意的是，`SW_DISPATCH_QUEUE` 代表采用了消息队列通信，并设置为争抢模式，因此没有设置 `out.mtype` 的具体值。
- 如果使用的是 `UXIX` 域套接字，那么就不断的 `accept` 接受新连接，并且读取新连接发来的数据
- 如果是 `pipefd`，那么就从管道中读取新数据。
- 获取后的数据调用 `onTask` 回调函数
- 消费消息之后，向 `stream` 中发送空数据，告知 `worker` 进程已消费，并且关闭新连接。


```
static int swProcessPool_worker_loop(swProcessPool *pool, swWorker *worker)
{
    struct
    {
        long mtype;
        swEventData buf;
    } out;

    int n = 0, ret;
    int task_n, worker_task_always = 0;

    if (pool->max_request < 1)
    {
        task_n = 1;
        worker_task_always = 1;
    }
    else
    {
        task_n = pool->max_request;
        if (pool->max_request > 10)
        {
            n = swoole_system_random(1, pool->max_request / 2);
            if (n > 0)
            {
                task_n += n;
            }
        }
    }

    /**
     * Use from_fd save the task_worker->id
     */
    out.buf.info.from_fd = worker->id;

    if (pool->dispatch_mode == SW_DISPATCH_QUEUE)
    {
        out.mtype = 0;
    }
    else
    {
        out.mtype = worker->id + 1;
    }

    while (SwooleG.running > 0 && task_n > 0)
    {
        /**
         * fetch task
         */
        if (pool->use_msgqueue)
        {
            n = swMsgQueue_pop(pool->queue, (swQueue_data *) &out, sizeof(out.buf));
            if (n < 0 && errno != EINTR)
            {
                swSysError("[Worker#%d] msgrcv() failed.", worker->id);
                break;
            }
        }
        else if (pool->use_socket)
        {
            int fd = accept(pool->stream->socket, NULL, NULL);
            if (fd < 0)
            {
                if (errno == EAGAIN || errno == EINTR)
                {
                    continue;
                }
                else
                {
                    swSysError("accept(%d) failed.", pool->stream->socket);
                    break;
                }
            }

            n = swStream_recv_blocking(fd, (void*) &out.buf, sizeof(out.buf));
            if (n == SW_CLOSE)
            {
                close(fd);
                continue;
            }
            pool->stream->last_connection = fd;
        }
        else
        {
            n = read(worker->pipe_worker, &out.buf, sizeof(out.buf));
            if (n < 0 && errno != EINTR)
            {
                swSysError("[Worker#%d] read(%d) failed.", worker->id, worker->pipe_worker);
            }
        }

        /**
         * timer
         */
        if (n < 0)
        {
            if (errno == EINTR && SwooleG.signal_alarm)
            {
                alarm_handler: SwooleG.signal_alarm = 0;
                swTimer_select(&SwooleG.timer);
            }
            continue;
        }

        /**
         * do task
         */
        worker->status = SW_WORKER_BUSY;
        worker->request_time = time(NULL);
        ret = pool->onTask(pool, &out.buf);
        worker->status = SW_WORKER_IDLE;
        worker->request_time = 0;
        worker->traced = 0;

        if (pool->use_socket && pool->stream->last_connection > 0)
        {
            int _end = 0;
            swSocket_write_blocking(pool->stream->last_connection, (void *) &_end, sizeof(_end));
            close(pool->stream->last_connection);
            pool->stream->last_connection = 0;
        }

        /**
         * timer
         */
        if (SwooleG.signal_alarm)
        {
            goto alarm_handler;
        }

        if (ret >= 0 && !worker_task_always)
        {
            task_n--;
        }
    }
    return SW_OK;
}


```

## `sendMessage` 函数

- `sendMessage` 函数用于 `worker` 进程向其他 `task` 进程发送消息
- 函数首先从参数中获取 `message` 和 `worker_id`
- 调用 `php_swoole_task_pack` 将 `message` 的数据存储到 `buf` 对象中。
- 调用 `swWorker_send2worker` 发送数据给其他 `worker` 进程


```
PHP_METHOD(swoole_server, sendMessage)
{
    swEventData buf;

    zval *message;
    long worker_id = -1;

    swServer *serv = swoole_get_object(getThis());

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zl", &message, &worker_id) == FAILURE)
    {
        return;
    }

    if (php_swoole_task_pack(&buf, message TSRMLS_CC) < 0)
    {
        RETURN_FALSE;
    }

    buf.info.type = SW_EVENT_PIPE_MESSAGE;
    buf.info.from_id = SwooleWG.id;

    swWorker *to_worker = swServer_get_worker(serv, worker_id);
    SW_CHECK_RETURN(swWorker_send2worker(to_worker, &buf, sizeof(buf.info) + buf.info.len, SW_PIPE_MASTER | SW_PIPE_NONBLOCK));
}
```

![](http://owql68l6p.bkt.clouddn.com/sendMessage.png)

### `php_swoole_task_pack` 函数

- 如果发送的消息是字符串，那么字符串赋值给 `task_data_str`
- 如果发送的消息不是字符串，那么需要进行序列化。如果开启快速序列化，调用 `php_swoole_serialize` 方法进行序列化；否则，调用 `sw_php_var_serialize` 进行序列化。
- 如果数据过大，那么调用 `swTaskWorker_large_pack` 将消息写入临时文件；否则赋值给 `task->data`


```
#define swTask_type(task)                  ((task)->info.from_fd)

int php_swoole_task_pack(swEventData *task, zval *data TSRMLS_DC)
{
    smart_str serialized_data = { 0 };
    php_serialize_data_t var_hash;
#if PHP_MAJOR_VERSION >= 7
    zend_string *serialized_string = NULL;
#endif

    task->info.type = SW_EVENT_TASK;
    task->info.fd = php_swoole_task_id++;

    task->info.from_id = SwooleWG.id;
    swTask_type(task) = 0;

    char *task_data_str;
    int task_data_len = 0;
  
    if (SW_Z_TYPE_P(data) != IS_STRING)
    {
        //serialize
        swTask_type(task) |= SW_TASK_SERIALIZE;

#if PHP_MAJOR_VERSION >= 7
        if (SWOOLE_G(fast_serialize))
        {
            serialized_string = php_swoole_serialize(data);
            task_data_str = serialized_string->val;
            task_data_len = serialized_string->len;
        }
        else
#endif
        {
            PHP_VAR_SERIALIZE_INIT(var_hash);
            sw_php_var_serialize(&serialized_data, data, &var_hash TSRMLS_CC);
            PHP_VAR_SERIALIZE_DESTROY(var_hash);

            if (!serialized_data.s)
            {
                return -1;
            }
            task_data_str = serialized_data.s->val;
            task_data_len = serialized_data.s->len;
#endif
        }
    }
    else
    {
        task_data_str = Z_STRVAL_P(data);
        task_data_len = Z_STRLEN_P(data);
    }

    if (task_data_len >= SW_IPC_MAX_SIZE - sizeof(task->info))
    {
        if (swTaskWorker_large_pack(task, task_data_str, task_data_len) < 0)
        {
            swoole_php_fatal_error(E_WARNING, "large task pack failed.");
            task->info.fd = SW_ERR;
            task->info.len = 0;
        }
    }
    else
    {
        memcpy(task->data, task_data_str, task_data_len);
        task->info.len = task_data_len;
    }

#if PHP_MAJOR_VERSION >= 7
    if (SWOOLE_G(fast_serialize) && serialized_string)
    {
        zend_string_release(serialized_string);
    }
    else
#endif
    {
        smart_str_free(&serialized_data);
    }
    return task->info.fd;
}

int swTaskWorker_large_pack(swEventData *task, void *data, int data_len)
{
    swPackage_task pkg;
    bzero(&pkg, sizeof(pkg));

    memcpy(pkg.tmpfile, SwooleG.task_tmpdir, SwooleG.task_tmpdir_len);

    //create temp file
    int tmp_fd = swoole_tmpfile(pkg.tmpfile);
    if (tmp_fd < 0)
    {
        return SW_ERR;
    }

    //write to file
    if (swoole_sync_writefile(tmp_fd, data, data_len) <= 0)
    {
        swWarn("write to tmpfile failed.");
        return SW_ERR;
    }

    task->info.len = sizeof(swPackage_task);
    //use tmp file
    swTask_type(task) |= SW_TASK_TMPFILE;

    pkg.length = data_len;
    memcpy(task->data, &pkg, sizeof(swPackage_task));
    close(tmp_fd);
    return SW_OK;
}
```


### `swWorker_send2worker` 函数

`swWorker_send2worker` 函数负责向 `task` 进程发送消息。可以看到 `sendMessage` 函数并不支持 `stream` 模式。


```
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

    //message-queue
    if (dst_worker->pool->use_msgqueue)
    {
        struct
        {
            long mtype;
            swEventData buf;
        } msg;

        msg.mtype = dst_worker->id + 1;
        memcpy(&msg.buf, buf, n);

        return swMsgQueue_push(dst_worker->pool->queue, (swQueue_data *) &msg, n);
    }

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

![](http://owql68l6p.bkt.clouddn.com/swoole_server1.png)

## `swoole_server->task` 函数

- 除了使用 `sendMessage`/`onPipeMessage` 发送消息之外，还可以使用 `task`/`finish` 向 `task` 进程发送异步任务。
- 类似于 `sendMessage`，函数首先将 `data` 利用 `php_swoole_task_pack` 进行序列化
- 利用 `buf.info.fd` 将 `onFinish` 异步回调函数保存到 `task_callbacks` 中
- 使用 `swProcessPool_dispatch` 将消息传递给 `task` 进程

```
PHP_METHOD(swoole_server, task)
{
    swEventData buf;
    zval *data;
    zval *callback = NULL;

    zend_long dst_worker_id = -1;

    swServer *serv = swoole_get_object(getThis());

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|lz", &data, &dst_worker_id, &callback) == FAILURE)
    {
        return;
    }
#endif

    if (php_swoole_task_pack(&buf, data TSRMLS_CC) < 0)
    {
        RETURN_FALSE;
    }

    if (callback && !ZVAL_IS_NULL(callback))
    {
#ifdef PHP_SWOOLE_CHECK_CALLBACK
        char *func_name = NULL;
        if (!sw_zend_is_callable(callback, 0, &func_name TSRMLS_CC))
        {
            swoole_php_fatal_error(E_WARNING, "function '%s' is not callable", func_name);
            efree(func_name);
            return;
        }
        efree(func_name);
#endif
        swTask_type(&buf) |= SW_TASK_CALLBACK;
        sw_zval_add_ref(&callback);
        swHashMap_add_int(task_callbacks, buf.info.fd, sw_zval_dup(callback));
    }

    swTask_type(&buf) |= SW_TASK_NONBLOCK;

    int _dst_worker_id = (int) dst_worker_id;
    if (swProcessPool_dispatch(&serv->gs->task_workers, &buf, &_dst_worker_id) >= 0)
    {
        sw_atomic_fetch_add(&serv->stats->tasking_num, 1);
        RETURN_LONG(buf.info.fd);
    }
    else
    {
        RETURN_FALSE;
    }
}
```

### `swProcessPool_dispatch` 函数

- 发送给 `task` 进程后，如果使用的是 `stream` 模式，那么可以直接向 `UNXI` 域套接字发送数据即可。
- 如果 `dst_worker_id` 为 -1，那么就调用 `swProcessPool_schedule` 选取空闲的 `task` 进程
- 调用 `swWorker_send2worker` 发送数据给 `worker` 进程。


```
int swProcessPool_dispatch(swProcessPool *pool, swEventData *data, int *dst_worker_id)
{
    int ret = 0;
    swWorker *worker;

    if (pool->use_socket)
    {
        swStream *stream = swStream_new(pool->stream->socket_file, 0, SW_SOCK_UNIX_STREAM);
        if (stream == NULL)
        {
            return SW_ERR;
        }
        stream->response = NULL;
        stream->session_id = 0;
        if (swStream_send(stream, (char*) data, sizeof(data->info) + data->info.len) < 0)
        {
            stream->cancel = 1;
            return SW_ERR;
        }
        return SW_OK;
    }

    if (*dst_worker_id < 0)
    {
        *dst_worker_id = swProcessPool_schedule(pool);
    }

    *dst_worker_id += pool->start_id;
    worker = swProcessPool_get_worker(pool, *dst_worker_id);

    int sendn = sizeof(data->info) + data->info.len;
    ret = swWorker_send2worker(worker, data, sendn, SW_PIPE_MASTER | SW_PIPE_NONBLOCK);

    if (ret >= 0)
    {
        sw_atomic_fetch_add(&worker->tasking_num, 1);
    }
    else
    {
        swWarn("send %d bytes to worker#%d failed.", sendn, *dst_worker_id);
    }

    return ret;
}

static sw_inline int swProcessPool_schedule(swProcessPool *pool)
{
    if (pool->dispatch_mode == SW_DISPATCH_QUEUE)
    {
        return 0;
    }

    int i, target_worker_id = 0;
    int run_worker_num = pool->run_worker_num;

    for (i = 0; i < run_worker_num + 1; i++)
    {
        target_worker_id = sw_atomic_fetch_add(&pool->round_id, 1) % run_worker_num;
        if (pool->workers[target_worker_id].status == SW_WORKER_IDLE)
        {
            break;
        }
    }
    return target_worker_id;
}
```

## `taskWait` 函数

`taskWait` 函数是同步投递任务的函数，该函数利用 `swProcessPool_dispatch_blocking` 投递任务之后，会不断读取 `serv->task_notify`，知道获取返回的数据。

```
PHP_METHOD(swoole_server, taskwait)
{
    swEventData buf;
    zval *data;

    double timeout = SW_TASKWAIT_TIMEOUT;
    long dst_worker_id = -1;

    swServer *serv = swoole_get_object(getThis());

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|dl", &data, &timeout, &dst_worker_id) == FAILURE)
    {
        return;
    }

    if (php_swoole_task_pack(&buf, data TSRMLS_CC) < 0)
    {
        RETURN_FALSE;
    }
    
    int task_id = buf.info.fd;

    uint64_t notify;
    swEventData *task_result = &(serv->task_result[SwooleWG.id]);
    bzero(task_result, sizeof(swEventData));
    swPipe *task_notify_pipe = &serv->task_notify[SwooleWG.id];
    int efd = task_notify_pipe->getFd(task_notify_pipe, 0);

    //clear history task
    while (read(efd, &notify, sizeof(notify)) > 0);

    int _dst_worker_id = (int) dst_worker_id;
    if (swProcessPool_dispatch_blocking(&serv->gs->task_workers, &buf, &_dst_worker_id) >= 0)
    {
        sw_atomic_fetch_add(&serv->stats->tasking_num, 1);
        task_notify_pipe->timeout = timeout;
        while(1)
        {
            if (task_notify_pipe->read(task_notify_pipe, &notify, sizeof(notify)) > 0)
            {
                if (task_result->info.fd != task_id)
                {
                    continue;
                }
                zval *task_notify_data = php_swoole_task_unpack(task_result TSRMLS_CC);
                RETVAL_ZVAL(task_notify_data, 0, 0);
                break;
            }
        }
    }
    RETURN_FALSE;
}

```

### `swProcessPool_dispatch_blocking` 函数

`swProcessPool_dispatch_blocking` 函数与 `swProcessPool_dispatch` 函数唯一的不同在于调用 `swWorker_send2worker` 的时候并没有使用 `SW_PIPE_NONBLOCK` 选项。

```
int swProcessPool_dispatch_blocking(swProcessPool *pool, swEventData *data, int *dst_worker_id)
{
    int ret = 0;
    int sendn = sizeof(data->info) + data->info.len;

    if (pool->use_socket)
    {
        swClient _socket;
        if (swClient_create(&_socket, SW_SOCK_UNIX_STREAM, SW_SOCK_SYNC) < 0)
        {
            return SW_ERR;
        }
        if (_socket.connect(&_socket, pool->stream->socket_file, 0, -1, 0) < 0)
        {
            return SW_ERR;
        }
        if (_socket.send(&_socket, (void*) data, sendn, 0) < 0)
        {
            return SW_ERR;
        }
        _socket.close(&_socket);
        return SW_OK;
    }

    if (*dst_worker_id < 0)
    {
        *dst_worker_id = swProcessPool_schedule(pool);
    }

    *dst_worker_id += pool->start_id;
    swWorker *worker = swProcessPool_get_worker(pool, *dst_worker_id);

    ret = swWorker_send2worker(worker, data, sendn, SW_PIPE_MASTER);
    if (ret < 0)
    {
        swWarn("send %d bytes to worker#%d failed.", sendn, *dst_worker_id);
    }
    else
    {
        sw_atomic_fetch_add(&worker->tasking_num, 1);
    }

    return ret;
}

```

### `php_swoole_task_unpack` 函数

```
zval* php_swoole_task_unpack(swEventData *task_result TSRMLS_DC)
{
    zval *result_data, *result_unserialized_data;
    char *result_data_str;
    int result_data_len = 0;
    php_unserialize_data_t var_hash;
    swString *large_packet;

    /**
     * Large result package
     */
    if (swTask_type(task_result) & SW_TASK_TMPFILE)
    {
        large_packet = swTaskWorker_large_unpack(task_result);
        /**
         * unpack failed
         */
        if (large_packet == NULL)
        {
            return NULL;
        }
        result_data_str = large_packet->str;
        result_data_len = large_packet->length;
    }
    else
    {
        result_data_str = task_result->data;
        result_data_len = task_result->info.len;
    }

    if (swTask_type(task_result) & SW_TASK_SERIALIZE)
    {
        SW_ALLOC_INIT_ZVAL(result_unserialized_data);

#if PHP_MAJOR_VERSION >= 7
        if (SWOOLE_G(fast_serialize))
        {
            if (php_swoole_unserialize(result_data_str, result_data_len, result_unserialized_data, NULL, 0))
            {
                result_data = result_unserialized_data;
            }
            else
            {
                SW_ALLOC_INIT_ZVAL(result_data);
                SW_ZVAL_STRINGL(result_data, result_data_str, result_data_len, 1);
            }
        }
        else
#endif
        {
            PHP_VAR_UNSERIALIZE_INIT(var_hash);
            //unserialize success
            if (sw_php_var_unserialize(&result_unserialized_data, (const unsigned char ** ) &result_data_str,
                    (const unsigned char * ) (result_data_str + result_data_len), &var_hash TSRMLS_CC))
            {
                result_data = result_unserialized_data;
            }
            //failed
            else
            {
                SW_ALLOC_INIT_ZVAL(result_data);
                SW_ZVAL_STRINGL(result_data, result_data_str, result_data_len, 1);
            }
            PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
        }
    }
    else
    {
        SW_ALLOC_INIT_ZVAL(result_data);
        SW_ZVAL_STRINGL(result_data, result_data_str, result_data_len, 1);
    }
    return result_data;
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

## `taskWaitMulti` 函数

- `taskWaitMulti` 函数用于同时投递多个任务
- 函数首先创建临时文件，循环 `tasks` 并调用 `swProcessPool_dispatch_blocking` 发送同步任务。
- 不断读取 `task_notify_pipe` 直到收到全部消息或者超时
- 读取临时文件内容，并解析文件中各个任务的返回值


```
#define SW_TASK_TMP_FILE                 "/tmp/swoole.task.XXXXXX"

PHP_METHOD(swoole_server, taskWaitMulti)
{
    swEventData buf;
    zval *tasks;
    zval *task;
    double timeout = SW_TASKWAIT_TIMEOUT;

    swServer *serv = swoole_get_object(getThis());

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|d", &tasks, &timeout) == FAILURE)
    {
        return;
    }

    array_init(return_value);

    int dst_worker_id;
    int task_id;
    int i = 0;
    int n_task = Z_ARRVAL_P(tasks)->nNumOfElements;

    int list_of_id[SW_MAX_CONCURRENT_TASK];

    uint64_t notify;
    swEventData *task_result = &(serv->task_result[SwooleWG.id]);
    bzero(task_result, sizeof(swEventData));
    swPipe *task_notify_pipe = &serv->task_notify[SwooleWG.id];
    swWorker *worker = swServer_get_worker(serv, SwooleWG.id);

    char _tmpfile[sizeof(SW_TASK_TMP_FILE)] = SW_TASK_TMP_FILE;
    int _tmpfile_fd = swoole_tmpfile(_tmpfile);
    if (_tmpfile_fd < 0)
    {
        RETURN_FALSE;
    }
    close(_tmpfile_fd);
    int *finish_count = (int *) task_result->data;

    worker->lock.lock(&worker->lock);
    *finish_count = 0;
    memcpy(task_result->data + 4, _tmpfile, sizeof(_tmpfile));
    worker->lock.unlock(&worker->lock);

    //clear history task
    int efd = task_notify_pipe->getFd(task_notify_pipe, 0);
    while (read(efd, &notify, sizeof(notify)) > 0);

    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(tasks), task)
        task_id = php_swoole_task_pack(&buf, task TSRMLS_CC);

        swTask_type(&buf) |= SW_TASK_WAITALL;
        dst_worker_id = -1;
        if (swProcessPool_dispatch_blocking(&serv->gs->task_workers, &buf, &dst_worker_id) < 0)
        {
            swoole_php_fatal_error(E_WARNING, "taskwait failed. Error: %s[%d]", strerror(errno), errno);
            task_id = -1;
            fail:
            add_index_bool(return_value, i, 0);
            n_task --;
        }
        sw_atomic_fetch_add(&serv->stats->tasking_num, 1);
        list_of_id[i] = task_id;
        i++;
    SW_HASHTABLE_FOREACH_END();

    if (n_task == 0)
    {
        SwooleG.error = SW_ERROR_TASK_DISPATCH_FAIL;
        RETURN_FALSE;
    }

    double _now = swoole_microtime();
    while (n_task > 0)
    {
        task_notify_pipe->timeout = timeout;
        int ret = task_notify_pipe->read(task_notify_pipe, &notify, sizeof(notify));
        if (ret > 0 && *finish_count < n_task)
        {
            if (swoole_microtime() - _now < timeout)
            {
                continue;
            }
        }
        break;
    }

    worker->lock.lock(&worker->lock);
    swString *content = swoole_file_get_contents(_tmpfile);
    worker->lock.unlock(&worker->lock);

    if (content == NULL)
    {
        RETURN_FALSE;
    }

    swEventData *result;
    zval *zdata;
    int j;

    do
    {
        result = (swEventData *) (content->str + content->offset);
        task_id = result->info.fd;
        zdata = php_swoole_task_unpack(result TSRMLS_CC);
        if (zdata == NULL)
        {
            goto next;
        }
        for (j = 0; j < Z_ARRVAL_P(tasks)->nNumOfElements; j++)
        {
            if (list_of_id[j] == task_id)
            {
                break;
            }
        }
        add_index_zval(return_value, j, zdata);
        efree(zdata);
        next: content->offset += sizeof(swDataHead) + result->info.len;
    }
    while(content->offset < content->length);
    //free memory
    swString_free(content);
    //delete tmp file
    unlink(_tmpfile);
}


```


## `pool->onTask` 函数

- `task` 进程接受到消息之后，要判断消息来源于 `sendMessage` 还是 `SW_TASK_CALLBACK`


```
int swTaskWorker_onTask(swProcessPool *pool, swEventData *task)
{
    int ret = SW_OK;
    swServer *serv = pool->ptr;
    current_task = task;

    if (task->info.type == SW_EVENT_PIPE_MESSAGE)
    {
        serv->onPipeMessage(serv, task);
    }
    else
    {
        ret = serv->onTask(serv, task);
    }

    return ret;
}
```

### `php_swoole_onPipeMessage` 函数

`php_swoole_onPipeMessage` 函数就是 `serv->onPipeMessage(serv, task)` 函数，该函数主要功能就是调用回调函数 `onPipeMessage`


```
static void php_swoole_onPipeMessage(swServer *serv, swEventData *req)
{
    SWOOLE_GET_TSRMLS;

    zval *zserv = (zval *) serv->ptr2;
    zval *zworker_id;
    zval *retval = NULL;

    SW_MAKE_STD_ZVAL(zworker_id);
    ZVAL_LONG(zworker_id, (long) req->info.from_id);

    zval *zdata = php_swoole_task_unpack(req TSRMLS_CC);

    {
        zval **args[3];
        args[0] = &zserv;
        args[1] = &zworker_id;
        args[2] = &zdata;

        if (sw_call_user_function_fast(php_sw_server_callbacks[SW_SERVER_CB_onPipeMessage], php_sw_server_caches[SW_SERVER_CB_onPipeMessage], &retval, 3, args TSRMLS_CC) == FAILURE)
        {
            swoole_php_fatal_error(E_WARNING, "onPipeMessage handler error.");
        }
    }
}
```

### `php_swoole_onTask` 函数

![](http://owql68l6p.bkt.clouddn.com/onTask.png)

本函数就是 `serv->onTask(serv, task)` 所调用的函数，该函数最重要的功能是调用 `onTask` 回调函数，回调函数结束之后调用 `php_swoole_task_finish` 函数向 `worker` 进程发送已结束信息。


```
static int php_swoole_onTask(swServer *serv, swEventData *req)
{
    zval *zserv = (zval *) serv->ptr2;
    zval **args[4];

    zval *zfd;
    zval *zfrom_id;

    sw_atomic_fetch_sub(&serv->stats->tasking_num, 1);

    zval *retval = NULL;

    SWOOLE_GET_TSRMLS;

    SW_MAKE_STD_ZVAL(zfd);
    ZVAL_LONG(zfd, (long) req->info.fd);

    SW_MAKE_STD_ZVAL(zfrom_id);
    ZVAL_LONG(zfrom_id, (long) req->info.from_id);

    zval *zdata = php_swoole_task_unpack(req TSRMLS_CC);
    if (zdata == NULL)
    {
        return SW_ERR;
    }

    args[0] = &zserv;
    args[1] = &zfd;
    args[2] = &zfrom_id;
    args[3] = &zdata;

    zend_fcall_info_cache *fci_cache = php_sw_server_caches[SW_SERVER_CB_onTask];
    if (sw_call_user_function_fast(php_sw_server_callbacks[SW_SERVER_CB_onTask], fci_cache, &retval, 4, args TSRMLS_CC) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onTask handler error.");
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    sw_zval_ptr_dtor(&zfd);
    sw_zval_ptr_dtor(&zfrom_id);
    sw_zval_free(zdata);

    if (retval)
    {
        if (SW_Z_TYPE_P(retval) != IS_NULL)
        {
            php_swoole_task_finish(serv, retval TSRMLS_CC);
        }
        sw_zval_ptr_dtor(&retval);
    }

    return SW_OK;
}
```

### `php_swoole_task_finish` 函数

`php_swoole_task_finish` 函数主要用于告知 `worker` 进程投递的任务已完成。首先需要序列化参数，然后调用 `swTaskWorker_finish` 函数发送消息。

```
static int php_swoole_task_finish(swServer *serv, zval *data TSRMLS_DC)
{
    int flags = 0;
    smart_str serialized_data = {0};
    php_serialize_data_t var_hash;
    char *data_str;
    int data_len = 0;
    int ret;

#if PHP_MAJOR_VERSION >= 7
    zend_string *serialized_string = NULL;
#endif

    //need serialize
    if (SW_Z_TYPE_P(data) != IS_STRING)
    {
        //serialize
        flags |= SW_TASK_SERIALIZE;
#if PHP_MAJOR_VERSION >= 7
        if (SWOOLE_G(fast_serialize))
        {
            serialized_string = php_swoole_serialize(data);
            data_str = serialized_string->val;
            data_len = serialized_string->len;
        }
        else
#endif
        {
            PHP_VAR_SERIALIZE_INIT(var_hash);
            sw_php_var_serialize(&serialized_data, data, &var_hash TSRMLS_CC);
            PHP_VAR_SERIALIZE_DESTROY(var_hash);
#if PHP_MAJOR_VERSION<7
            data_str = serialized_data.c;
            data_len = serialized_data.len;
#else
            data_str = serialized_data.s->val;
            data_len = serialized_data.s->len;
#endif
        }
    }
    else
    {
        data_str = Z_STRVAL_P(data);
        data_len = Z_STRLEN_P(data);
    }

    ret = swTaskWorker_finish(serv, data_str, data_len, flags);
#if PHP_MAJOR_VERSION >= 7
    if (SWOOLE_G(fast_serialize) && serialized_string)
    {
        zend_string_release(serialized_string);
    }
    else
#endif
    {
        smart_str_free(&serialized_data);
    }
    return ret;
}

```

### `swTaskWorker_finish` 函数

- 如果是异步投递任务的话，本函数会调用 `swWorker_send2worker` 函数发送消息。如果使用 `stream` 模式，会向 `worker->pool->stream->last_connection` 这个套接字写入；如果数据量过大，会采用临时文件；
- 如果是使用 `taskWaitMulti` 同步投递任务的话，将消息写入 `serv->task_result` 中的临时文件中。值得注意的是，消息有可能存放在了 `SwooleG.task_tmpdir` 临时文件中，这时候存入 `serv->task_result` 中的临时文件中的仅仅是文件名而不是具体内容。
- 如果使用的是 `taskWait` 同步投递任务的话，将数据放入 `serv->task_result` 中，或者放入 `SwooleG.task_tmpdir` 指定的临时文件中。向 `serv->task_notify` 发送消息，告知 `worker` 进行 `task` 已消费完毕。


```
int swTaskWorker_finish(swServer *serv, char *data, int data_len, int flags)
{
    swEventData buf;
    if (!current_task)
    {
        swWarn("cannot use finish in worker");
        return SW_ERR;
    }
    if (serv->task_worker_num < 1)
    {
        swWarn("cannot use task/finish, because no set serv->task_worker_num.");
        return SW_ERR;
    }
	if (current_task->info.type == SW_EVENT_PIPE_MESSAGE)
	{
		swWarn("task/finish is not supported in onPipeMessage callback.");
		return SW_ERR;
	}

    uint16_t source_worker_id = current_task->info.from_id;
    swWorker *worker = swServer_get_worker(serv, source_worker_id);

    if (worker == NULL)
    {
        swWarn("invalid worker_id[%d].", source_worker_id);
        return SW_ERR;
    }

    int ret;
    //for swoole_server_task
    if (swTask_type(current_task) & SW_TASK_NONBLOCK)
    {
        buf.info.type = SW_EVENT_FINISH;
        buf.info.fd = current_task->info.fd;
        //callback function
        if (swTask_type(current_task) & SW_TASK_CALLBACK)
        {
            flags |= SW_TASK_CALLBACK;
        }
        else if (swTask_type(current_task) & SW_TASK_COROUTINE)
        {
            flags |= SW_TASK_COROUTINE;
        }
        swTask_type(&buf) = flags;

        //write to file
        if (data_len >= SW_IPC_MAX_SIZE - sizeof(buf.info))
        {
            if (swTaskWorker_large_pack(&buf, data, data_len) < 0 )
            {
                swWarn("large task pack failed()");
                return SW_ERR;
            }
        }
        else
        {
            memcpy(buf.data, data, data_len);
            buf.info.len = data_len;
        }

        if (worker->pool->use_socket && worker->pool->stream->last_connection > 0)
        {
            int32_t _len = htonl(data_len);
            ret = swSocket_write_blocking(worker->pool->stream->last_connection, (void *) &_len, sizeof(_len));
            if (ret > 0)
            {
                ret = swSocket_write_blocking(worker->pool->stream->last_connection, data, data_len);
            }
        }
        else
        {
            ret = swWorker_send2worker(worker, &buf, sizeof(buf.info) + buf.info.len, SW_PIPE_MASTER);
        }
    }
    else
    {
        uint64_t flag = 1;

        /**
         * Use worker shm store the result
         */
        swEventData *result = &(serv->task_result[source_worker_id]);
        swPipe *task_notify_pipe = &(serv->task_notify[source_worker_id]);

        //lock worker
        worker->lock.lock(&worker->lock);

        if (swTask_type(current_task) & SW_TASK_WAITALL)
        {
            sw_atomic_t *finish_count = (sw_atomic_t*) result->data;
            char *_tmpfile = result->data + 4;
            int fd = open(_tmpfile, O_APPEND | O_WRONLY);
            if (fd >= 0)
            {
                buf.info.type = SW_EVENT_FINISH;
                buf.info.fd = current_task->info.fd;
                swTask_type(&buf) = flags;
                //result pack
                if (data_len >= SW_IPC_MAX_SIZE - sizeof(buf.info))
                {
                    if (swTaskWorker_large_pack(&buf, data, data_len) < 0)
                    {
                        swWarn("large task pack failed()");
                        buf.info.len = 0;
                    }
                }
                else
                {
                    buf.info.len = data_len;
                    memcpy(buf.data, data, data_len);
                }
                //write to tmpfile
                if (swoole_sync_writefile(fd, &buf, sizeof(buf.info) + buf.info.len) < 0)
                {
                    swSysError("write(%s, %ld) failed.", result->data, sizeof(buf.info) + buf.info.len);
                }
                sw_atomic_fetch_add(finish_count, 1);
                close(fd);
            }
        }
        else
        {
            result->info.type = SW_EVENT_FINISH;
            result->info.fd = current_task->info.fd;
            swTask_type(result) = flags;

            if (data_len >= SW_IPC_MAX_SIZE - sizeof(buf.info))
            {
                if (swTaskWorker_large_pack(result, data, data_len) < 0)
                {
                    //unlock worker
                    worker->lock.unlock(&worker->lock);
                    swWarn("large task pack failed()");
                    return SW_ERR;
                }
            }
            else
            {
                memcpy(result->data, data, data_len);
                result->info.len = data_len;
            }
        }

        //unlock worker
        worker->lock.unlock(&worker->lock);

        while (1)
        {
            ret = task_notify_pipe->write(task_notify_pipe, &flag, sizeof(flag));
#ifdef HAVE_KQUEUE
            if (ret < 0 && (errno == EAGAIN || errno == ENOBUFS))
#else
            if (ret < 0 && errno == EAGAIN)
#endif
            {
                if (swSocket_wait(task_notify_pipe->getFd(task_notify_pipe, 1), -1, SW_EVENT_WRITE) == 0)
                {
                    continue;
                }
            }
            break;
        }
    }
    if (ret < 0)
    {
        swWarn("TaskWorker: send result to worker failed. Error: %s[%d]", strerror(errno), errno);
    }
    return ret;
}
```

## `php_swoole_onFinish` 函数

- 异步投递任务结束后，`task` 进程会调用 `swWorker_send2worker` 给 `worker` 进程发送消息，`worker` 进程进而调用 `swWorker_onTask`。
- 我们可以看到，`worker` 函数会调用 `serv->onFinish` 函数，也就是 `php_swoole_onFinish` 函数。
- `php_swoole_onFinish` 函数主要用于调用 `onFinish` 回调函数。`onFinish` 回调函数有些是 `swoole_server->task` 函数指定，存储在 `task_callbacks` 中；有些是 `swoole_server->onFinish` 指定，存储在 `php_sw_server_callbacks[SW_SERVER_CB_onFinish]` 中。

```
int swWorker_onTask(swFactory *factory, swEventData *task)
{
    ...
    switch (task->info.type)
    {
        case SW_EVENT_FINISH:
            serv->onFinish(serv, task);
            break;

        case SW_EVENT_PIPE_MESSAGE:
            serv->onPipeMessage(serv, task);
            break;
    }
    ...
}

static int php_swoole_onFinish(swServer *serv, swEventData *req)
{
    zval *zserv = (zval *) serv->ptr2;
    zval **args[3];

    zval *ztask_id;
    zval *zdata;
    zval *retval = NULL;

    SWOOLE_GET_TSRMLS;

    SW_MAKE_STD_ZVAL(ztask_id);
    ZVAL_LONG(ztask_id, (long) req->info.fd);

    zdata = php_swoole_task_unpack(req TSRMLS_CC);

    args[0] = &zserv;
    args[1] = &ztask_id;
    args[2] = &zdata;

    zval *callback = NULL;
    if (swTask_type(req) & SW_TASK_CALLBACK)
    {
        callback = swHashMap_find_int(task_callbacks, req->info.fd);
        if (callback == NULL)
        {
            swTask_type(req) = swTask_type(req) & (~SW_TASK_CALLBACK);
        }
    }
    if (callback == NULL)
    {
        callback = php_sw_server_callbacks[SW_SERVER_CB_onFinish];
    }
    if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 3, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onFinish handler error.");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    sw_zval_ptr_dtor(&ztask_id);
    sw_zval_free(zdata);
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    if (swTask_type(req) & SW_TASK_CALLBACK)
    {
        swHashMap_del_int(task_callbacks, req->info.fd);
        sw_zval_free(callback);
    }
    return SW_OK;
}

```