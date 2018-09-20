# Swoole 源码分析——Server模块之Start

## `Server` 的启动

- 在 `server` 启动之前，`swoole` 首先要调用 `php_swoole_register_callback` 将 `PHP` 的回调函数注册到 `server` 的对象函数中去
- 之后调用 `php_swoole_server_before_start` 创建 `swReactorThread` 数组对象、`workers` 进程池对象
- 最后调用 `swServer_start` 函数创建 `reactor` 线程，`work`、`manager` 等进程，开启事件循环

```c
PHP_METHOD(swoole_server, start)
{
    zval *zobject = getThis();
    int ret;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start > 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is running. unable to execute swoole_server->start.");
        RETURN_FALSE;
    }

    php_swoole_register_callback(serv);

    //-------------------------------------------------------------
    serv->onReceive = php_swoole_onReceive;

    php_swoole_server_before_start(serv, zobject TSRMLS_CC);

    ret = swServer_start(serv);
    if (ret < 0)
    {
        swoole_php_fatal_error(E_ERROR, "failed to start server. Error: %s", sw_error);
        RETURN_LONG(ret);
    }
    RETURN_TRUE;
}

```

![](http://owql68l6p.bkt.clouddn.com/swServer_start.png)

## 注册 `PHP` 回调函数

```c
void php_swoole_register_callback(swServer *serv)
{
    /*
     * optional callback
     */
    if (php_sw_server_callbacks[SW_SERVER_CB_onStart] != NULL)
    {
        serv->onStart = php_swoole_onStart;
    }
    serv->onShutdown = php_swoole_onShutdown;
    /**
     * require callback, set the master/manager/worker PID
     */
    serv->onWorkerStart = php_swoole_onWorkerStart;

    if (php_sw_server_callbacks[SW_SERVER_CB_onWorkerStop] != NULL)
    {
        serv->onWorkerStop = php_swoole_onWorkerStop;
    }
    if (php_sw_server_callbacks[SW_SERVER_CB_onWorkerExit] != NULL)
    {
        serv->onWorkerExit = php_swoole_onWorkerExit;
    }
    /**
     * UDP Packet
     */
    if (php_sw_server_callbacks[SW_SERVER_CB_onPacket] != NULL)
    {
        serv->onPacket = php_swoole_onPacket;
    }
    /**
     * Task Worker
     */
    if (php_sw_server_callbacks[SW_SERVER_CB_onTask] != NULL)
    {
        serv->onTask = php_swoole_onTask;
    }
    if (php_sw_server_callbacks[SW_SERVER_CB_onFinish] != NULL)
    {
        serv->onFinish = php_swoole_onFinish;
    }
    if (php_sw_server_callbacks[SW_SERVER_CB_onWorkerError] != NULL)
    {
        serv->onWorkerError = php_swoole_onWorkerError;
    }
    if (php_sw_server_callbacks[SW_SERVER_CB_onManagerStart] != NULL)
    {
        serv->onManagerStart = php_swoole_onManagerStart;
    }
    if (php_sw_server_callbacks[SW_SERVER_CB_onManagerStop] != NULL)
    {
        serv->onManagerStop = php_swoole_onManagerStop;
    }
    if (php_sw_server_callbacks[SW_SERVER_CB_onPipeMessage] != NULL)
    {
        serv->onPipeMessage = php_swoole_onPipeMessage;
    }
    if (php_sw_server_callbacks[SW_SERVER_CB_onBufferFull] != NULL)
    {
        serv->onBufferFull = php_swoole_onBufferFull;
    }
    if (php_sw_server_callbacks[SW_SERVER_CB_onBufferEmpty] != NULL || serv->send_yield)
    {
        serv->onBufferEmpty = php_swoole_onBufferEmpty;
    }
}

```

## 创建 `reactor` 线程池对象与 `work` 进程池对象

- `php_swoole_server_before_start` 主要调用 `swServer_create` 函数
- `swServer_create` 函数主要任务是 `swReactorThread_create` 创建 `reactor` 多线程

```c
void php_swoole_server_before_start(swServer *serv, zval *zobject TSRMLS_DC)
{
    /**
     * create swoole server
     */
    if (swServer_create(serv) < 0)
    {
        swoole_php_fatal_error(E_ERROR, "failed to create the server. Error: %s", sw_error);
        return;
    }

}

int swServer_create(swServer *serv)
{
    if (SwooleG.main_reactor)
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_MUST_CREATED_BEFORE_CLIENT, "The swoole_server must create before client");
        return SW_ERR;
    }

    SwooleG.factory = &serv->factory;
    serv->factory.ptr = serv;
    /**
     * init current time
     */
    swServer_update_time(serv);

#ifdef SW_REACTOR_USE_SESSION
    serv->session_list = sw_shm_calloc(SW_SESSION_LIST_SIZE, sizeof(swSession));
    if (serv->session_list == NULL)
    {
        swError("sw_shm_calloc(%ld) for session_list failed", SW_SESSION_LIST_SIZE * sizeof(swSession));
        return SW_ERR;
    }
#endif

    if (serv->factory_mode == SW_MODE_SINGLE)
    {
        return swReactorProcess_create(serv);
    }
    else
    {
        return swReactorThread_create(serv);
    }
}
```

### `swReactorThread_create` 创建线程池对象

- 函数首先申请内存构建 `reactor_threads` 用于存储多线程的各种信息，创建 `connection_list` 保存已建立连接的 `socket` 信息
- 利用 `swFactoryThread_create` 创建 `reactor` 多线程

```c
int swReactorThread_create(swServer *serv)
{
    int ret = 0;
    /**
     * init reactor thread pool
     */
    serv->reactor_threads = SwooleG.memory_pool->alloc(SwooleG.memory_pool, (serv->reactor_num * sizeof(swReactorThread)));
    if (serv->reactor_threads == NULL)
    {
        swError("calloc[reactor_threads] fail.alloc_size=%d", (int )(serv->reactor_num * sizeof(swReactorThread)));
        return SW_ERR;
    }

    /**
     * alloc the memory for connection_list
     */
    if (serv->factory_mode == SW_MODE_PROCESS)
    {
        serv->connection_list = sw_shm_calloc(serv->max_connection, sizeof(swConnection));
    }
    else
    {
        serv->connection_list = sw_calloc(serv->max_connection, sizeof(swConnection));
    }

    //create factry object
    if (serv->factory_mode == SW_MODE_PROCESS)
    {
        if (serv->worker_num < 1)
        {
            swError("Fatal Error: serv->worker_num < 1");
            return SW_ERR;
        }
        ret = swFactoryProcess_create(&(serv->factory), serv->worker_num);
    }

    if (ret < 0)
    {
        swError("create factory failed");
        return SW_ERR;
    }
    return SW_OK;
}

```

### `swFactoryProcess_create` 创建进程池对象

```c
int swFactoryProcess_create(swFactory *factory, int worker_num)
{
    swFactoryProcess *object;
    object = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swFactoryProcess));
    if (object == NULL)
    {
        swWarn("[Master] malloc[object] failed");
        return SW_ERR;
    }

    factory->object = object;
    factory->dispatch = swFactoryProcess_dispatch;
    factory->finish = swFactoryProcess_finish;
    factory->start = swFactoryProcess_start;
    factory->notify = swFactoryProcess_notify;
    factory->shutdown = swFactoryProcess_shutdown;
    factory->end = swFactoryProcess_end;

    return SW_OK;
}

```

## `swServer_start` 函数

- `swServer_start` 函数是启动整个 `swoole` 的关键
- `swServer_start_check` 函数用于检查各种回调函数已经被正确设置
- 如果当前 `swoole` 是守护程序(`daemonize`)，那么要设置日志输出目录，调用 `daemon` 函数设置自身进程会话
- 从内存池中申请构建 `worker` 对象，设置全局共享对象 `event_workers`
- 申请 `reactor` 线程的 `buffer_input` 
- 如果存在 `task_worker` 进程，那么申请 `worker` 进程与 `task_worker` 进程用于通讯的 `pipe`
- 如果存在用户 `task` 进程，要设置用户 `task` 进程的 `id`
- `factory->start(factory)` 启动创建 `manager`、`worker`、`task_worker`、`user_task_worker` 进程
- `swServer_signal_init` 进行信号初始化
- `swServer_start_proxy` 创建 `reactor` 多线程，开启事件循环

```c
int swServer_start(swServer *serv)
{
    swFactory *factory = &serv->factory;
    int ret;

    ret = swServer_start_check(serv);
    if (ret < 0)
    {
        return SW_ERR;
    }
    if (SwooleG.hooks[SW_GLOBAL_HOOK_BEFORE_SERVER_START])
    {
        swoole_call_hook(SW_GLOBAL_HOOK_BEFORE_SERVER_START, serv);
    }
    //cann't start 2 servers at the same time, please use process->exec.
    if (!sw_atomic_cmp_set(&serv->gs->start, 0, 1))
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_ONLY_START_ONE, "must only start one server.");
        return SW_ERR;
    }
    //init loggger
    if (SwooleG.log_file)
    {
        swLog_init(SwooleG.log_file);
    }
    //run as daemon
    if (serv->daemonize > 0)
    {
        /**
         * redirect STDOUT to log file
         */
        if (SwooleG.log_fd > STDOUT_FILENO)
        {
            swoole_redirect_stdout(SwooleG.log_fd);
        }
        /**
         * redirect STDOUT_FILENO/STDERR_FILENO to /dev/null
         */
        else
        {
            SwooleG.null_fd = open("/dev/null", O_WRONLY);
            if (SwooleG.null_fd > 0)
            {
                swoole_redirect_stdout(SwooleG.null_fd);
            }
            else
            {
                swoole_error_log(SW_LOG_ERROR, SW_ERROR_SYSTEM_CALL_FAIL, "open(/dev/null) failed. Error: %s[%d]", strerror(errno), errno);
            }
        }

        if (daemon(0, 1) < 0)
        {
            return SW_ERR;
        }
    }

    //master pid
    serv->gs->master_pid = getpid();
    serv->gs->now = serv->stats->start_time = time(NULL);

    serv->send = swServer_tcp_send;
    serv->sendwait = swServer_tcp_sendwait;
    serv->sendfile = swServer_tcp_sendfile;
    serv->close = swServer_tcp_close;

    serv->workers = SwooleG.memory_pool->alloc(SwooleG.memory_pool, serv->worker_num * sizeof(swWorker));
    if (serv->workers == NULL)
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SYSTEM_CALL_FAIL, "gmalloc[server->workers] failed.");
        return SW_ERR;
    }

    /**
     * store to swProcessPool object
     */
    serv->gs->event_workers.workers = serv->workers;
    serv->gs->event_workers.worker_num = serv->worker_num;
    serv->gs->event_workers.use_msgqueue = 0;

    int i;
    for (i = 0; i < serv->worker_num; i++)
    {
        serv->gs->event_workers.workers[i].pool = &serv->gs->event_workers;
    }

#ifdef SW_USE_RINGBUFFER
    for (i = 0; i < serv->reactor_num; i++)
    {
        serv->reactor_threads[i].buffer_input = swRingBuffer_new(SwooleG.serv->buffer_input_size, 1);
        if (!serv->reactor_threads[i].buffer_input)
        {
            return SW_ERR;
        }
    }
#endif

    /*
     * For swoole_server->taskwait, create notify pipe and result shared memory.
     */
    if (serv->task_worker_num > 0 && serv->worker_num > 0)
    {
        serv->task_result = sw_shm_calloc(serv->worker_num, sizeof(swEventData));
        serv->task_notify = sw_calloc(serv->worker_num, sizeof(swPipe));
        for (i = 0; i < serv->worker_num; i++)
        {
            if (swPipeNotify_auto(&serv->task_notify[i], 1, 0))
            {
                return SW_ERR;
            }
        }
    }

    /**
     * user worker process
     */
    if (serv->user_worker_list)
    {
        swUserWorker_node *user_worker;
        i = 0;
        LL_FOREACH(serv->user_worker_list, user_worker)
        {
            user_worker->worker->id = serv->worker_num + serv->task_worker_num + i;
            i++;
        }
    }

    //factory start
    if (factory->start(factory) < 0)
    {
        return SW_ERR;
    }
    //signal Init
    swServer_signal_init(serv);

    //write PID file
    if (serv->pid_file)
    {
        ret = snprintf(SwooleTG.buffer_stack->str, SwooleTG.buffer_stack->size, "%d", getpid());
        swoole_file_put_contents(serv->pid_file, SwooleTG.buffer_stack->str, ret);
    }
    if (serv->factory_mode == SW_MODE_SINGLE)
    {
        ret = swReactorProcess_start(serv);
    }
    else
    {
        ret = swServer_start_proxy(serv);
    }
    swServer_free(serv);
    serv->gs->start = 0;
    //remove PID file
    if (serv->pid_file)
    {
        unlink(serv->pid_file);
    }
    return SW_OK;
}

```

### `daemon`

如果想要进程 `daemon` 化，必要的步骤如下：

- 切换目录为根目录
- 将 `stdin`，`stdout`，`stderr` 重定向到 `/dev/null`
- `fork` 开启一个新进程
- 退出父进程，在子进程中开启一个新的会话

```c
int daemon(int nochdir, int noclose)
{
    pid_t pid;

    if (!nochdir && chdir("/") != 0)
    {
        swWarn("chdir() failed. Error: %s[%d]", strerror(errno), errno);
        return -1;
    }

    if (!noclose)
    {
        int fd = open("/dev/null", O_RDWR);
        if (fd < 0)
        {
            swWarn("open() failed. Error: %s[%d]", strerror(errno), errno);
            return -1;
        }

        if (dup2(fd, 0) < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0)
        {
            close(fd);
            swWarn("dup2() failed. Error: %s[%d]", strerror(errno), errno);
            return -1;
        }

        close(fd);
    }

    pid = fork();
    if (pid < 0)
    {
        swWarn("fork() failed. Error: %s[%d]", strerror(errno), errno);
        return -1;
    }
    if (pid > 0)
    {
        _exit(0);
    }
    if (setsid() < 0)
    {
        swWarn("setsid() failed. Error: %s[%d]", strerror(errno), errno);
        return -1;
    }
    return 0;
}

```

## `factory->start` 开启 `manager`、`work` 进程

- `swServer_get_worker` 函数用于从 `event_workers`
- `swWorker_create` 函数用于初始化 `send_shm`、`lock`
-  `swManager_start` 函数用于启动 `manager` 进程

```c
static int swFactoryProcess_start(swFactory *factory)
{
    int i;
    swServer *serv = factory->ptr;
    swWorker *worker;

    for (i = 0; i < serv->worker_num; i++)
    {
        worker = swServer_get_worker(serv, i);
        if (swWorker_create(worker) < 0)
        {
            return SW_ERR;
        }
    }

    serv->reactor_pipe_num = serv->worker_num / serv->reactor_num;

    //必须先启动manager进程组，否则会带线程fork
    if (swManager_start(factory) < 0)
    {
        swWarn("swFactoryProcess_manager_start failed.");
        return SW_ERR;
    }
    //主进程需要设置为直写模式
    factory->finish = swFactory_finish;
    return SW_OK;
}

static sw_inline swWorker* swServer_get_worker(swServer *serv, uint16_t worker_id)
{
    //Event Worker
    if (worker_id < serv->worker_num)
    {
        return &(serv->gs->event_workers.workers[worker_id]);
    }

    //Task Worker
    uint16_t task_worker_max = serv->task_worker_num + serv->worker_num;
    if (worker_id < task_worker_max)
    {
        return &(serv->gs->task_workers.workers[worker_id - serv->worker_num]);
    }

    //User Worker
    uint16_t user_worker_max = task_worker_max + serv->user_worker_num;
    if (worker_id < user_worker_max)
    {
        return &(serv->user_workers[worker_id - task_worker_max]);
    }

    return NULL;
}

int swWorker_create(swWorker *worker)
{
    /**
     * Create shared memory storage
     */
    worker->send_shm = sw_shm_malloc(SwooleG.serv->buffer_output_size);
    if (worker->send_shm == NULL)
    {
        swWarn("malloc for worker->store failed.");
        return SW_ERR;
    }
    swMutex_create(&worker->lock, 1);

    return SW_OK;
}

```

### `swManager_start` 函数

- 首先需要准备好 `pipes` 作为 `master` 进程与 `worker` 进行的通讯管道
- 设置每个 `worker` 进程的 `pipe_master`(`master` 进程向 `worker` 进程传递消息)、`pipe_worker`(`worker` 进程向 `master` 进程传递消息)
- 如果存在 `task_worker` 进程，需要调用 `swServer_create_task_worker` 函数创建 `serv->gs->task_workers`，之后将对其进行初始化
- 如果存在 `user_workers` 进程，那么就要创建相应的 `serv->user_workers`，并初始化
- 调用 `fork`，启动 `manager` 进程
- 在 `manager` 进程中，调用 `swServer_close_listen_port` 关闭监听的 `socket`
- 对于 `task_worker` 进程，利用 `swProcessPool_start` 启动 `task_worker` 进程
- 对于 `worker` 进程，调用 `swManager_spawn_worker` 启动 `worker` 进程
- 对于 `user_worker` 进程，调用 `swManager_spawn_user_worker` 启动 `user_worker ` 进程
- 调用 `swManager_loop` 进行事件循环，管理 `worker` 等进程

```c
void swServer_store_pipe_fd(swServer *serv, swPipe *p)
{
    int master_fd = p->getFd(p, SW_PIPE_MASTER);

    serv->connection_list[p->getFd(p, SW_PIPE_WORKER)].object = p;
    serv->connection_list[master_fd].object = p;

    if (master_fd > swServer_get_minfd(serv))
    {
        swServer_set_minfd(serv, master_fd);
    }
}

int swManager_start(swFactory *factory)
{
    swFactoryProcess *object = factory->object;
    int i;
    pid_t pid;
    swServer *serv = factory->ptr;

    object->pipes = sw_calloc(serv->worker_num, sizeof(swPipe));
    if (object->pipes == NULL)
    {
        swError("malloc[worker_pipes] failed. Error: %s [%d]", strerror(errno), errno);
        return SW_ERR;
    }

    //worker进程的pipes
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

    //User Worker Process
    if (serv->user_worker_num > 0)
    {
        serv->user_workers = SwooleG.memory_pool->alloc(SwooleG.memory_pool, serv->user_worker_num * sizeof(swWorker));
        if (serv->user_workers == NULL)
        {
            swoole_error_log(SW_LOG_ERROR, SW_ERROR_SYSTEM_CALL_FAIL, "gmalloc[server->user_workers] failed.");
            return SW_ERR;
        }
        swUserWorker_node *user_worker;
        i = 0;
        LL_FOREACH(serv->user_worker_list, user_worker)
        {
            memcpy(&serv->user_workers[i], user_worker->worker, sizeof(swWorker));
            if (swWorker_create(&serv->user_workers[i]) < 0)
            {
                return SW_ERR;
            }
            i++;
        }
    }

    serv->message_box = swChannel_new(65536, sizeof(swWorkerStopMessage), SW_CHAN_LOCK | SW_CHAN_SHM);
    if (serv->message_box == NULL)
    {
        return SW_ERR;
    }

    pid = fork();
    switch (pid)
    {
    //fork manager process
    case 0:
        //wait master process
        SW_START_SLEEP;
        if (serv->gs->start == 0)
        {
            return SW_OK;
        }
        swServer_close_listen_port(serv);

        /**
         * create task worker process
         */
        if (serv->task_worker_num > 0)
        {
            swProcessPool_start(&serv->gs->task_workers);
        }
        /**
         * create worker process
         */
        for (i = 0; i < serv->worker_num; i++)
        {
            //close(worker_pipes[i].pipes[0]);
            pid = swManager_spawn_worker(factory, i);
            if (pid < 0)
            {
                swError("fork() failed.");
                return SW_ERR;
            }
            else
            {
                serv->workers[i].pid = pid;
            }
        }
        /**
         * create user worker process
         */
        if (serv->user_worker_list)
        {
            swUserWorker_node *user_worker;
            LL_FOREACH(serv->user_worker_list, user_worker)
            {
                /**
                 * store the pipe object
                 */
                if (user_worker->worker->pipe_object)
                {
                    swServer_store_pipe_fd(serv, user_worker->worker->pipe_object);
                }
                swManager_spawn_user_worker(serv, user_worker->worker);
            }
        }

        SwooleG.process_type = SW_PROCESS_MANAGER;
        SwooleG.pid = getpid();
        exit(swManager_loop(factory));
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

### `swManager_spawn_worker` 启动 `worker` 进程

```c
static pid_t swManager_spawn_worker(swFactory *factory, int worker_id)
{
    pid_t pid;
    int ret;

    pid = fork();

    //fork() failed
    if (pid < 0)
    {
        swWarn("Fork Worker failed. Error: %s [%d]", strerror(errno), errno);
        return SW_ERR;
    }
    //worker child processor
    else if (pid == 0)
    {
        ret = swWorker_loop(factory, worker_id);
        exit(ret);
    }
    //parent,add to writer
    else
    {
        return pid;
    }
}

```

### `swManager_spawn_user_worker` 启动 `user_worker` 进程

```c
pid_t swManager_spawn_user_worker(swServer *serv, swWorker* worker)
{
    pid_t pid = fork();

    if (pid < 0)
    {
        swWarn("Fork Worker failed. Error: %s [%d]", strerror(errno), errno);
        return SW_ERR;
    }
    //child
    else if (pid == 0)
    {
        SwooleG.process_type = SW_PROCESS_USERWORKER;
        SwooleWG.worker = worker;
        SwooleWG.id = worker->id;
        worker->pid = getpid();
        //close tcp listen socket
        if (serv->factory_mode == SW_MODE_SINGLE)
        {
            swServer_close_port(serv, SW_TRUE);
        }
        serv->onUserWorkerStart(serv, worker);
        exit(0);
    }
    //parent
    else
    {
        if (worker->pid)
        {
            swHashMap_del_int(serv->user_worker_map, worker->pid);
        }
        worker->pid = pid;
        swHashMap_add_int(serv->user_worker_map, pid, worker);
        return pid;
    }
}

```

## `swServer_start_proxy` 开启 `reactor` 多线程

- 直到这个时候，`main_reactor` 才真正的被创建出来，并进行初始化
- 如果当前系统支持 `signalfd`，那么就要调用 `swSignalfd_setup` 函数对 `signalfd` 进行初始化
- 对于 `listen_list` 里面的 `tcp` 监听 `socket`，需要调用 `swPort_listen` 进行监听
- `stream_fd` 是为了 `worker` 准备的，对于 `master` 进程，直接关闭即可
- `swReactorThread_start` 函数用于创建 `reactor` 线程
- 如果系统不支持时间轮算法，那么就要利用 `swHeartbeatThread_start` 启动一个进程，专门踢掉空闲的连接
- 对于定时任务，利用 `swTimer_init` 初始化 `SwooleG.timer`
- 设置 `master` 主线程的线程特有数据
- 利用 `main_reactor->wait` 等待新的连接

```c
static int swServer_start_proxy(swServer *serv)
{
    int ret;
    swReactor *main_reactor = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swReactor));

    ret = swReactor_create(main_reactor, SW_REACTOR_MAXEVENTS);
    if (ret < 0)
    {
        swWarn("Reactor create failed");
        return SW_ERR;
    }

    main_reactor->thread = 1;
    main_reactor->socket_list = serv->connection_list;
    main_reactor->disable_accept = 0;
    main_reactor->enable_accept = swServer_enable_accept;

#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd)
    {
        swSignalfd_setup(main_reactor);
    }
#endif

    //set listen socket options
    swListenPort *ls;
    LL_FOREACH(serv->listen_list, ls)
    {
        if (swSocket_is_dgram(ls->type))
        {
            continue;
        }
        if (swPort_listen(ls) < 0)
        {
            return SW_ERR;
        }
    }

    if (serv->stream_fd > 0)
    {
        close(serv->stream_fd);
    }

    /**
     * create reactor thread
     */
    ret = swReactorThread_start(serv, main_reactor);
    if (ret < 0)
    {
        swWarn("ReactorThread start failed");
        return SW_ERR;
    }

#ifndef SW_USE_TIMEWHEEL
    /**
     * heartbeat thread
     */
    if (serv->heartbeat_check_interval >= 1 && serv->heartbeat_check_interval <= serv->heartbeat_idle_time)
    {
        swTrace("hb timer start, time: %d live time:%d", serv->heartbeat_check_interval, serv->heartbeat_idle_time);
        swHeartbeatThread_start(serv);
    }
#endif

    /**
     * master thread loop
     */
    SwooleTG.type = SW_THREAD_MASTER;
    SwooleTG.factory_target_worker = -1;
    SwooleTG.factory_lock_target = 0;
    SwooleTG.id = serv->reactor_num;
    SwooleTG.update_time = 1;

    SwooleG.main_reactor = main_reactor;
    SwooleG.pid = getpid();
    SwooleG.process_type = SW_PROCESS_MASTER;

    /**
     * set a special id
     */
    main_reactor->id = serv->reactor_num;
    main_reactor->ptr = serv;
    main_reactor->setHandle(main_reactor, SW_FD_LISTEN, swServer_master_onAccept);

    if (serv->hooks[SW_SERVER_HOOK_MASTER_START])
    {
        swServer_call_hook(serv, SW_SERVER_HOOK_MASTER_START, serv);
    }

    /**
     * init timer
     */
    if (swTimer_init(1000) < 0)
    {
        return SW_ERR;
    }
    /**
     * 1 second timer, update serv->gs->now
     */
    if (SwooleG.timer.add(&SwooleG.timer, 1000, 1, serv, swServer_master_onTimer) == NULL)
    {
        return SW_ERR;
    }

    if (serv->onStart != NULL)
    {
        serv->onStart(serv);
    }

    return main_reactor->wait(main_reactor, NULL);
}

```

### `swPort_listen` 开启端口监听

- `tcp_defer_accept` ：当一个TCP连接有数据发送时才触发 `accept`
- `tcp_fastopen`: 开启 `TCP` 快速握手特性。此项特性，可以提升 `TCP` 短连接的响应速度，在客户端完成握手的第三步，发送 `SYN` 包时携带数据。
- `open_tcp_keepalive`: 在 `TCP` 中有一个 `Keep-Alive` 的机制可以检测死连接，应用层如果对于死链接周期不敏感或者没有实现心跳机制，可以使用操作系统提供的 `keepalive` 机制来踢掉死链接。
- `buffer_high_watermark` 是缓存区高水位线，达到了说明缓冲区即将满了

```c
int swPort_listen(swListenPort *ls)
{
    int sock = ls->sock;
    int option = 1;

    //listen stream socket
    if (listen(sock, ls->backlog) < 0)
    {
        swWarn("listen(%s:%d, %d) failed. Error: %s[%d]", ls->host, ls->port, ls->backlog, strerror(errno), errno);
        return SW_ERR;
    }

#ifdef TCP_DEFER_ACCEPT
    if (ls->tcp_defer_accept)
    {
        if (setsockopt(sock, IPPROTO_TCP, TCP_DEFER_ACCEPT, (const void*) &ls->tcp_defer_accept, sizeof(int)) < 0)
        {
            swSysError("setsockopt(TCP_DEFER_ACCEPT) failed.");
        }
    }
#endif

#ifdef TCP_FASTOPEN
    if (ls->tcp_fastopen)
    {
        if (setsockopt(sock, IPPROTO_TCP, TCP_FASTOPEN, (const void*) &ls->tcp_fastopen, sizeof(int)) < 0)
        {
            swSysError("setsockopt(TCP_FASTOPEN) failed.");
        }
    }
#endif

#ifdef SO_KEEPALIVE
    if (ls->open_tcp_keepalive == 1)
    {
        if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *) &option, sizeof(option)) < 0)
        {
            swSysError("setsockopt(SO_KEEPALIVE) failed.");
        }
#ifdef TCP_KEEPIDLE
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, (void*) &ls->tcp_keepidle, sizeof(int));
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, (void *) &ls->tcp_keepinterval, sizeof(int));
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, (void *) &ls->tcp_keepcount, sizeof(int));
#endif
    }
#endif

    ls->buffer_high_watermark = ls->socket_buffer_size * 0.8;
    ls->buffer_low_watermark = 0;

    return SW_OK;
}

```

### `swReactorThread_start` 创建 `reactor` 线程
	
- `swServer_store_listen_socket` 函数用于将监控的 `socket` 存放于 `connection_list` 中
- 向 `main_reactor` 中添加监听的 `socket` 文件描述符
- `pthread_barrier_init`、`pthread_barrier_wait` 等待所有的 `reactor` 线程开启事件循环
- 利用 `pthread_create` 创建 `reactor` 线程，线程启动函数是 `swReactorThread_loop` 

```c
int swReactorThread_start(swServer *serv, swReactor *main_reactor_ptr)
{
    swThreadParam *param;
    swReactorThread *thread;
    pthread_t pidt;
    int i;

    swServer_store_listen_socket(serv);

#ifdef HAVE_REUSEPORT
    SwooleG.reuse_port = 0;
#endif

    swListenPort *ls;
    LL_FOREACH(serv->listen_list, ls)
    {
        if (ls->type == SW_SOCK_UDP || ls->type == SW_SOCK_UDP6 || ls->type == SW_SOCK_UNIX_DGRAM)
        {
            continue;
        }
        main_reactor_ptr->add(main_reactor_ptr, ls->sock, SW_FD_LISTEN);
    }

#ifdef HAVE_PTHREAD_BARRIER
    //init thread barrier
    pthread_barrier_init(&serv->barrier, NULL, serv->reactor_num + 1);
#endif

    //create reactor thread
    for (i = 0; i < serv->reactor_num; i++)
    {
        thread = &(serv->reactor_threads[i]);
        param = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swThreadParam));
        if (param == NULL)
        {
            swError("malloc failed");
            return SW_ERR;
        }

        param->object = serv;
        param->pti = i;

        if (pthread_create(&pidt, NULL, (void * (*)(void *)) swReactorThread_loop, (void *) param) < 0)
        {
            swError("pthread_create[tcp_reactor] failed. Error: %s[%d]", strerror(errno), errno);
        }
        thread->thread_id = pidt;
    }
#ifdef HAVE_PTHREAD_BARRIER
    //wait reactor thread
    pthread_barrier_wait(&serv->barrier);
#else
    SW_START_SLEEP;
#endif

    return SW_OK;
}

```

### `swServer_store_listen_socket` 保存监听

- 本函数将用于监听的 `socket` 存放到 `connection_list` 当中，并设置相应的 `info` 属性；

```c
void swServer_store_listen_socket(swServer *serv)
{
    swListenPort *ls;
    int sockfd;
    LL_FOREACH(serv->listen_list, ls)
    {
        sockfd = ls->sock;
        //save server socket to connection_list
        serv->connection_list[sockfd].fd = sockfd;
        //socket type
        serv->connection_list[sockfd].socket_type = ls->type;
        //save listen_host object
        serv->connection_list[sockfd].object = ls;

        if (swSocket_is_dgram(ls->type))
        {
            if (ls->type == SW_SOCK_UDP)
            {
                serv->connection_list[sockfd].info.addr.inet_v4.sin_port = htons(ls->port);
            }
            else if (ls->type == SW_SOCK_UDP6)
            {
                SwooleG.serv->udp_socket_ipv6 = sockfd;
                serv->connection_list[sockfd].info.addr.inet_v6.sin6_port = htons(ls->port);
            }
        }
        else
        {
            //IPv4
            if (ls->type == SW_SOCK_TCP)
            {
                serv->connection_list[sockfd].info.addr.inet_v4.sin_port = htons(ls->port);
            }
            //IPv6
            else if (ls->type == SW_SOCK_TCP6)
            {
                serv->connection_list[sockfd].info.addr.inet_v6.sin6_port = htons(ls->port);
            }
        }
        if (sockfd >= 0)
        {
            swServer_set_minfd(serv, sockfd);
            swServer_set_maxfd(serv, sockfd);
        }
    }
}

```