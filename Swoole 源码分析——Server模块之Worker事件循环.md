# Swoole 源码分析——Server模块之Worker事件循环

## `swManager_loop` 函数 `manager` 进程管理

- `manager` 进程开启的时候，首先要调用 `onManagerStart` 回调
- 添加信号处理函数 `swSignal_add`，`SIGTERM` 用于结束 `server`，只需要 `running` 设置为 0，`manager` 会逐个杀死 `worker` 进程；`SIGUSR1` 用于重载所有的 `worker` 进程；`SIGUSR2` 用于重载所有的 `task_worker` 进程；`SIGIO` 用于重启已经关闭了的 `worker` 进程；`SIGALRM` 用于检测所有的超时请求；
- 如果设置了 `serv->manager_alarm`，那么就是开启了超时请求的监控，此时需要设置 `alarm` 信号，让 `manager` 进程定时去检查是否有超时的请求。
- 如果 `running` 为 1，就不断 `while` 循环，杀死或者启动相应的 `worker` 进程，如果 `running` 为 0，那么就关闭所有的 `worker` 进程，调用 `onManagerStop` 函数退出程序。
- 调用 `wait` 函数，监控已结束的 `worker` 进程
	- 如果 `wait` 函数返回异常，很有可能是被信号打断。此时需要先检查 `ManagerProcess.read_message`，如果是 1，那么说明 `wait` 函数被 `SIGIO` 信号打断，该信号由 `worker` 进程发送，用于告知 `manager` 进程该 `worker` 进程即将关闭。此时，需要 `manager` 进程重新开启 `worker` 进程。
	- 如果 `ManagerProcess.alarm` 为 1，那么说明 `wait` 函数由 `SIGALRM` 信号打断，此时需要检查超时的请求。`erv->hooks[SW_SERVER_HOOK_MANAGER_TIMER]` 也就是 `php_swoole_trace_check` 是检查慢请求的函数。
	- 如果 `ManagerProcess.reload_all_worker` 为 1，那么 `wait` 函数由 `SIGUSR1` 打断，此时应该重启所有的 `worker` 进程
	- 如果 `ManagerProcess.reload_task_worker` 为 1，那么 `wait` 函数由 `SIGUSR2` 打断，此时应该重启所有的 `task_worker` 进程
	- 如果 	`wait` 返回值正常，那么就要从 `serv->workers`、`serv->gs->task_workers`、`serv->user_worker` 中寻找退出的 `worker` 进程。如果该进程是 `STOPPED` 状态，说明很有可能是调试状态，此时不需要重启，只需要调用 `tracer` 函数

```c
static void swManager_signal_handle(int sig)
{
    switch (sig)
    {
    case SIGTERM:
        SwooleG.running = 0;
        break;
        /**
         * reload all workers
         */
    case SIGUSR1:
        if (ManagerProcess.reloading == 0)
        {
            ManagerProcess.reloading = 1;
            ManagerProcess.reload_all_worker = 1;
        }
        break;
        /**
         * only reload task workers
         */
    case SIGUSR2:
        if (ManagerProcess.reloading == 0)
        {
            ManagerProcess.reloading = 1;
            ManagerProcess.reload_task_worker = 1;
        }
        break;
    case SIGIO:
        ManagerProcess.read_message = 1;
        break;
    case SIGALRM:
        ManagerProcess.alarm = 1;
        break;
    default:
#ifdef SIGRTMIN
        if (sig == SIGRTMIN)
        {
            swServer_reopen_log_file(SwooleG.serv);
        }
#endif
        break;
    }
}

static int swManager_loop(swFactory *factory)
{
    int pid, new_pid;
    int i;
    int reload_worker_i = 0;
    int reload_worker_num;
    int reload_init = 0;
    pid_t reload_worker_pid = 0;

    int status;

    SwooleG.use_signalfd = 0;
    SwooleG.use_timerfd = 0;

    memset(&ManagerProcess, 0, sizeof(ManagerProcess));

    swServer *serv = factory->ptr;
    swWorker *reload_workers;

    if (serv->hooks[SW_SERVER_HOOK_MANAGER_START])
    {
        swServer_call_hook(serv, SW_SERVER_HOOK_MANAGER_START, serv);
    }

    if (serv->onManagerStart)
    {
        serv->onManagerStart(serv);
    }

    reload_worker_num = serv->worker_num + serv->task_worker_num;
    reload_workers = sw_calloc(reload_worker_num, sizeof(swWorker));
    if (reload_workers == NULL)
    {
        swError("malloc[reload_workers] failed");
        return SW_ERR;
    }

    //for reload
    swSignal_add(SIGHUP, NULL);
    swSignal_add(SIGTERM, swManager_signal_handle);
    swSignal_add(SIGUSR1, swManager_signal_handle);
    swSignal_add(SIGUSR2, swManager_signal_handle);
    swSignal_add(SIGIO, swManager_signal_handle);
#ifdef SIGRTMIN
    swSignal_add(SIGRTMIN, swManager_signal_handle);
#endif
    //swSignal_add(SIGINT, swManager_signal_handle);

    if (serv->manager_alarm > 0)
    {
        alarm(serv->manager_alarm);
        swSignal_add(SIGALRM, swManager_signal_handle);
    }

    SwooleG.main_reactor = NULL;

    while (SwooleG.running > 0)
    {
        _wait: pid = wait(&status);

        if (ManagerProcess.read_message)
        {
            swWorkerStopMessage msg;
            while (swChannel_pop(serv->message_box, &msg, sizeof(msg)) > 0)
            {
                if (SwooleG.running == 0)
                {
                    continue;
                }
                pid_t new_pid = swManager_spawn_worker(factory, msg.worker_id);
                if (new_pid > 0)
                {
                    serv->workers[msg.worker_id].pid = new_pid;
                }
            }
            ManagerProcess.read_message = 0;
        }

        if (pid < 0)
        {
            if (ManagerProcess.alarm == 1)
            {
                ManagerProcess.alarm = 0;
                alarm(serv->manager_alarm);

                if (serv->hooks[SW_SERVER_HOOK_MANAGER_TIMER])
                {
                    swServer_call_hook(serv, SW_SERVER_HOOK_MANAGER_TIMER, serv);
                }
            }

            if (ManagerProcess.reloading == 0)
            {
                error: if (errno != EINTR)
                {
                    swSysError("wait() failed.");
                }
                continue;
            }
            //reload task & event workers
            else if (ManagerProcess.reload_all_worker == 1)
            {
                swNotice("Server is reloading now.");
                if (reload_init == 0)
                {
                    reload_init = 1;
                    memcpy(reload_workers, serv->workers, sizeof(swWorker) * serv->worker_num);
                    reload_worker_num = serv->worker_num;

                    if (serv->task_worker_num > 0)
                    {
                        memcpy(reload_workers + serv->worker_num, serv->gs->task_workers.workers,
                                sizeof(swWorker) * serv->task_worker_num);
                        reload_worker_num += serv->task_worker_num;
                    }

                    ManagerProcess.reload_all_worker = 0;
                    if (serv->reload_async)
                    {
                        for (i = 0; i < serv->worker_num; i++)
                        {
                            if (kill(reload_workers[i].pid, SIGTERM) < 0)
                            {
                                swSysError("kill(%d, SIGTERM) [%d] failed.", reload_workers[i].pid, i);
                            }
                        }
                        reload_worker_i = serv->worker_num;
                    }
                    else
                    {
                        reload_worker_i = 0;
                    }
                }
                goto kill_worker;
            }
            //only reload task workers
            else if (ManagerProcess.reload_task_worker == 1)
            {
                if (serv->task_worker_num == 0)
                {
                    swWarn("cannot reload task workers, task workers is not started.");
                    continue;
                }
                swNotice("Server is reloading now.");
                if (reload_init == 0)
                {
                    memcpy(reload_workers, serv->gs->task_workers.workers, sizeof(swWorker) * serv->task_worker_num);
                    reload_worker_num = serv->task_worker_num;
                    reload_worker_i = 0;
                    reload_init = 1;
                    ManagerProcess.reload_task_worker = 0;
                }
                goto kill_worker;
            }
            else
            {
                goto error;
            }
        }
        if (SwooleG.running == 1)
        {
            //event workers
            for (i = 0; i < serv->worker_num; i++)
            {
                //compare PID
                if (pid != serv->workers[i].pid)
                {
                    continue;
                }

                if (WIFSTOPPED(status) && serv->workers[i].tracer)
                {
                    serv->workers[i].tracer(&serv->workers[i]);
                    serv->workers[i].tracer = NULL;
                    goto _wait;
                }

                //Check the process return code and signal
                swManager_check_exit_status(serv, i, pid, status);

                while (1)
                {
                    new_pid = swManager_spawn_worker(factory, i);
                    if (new_pid < 0)
                    {
                        usleep(100000);
                        continue;
                    }
                    else
                    {
                        serv->workers[i].pid = new_pid;
                        break;
                    }
                }
            }

            swWorker *exit_worker;
            //task worker
            if (serv->gs->task_workers.map)
            {
                exit_worker = swHashMap_find_int(serv->gs->task_workers.map, pid);
                if (exit_worker != NULL)
                {
                    if (WIFSTOPPED(status) && exit_worker->tracer)
                    {
                        exit_worker->tracer(exit_worker);
                        exit_worker->tracer = NULL;
                        goto _wait;
                    }
                    swManager_check_exit_status(serv, exit_worker->id, pid, status);
                    swProcessPool_spawn(&serv->gs->task_workers, exit_worker);
                }
            }
            //user process
            if (serv->user_worker_map != NULL)
            {
                swManager_wait_user_worker(&serv->gs->event_workers, pid, status);
            }
            if (pid == reload_worker_pid)
            {
                reload_worker_i++;
            }
        }
        //reload worker
        kill_worker: if (ManagerProcess.reloading == 1)
        {
            //reload finish
            if (reload_worker_i >= reload_worker_num)
            {
                reload_worker_pid = reload_worker_i = reload_init = ManagerProcess.reloading = 0;
                continue;
            }
            reload_worker_pid = reload_workers[reload_worker_i].pid;
            if (kill(reload_worker_pid, SIGTERM) < 0)
            {
                if (errno == ECHILD)
                {
                    reload_worker_i++;
                    goto kill_worker;
                }
                swSysError("kill(%d, SIGTERM) [%d] failed.", reload_workers[reload_worker_i].pid, reload_worker_i);
            }
        }
    }

    sw_free(reload_workers);
    swSignal_none();
    //kill all child process
    for (i = 0; i < serv->worker_num; i++)
    {
        swTrace("[Manager]kill worker processor");
        kill(serv->workers[i].pid, SIGTERM);
    }
    //kill and wait task process
    if (serv->task_worker_num > 0)
    {
        swProcessPool_shutdown(&serv->gs->task_workers);
    }
    //wait child process
    for (i = 0; i < serv->worker_num; i++)
    {
        if (swWaitpid(serv->workers[i].pid, &status, 0) < 0)
        {
            swSysError("waitpid(%d) failed.", serv->workers[i].pid);
        }
    }
    //kill all user process
    if (serv->user_worker_map)
    {
        swManager_kill_user_worker(serv);
    }

    if (serv->onManagerStop)
    {
        serv->onManagerStop(serv);
    }

    return SW_OK;
}

void php_swoole_trace_check(void *arg)
{
    swServer *serv = (swServer *) arg;
    uint8_t timeout = serv->request_slowlog_timeout;
    int count = serv->worker_num + serv->task_worker_num;
    int i = serv->trace_event_worker ? 0 : serv->worker_num;
    swWorker *worker;

    for (; i < count; i++)
    {
        worker = swServer_get_worker(serv, i);
        swTraceLog(SW_TRACE_SERVER, "trace request, worker#%d, pid=%d. request_time=%d.", i, worker->pid, worker->request_time);
        if (!(worker->request_time > 0 && worker->traced == 0 && serv->gs->now - worker->request_time >= timeout))
        {
            continue;
        }
        if (ptrace(PTRACE_ATTACH, worker->pid, 0, 0) < 0)
        {
            swSysError("failed to ptrace(ATTACH, %d) worker#%d,", worker->pid, worker->id);
            continue;
        }
        worker->tracer = trace_request;
        worker->traced = 1;
    }
}

static void swManager_check_exit_status(swServer *serv, int worker_id, pid_t pid, int status)
{
    if (status != 0)
    {
        swWarn("worker#%d abnormal exit, status=%d, signal=%d", worker_id, WEXITSTATUS(status), WTERMSIG(status));
        if (serv->onWorkerError != NULL)
        {
            serv->onWorkerError(serv, worker_id, pid, WEXITSTATUS(status), WTERMSIG(status));
        }
    }
}


```

## `swWorker_loop` 函数 `worker` 事件循环

- `worker` 进程的事件循环和 `reactor` 线程类似，都是创建 `reactor` 对象，然后调用 `SwooleG.main_reactor->wait` 函数进行事件循环，不同的是 `worker` 进程监控的是 `pipe_worker` 这个 `socket`。
- 如果 `worker` 的 `dispatch_mode` 是 `stream`，`reactor` 还要监听 `serv->stream_fd`，以便可以更加高效的消费 `reactor` 线程发送的数据
- `swServer_worker_init` 函数用于初始化 `worker` 进程，`swWorker_onStart` 用于调用回调函数，`swWorker_onStop` 用于停止 `worker` 进程

```c
int swWorker_loop(swFactory *factory, int worker_id)
{
    swServer *serv = factory->ptr;

#ifndef SW_WORKER_USE_SIGNALFD
    SwooleG.use_signalfd = 0;
#elif defined(HAVE_SIGNALFD)
    SwooleG.use_signalfd = 1;
#endif
    //timerfd
#ifdef HAVE_TIMERFD
    SwooleG.use_timerfd = 1;
#endif

    //worker_id
    SwooleWG.id = worker_id;
    SwooleG.pid = getpid();

    swWorker *worker = swServer_get_worker(serv, worker_id);
    swServer_worker_init(serv, worker);

    SwooleG.main_reactor = sw_malloc(sizeof(swReactor));
    if (SwooleG.main_reactor == NULL)
    {
        swError("[Worker] malloc for reactor failed.");
        return SW_ERR;
    }

    if (swReactor_create(SwooleG.main_reactor, SW_REACTOR_MAXEVENTS) < 0)
    {
        swError("[Worker] create worker_reactor failed.");
        return SW_ERR;
    }
    
    worker->status = SW_WORKER_IDLE;

    int pipe_worker = worker->pipe_worker;

    swSetNonBlock(pipe_worker);
    SwooleG.main_reactor->ptr = serv;
    SwooleG.main_reactor->add(SwooleG.main_reactor, pipe_worker, SW_FD_PIPE | SW_EVENT_READ);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_PIPE, swWorker_onPipeReceive);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_WRITE, swReactor_onWrite);

    /**
     * set pipe buffer size
     */
    int i;
    swConnection *pipe_socket;
    for (i = 0; i < serv->worker_num + serv->task_worker_num; i++)
    {
        worker = swServer_get_worker(serv, i);
        pipe_socket = swReactor_get(SwooleG.main_reactor, worker->pipe_master);
        pipe_socket->buffer_size = SW_MAX_INT;
        pipe_socket = swReactor_get(SwooleG.main_reactor, worker->pipe_worker);
        pipe_socket->buffer_size = SW_MAX_INT;
    }

    if (serv->dispatch_mode == SW_DISPATCH_STREAM)
    {
        SwooleG.main_reactor->add(SwooleG.main_reactor, serv->stream_fd, SW_FD_LISTEN | SW_EVENT_READ);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_LISTEN, swWorker_onStreamAccept);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_STREAM, swWorker_onStreamRead);
        swStream_set_protocol(&serv->stream_protocol);
        serv->stream_protocol.package_max_length = SW_MAX_INT;
        serv->stream_protocol.onPackage = swWorker_onStreamPackage;
        serv->buffer_pool = swLinkedList_new(0, NULL);
    }

    swWorker_onStart(serv);

#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd)
    {
        swSignalfd_setup(SwooleG.main_reactor);
    }
#endif
    //main loop
    SwooleG.main_reactor->wait(SwooleG.main_reactor, NULL);
    //clear pipe buffer
    swWorker_clean();
    //worker shutdown
    swWorker_onStop(serv);
    return SW_OK;
}

```

### `swServer_worker_init` 初始化函数

- 与 `reactor` 线程一样，首先如果设置了 `CPU` 亲和度的话，要将 `worker` 进程绑定到特定的 `CPU` 上，指定 `CPU` 的方法仍然是 `SwooleWG.id % serv->cpu_affinity_available_num`，这样可以保证对应的 `reactor` 线程和 `worker` 进程在同一个 `CPU` 核上
- `swWorker_signal_init` 用于设置 `worker` 进程的信号处理函数：`SIGTERM` 信号用于关闭当前 `worker` 进程;`SIGALRM` 代表定时任务。
- `buffer_input` 用于存储来源于 `reactor` 线程发送的数据，是一个 `serv->reactor_num + serv->dgram_port_num` 大小的数组。


```c
void swWorker_signal_init(void)
{
    swSignal_clear();
    /**
     * use user settings
     */
    SwooleG.use_signalfd = SwooleG.enable_signalfd;

    swSignal_add(SIGHUP, NULL);
    swSignal_add(SIGPIPE, NULL);
    swSignal_add(SIGUSR1, NULL);
    swSignal_add(SIGUSR2, NULL);
    swSignal_add(SIGTERM, swWorker_signal_handler);
    swSignal_add(SIGALRM, swSystemTimer_signal_handler);
    //for test
    swSignal_add(SIGVTALRM, swWorker_signal_handler);
#ifdef SIGRTMIN
    swSignal_add(SIGRTMIN, swWorker_signal_handler);
#endif
}

int swServer_worker_init(swServer *serv, swWorker *worker)
{
#ifdef HAVE_CPU_AFFINITY
    if (serv->open_cpu_affinity)
    {
        cpu_set_t cpu_set;
        CPU_ZERO(&cpu_set);
        if (serv->cpu_affinity_available_num)
        {
            CPU_SET(serv->cpu_affinity_available[SwooleWG.id % serv->cpu_affinity_available_num], &cpu_set);
        }
        else
        {
            CPU_SET(SwooleWG.id % SW_CPU_NUM, &cpu_set);
        }
#ifdef __FreeBSD__
        if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1,
                                sizeof(cpu_set), &cpu_set) < 0)
#else
        if (sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set) < 0)
#endif
        {
            swSysError("sched_setaffinity() failed.");
        }
    }
#endif

    //signal init
    swWorker_signal_init();

    SwooleWG.buffer_input = swServer_create_worker_buffer(serv);
    if (!SwooleWG.buffer_input)
    {
        return SW_ERR;
    }

    if (serv->max_request < 1)
    {
        SwooleWG.run_always = 1;
    }
    else
    {
        SwooleWG.max_request = serv->max_request;
        if (SwooleWG.max_request > 10)
        {
            int n = swoole_system_random(1, SwooleWG.max_request / 2);
            if (n > 0)
            {
                SwooleWG.max_request += n;
            }
        }
    }

    worker->start_time = serv->gs->now;
    worker->request_time = 0;
    worker->request_count = 0;

    return SW_OK;
}

swString** swServer_create_worker_buffer(swServer *serv)
{
    int i;
    int buffer_num;

    if (serv->factory_mode == SW_MODE_SINGLE)
    {
        buffer_num = 1;
    }
    else
    {
        buffer_num = serv->reactor_num + serv->dgram_port_num;
    }

    swString **buffers = sw_malloc(sizeof(swString*) * buffer_num);
    if (buffers == NULL)
    {
        swError("malloc for worker buffer_input failed.");
        return NULL;
    }

    for (i = 0; i < buffer_num; i++)
    {
        buffers[i] = swString_new(SW_BUFFER_SIZE_BIG);
        if (buffers[i] == NULL)
        {
            swError("worker buffer_input init failed.");
            return NULL;
        }
    }

    return buffers;
}

```

### `swWorker_onStart` 进程启动
- `swWorker_onStart` 函数将其他的 `worker` 进程所占内存全部释放
- 设定当前 `worker` 的状态为 `SW_WORKER_IDLE` 空闲
- 如果用户更改了 `worker` 进程的用户与组、进行了重定向根目录，那么我们还要调用 `setgid`、`setuid`、`chroot` 函数进行相应设置

```c
void swWorker_onStart(swServer *serv)
{
    /**
     * Release other worker process
     */
    swWorker *worker;

    if (SwooleWG.id >= serv->worker_num)
    {
        SwooleG.process_type = SW_PROCESS_TASKWORKER;
    }
    else
    {
        SwooleG.process_type = SW_PROCESS_WORKER;
    }

    int is_root = !geteuid();
    struct passwd *passwd = NULL;
    struct group *group = NULL;

    if (is_root)
    {
        //get group info
        if (SwooleG.group)
        {
            group = getgrnam(SwooleG.group);
            if (!group)
            {
                swWarn("get group [%s] info failed.", SwooleG.group);
            }
        }
        //get user info
        if (SwooleG.user)
        {
            passwd = getpwnam(SwooleG.user);
            if (!passwd)
            {
                swWarn("get user [%s] info failed.", SwooleG.user);
            }
        }
        //chroot
        if (SwooleG.chroot)
        {
            if (0 > chroot(SwooleG.chroot))
            {
                swSysError("chroot to [%s] failed.", SwooleG.chroot);
            }
        }
        //set process group
        if (SwooleG.group && group)
        {
            if (setgid(group->gr_gid) < 0)
            {
                swSysError("setgid to [%s] failed.", SwooleG.group);
            }
        }
        //set process user
        if (SwooleG.user && passwd)
        {
            if (setuid(passwd->pw_uid) < 0)
            {
                swSysError("setuid to [%s] failed.", SwooleG.user);
            }
        }
    }

    SwooleWG.worker = swServer_get_worker(serv, SwooleWG.id);

    int i;
    for (i = 0; i < serv->worker_num + serv->task_worker_num; i++)
    {
        worker = swServer_get_worker(serv, i);
        if (SwooleWG.id == i)
        {
            continue;
        }
        else
        {
            swWorker_free(worker);
        }
        if (swIsWorker())
        {
            swSetNonBlock(worker->pipe_master);
        }
    }

    SwooleWG.worker->status = SW_WORKER_IDLE;
    sw_shm_protect(serv->session_list, PROT_READ);

    if (serv->onWorkerStart)
    {
        serv->onWorkerStart(serv, SwooleWG.id);
    }
}

```

### `swWorker_stop` 关闭 `worker` 进程

- `reload_async` 设置为 1 后，并不会立刻停止 `worker` 进程，如果 `reactor` 当中还有待监听的事件，`reactor` 仍然可以继续循环；与此同时，`worker` 进程设置了一个超时时间，超过时间后，立刻关闭事件循环。
- 为了通知 `manager` 进程重启 `worker` 进程，需要调用 `swChannel_push` 函数更新 `message_box`
- 从 `reactor` 中删除对 `pipe_worker`、`stream_fd` 的事件监控
- `swWorker_try_to_exit` 用于判断当前 `worker` 进程中 `reactor` 是否还有待监听事件，如果没有可以立刻停止进程

```c
static sw_inline int swReactor_remove_read_event(swReactor *reactor, int fd)
{
    swConnection *conn = swReactor_get(reactor, fd);
    if (conn->events & SW_EVENT_WRITE)
    {
        conn->events &= (~SW_EVENT_READ);
        return reactor->set(reactor, fd, conn->fdtype | conn->events);
    }
    else
    {
        return reactor->del(reactor, fd);
    }
}

static void swWorker_stop()
{
    swWorker *worker = SwooleWG.worker;
    swServer *serv = SwooleG.serv;
    worker->status = SW_WORKER_BUSY;

    /**
     * force to end
     */
    if (serv->reload_async == 0)
    {
        SwooleG.running = 0;
        SwooleG.main_reactor->running = 0;
        return;
    }

    //The worker process is shutting down now.
    if (SwooleWG.wait_exit)
    {
        return;
    }

    //remove read event
    if (worker->pipe_worker)
    {
        swReactor_remove_read_event(SwooleG.main_reactor, worker->pipe_worker);
    }

    if (serv->stream_fd > 0)
    {
        SwooleG.main_reactor->del(SwooleG.main_reactor, serv->stream_fd);
        close(serv->stream_fd);
        serv->stream_fd = 0;
    }

    if (serv->onWorkerStop)
    {
        serv->onWorkerStop(serv, SwooleWG.id);
        serv->onWorkerStop = NULL;
    }

    swWorkerStopMessage msg;
    msg.pid = SwooleG.pid;
    msg.worker_id = SwooleWG.id;

    //send message to manager
    if (swChannel_push(SwooleG.serv->message_box, &msg, sizeof(msg)) < 0)
    {
        SwooleG.running = 0;
    }
    else
    {
        kill(serv->gs->manager_pid, SIGIO);
    }

    try_to_exit: SwooleWG.wait_exit = 1;
    if (SwooleG.timer.fd == 0)
    {
        swTimer_init(serv->max_wait_time * 1000);
    }
    SwooleG.timer.add(&SwooleG.timer, serv->max_wait_time * 1000, 0, NULL, swWorker_onTimeout);

    swWorker_try_to_exit();
}

static void swWorker_onTimeout(swTimer *timer, swTimer_node *tnode)
{
    SwooleG.running = 0;
    SwooleG.main_reactor->running = 0;
    swoole_error_log(SW_LOG_WARNING, SW_ERROR_SERVER_WORKER_EXIT_TIMEOUT, "worker exit timeout, forced to terminate.");
}

void swWorker_try_to_exit()
{
    swServer *serv = SwooleG.serv;
    int expect_event_num = SwooleG.use_signalfd ? 1 : 0;

    uint8_t call_worker_exit_func = 0;

    while (1)
    {
        if (SwooleG.main_reactor->event_num == expect_event_num)
        {
            SwooleG.main_reactor->running = 0;
            SwooleG.running = 0;
        }
        else
        {
            if (serv->onWorkerExit && call_worker_exit_func == 0)
            {
                serv->onWorkerExit(serv, SwooleWG.id);
                call_worker_exit_func = 1;
                continue;
            }
        }
        break;
    }
}

```

## `swWorker_onPipeReceive` 接受数据

接受数据的时候，如果类型是 `SW_EVENT_PACKAGE_START`，说明后续还有数据，需要将数据合并在一起接受。

```c
static int swWorker_onPipeReceive(swReactor *reactor, swEvent *event)
{
    swEventData task;
    swServer *serv = reactor->ptr;
    swFactory *factory = &serv->factory;
    int ret;

    read_from_pipe:

    if (read(event->fd, &task, sizeof(task)) > 0)
    {
        ret = swWorker_onTask(factory, &task);

        /**
         * Big package
         */
        if (task.info.type == SW_EVENT_PACKAGE_START)
        {
            //no data
            if (ret < 0 && errno == EAGAIN)
            {
                return SW_OK;
            }
            else if (ret > 0)
            {
                goto read_from_pipe;
            }
        }
        return ret;
    }
    return SW_ERR;
}

```

### `swWorker_onTask` 函数处理数据

- `worker` 接受的消息数据类型有多种，最常用的是 `SW_EVENT_TCP`、`SW_EVENT_PACKAGE`、`SW_EVENT_PACKAGE_START`、`SW_EVENT_PACKAGE_END`
- 如果数据类型是 `SW_EVENT_TCP`、`SW_EVENT_PACKAGE`，首先要调用 `swWorker_discard_data` 函数观察数据是否有效，接着利用 `onReceive` 函数接受 `ring_buff` 数据并且调用回调函数
- 如果数据是 `SW_EVENT_PACKAGE_START`、`SW_EVENT_PACKAGE_END`,会将数据存储在 `SwooleWG.buffer_input` 中去。最后调用 ` serv->onReceive`
- `SW_EVENT_CONNECT` 事件由接受连接时触发
- `SW_EVENT_BUFFER_FULL`、`SW_EVENT_BUFFER_EMPTY` 事件是连接中客户端数据过多 `worker` 无法及时消费触发
- `SW_EVENT_FINISH` 由 `task_worker` 完成任务触发
- `SW_EVENT_PIPE_MESSAGE` 由发送任务给 `task_worker` 触发

```c
int swWorker_onTask(swFactory *factory, swEventData *task)
{
    swServer *serv = factory->ptr;
    swString *package = NULL;
    swDgramPacket *header;

#ifdef SW_USE_OPENSSL
    swConnection *conn;
#endif

    factory->last_from_id = task->info.from_id;
    serv->last_session_id = task->info.fd;
    swWorker *worker = SwooleWG.worker;
    //worker busy
    worker->status = SW_WORKER_BUSY;

    switch (task->info.type)
    {
    //no buffer
    case SW_EVENT_TCP:
    //ringbuffer shm package
    case SW_EVENT_PACKAGE:
        //discard data
        if (swWorker_discard_data(serv, task) == SW_TRUE)
        {
            break;
        }
        do_task:
        {
            worker->request_time = serv->gs->now;
#ifdef SW_BUFFER_RECV_TIME
            serv->last_receive_usec = task->info.time;
#endif
            serv->onReceive(serv, task);
            worker->request_time = 0;
#ifdef SW_BUFFER_RECV_TIME
            serv->last_receive_usec = 0;
#endif
            worker->traced = 0;
            worker->request_count++;
            sw_atomic_fetch_add(&serv->stats->request_count, 1);
        }
        if (task->info.type == SW_EVENT_PACKAGE_END)
        {
            package->length = 0;
        }
        break;

    //chunk package
    case SW_EVENT_PACKAGE_START:
    case SW_EVENT_PACKAGE_END:
        //discard data
        if (swWorker_discard_data(serv, task) == SW_TRUE)
        {
            break;
        }
        package = swWorker_get_buffer(serv, task->info.from_id);
        if (task->info.len > 0)
        {
            //merge data to package buffer
            swString_append_ptr(package, task->data, task->info.len);
        }
        //package end
        if (task->info.type == SW_EVENT_PACKAGE_END)
        {
            goto do_task;
        }
        break;

    case SW_EVENT_CLOSE:
        factory->end(factory, task->info.fd);
        break;

    case SW_EVENT_CONNECT:
        if (serv->onConnect)
        {
            serv->onConnect(serv, &task->info);
        }
        break;

    case SW_EVENT_BUFFER_FULL:
        if (serv->onBufferFull)
        {
            serv->onBufferFull(serv, &task->info);
        }
        break;

    case SW_EVENT_BUFFER_EMPTY:
        if (serv->onBufferEmpty)
        {
            serv->onBufferEmpty(serv, &task->info);
        }
        break;

    case SW_EVENT_FINISH:
        serv->onFinish(serv, task);
        break;

    case SW_EVENT_PIPE_MESSAGE:
        serv->onPipeMessage(serv, task);
        break;

    default:
        swWarn("[Worker] error event[type=%d]", (int )task->info.type);
        break;
    }

    //worker idle
    worker->status = SW_WORKER_IDLE;

    //maximum number of requests, process will exit.
    if (!SwooleWG.run_always && worker->request_count >= SwooleWG.max_request)
    {
        swWorker_stop();
    }
    return SW_OK;
}

```

### `swWorker_discard_data` 验证数据有效性

`swServer_connection_verify` 函数利用 `task->info.fd` 这个 `sessionid` 来验证连接的有效性，如果连接已经关闭，或者已经被删除，那么就要抛弃当前数据


```c
static sw_inline int swWorker_discard_data(swServer *serv, swEventData *task)
{
    int fd = task->info.fd;
    //check connection
    swConnection *conn = swServer_connection_verify(serv, task->info.fd);
    if (conn == NULL)
    {
        if (serv->disable_notify && !serv->discard_timeout_request)
        {
            return SW_FALSE;
        }
        goto discard_data;
    }
    else
    {
        if (conn->closed)
        {
            goto discard_data;
        }
        else
        {
            return SW_FALSE;
        }
    }
    discard_data:
#ifdef SW_USE_RINGBUFFER
    if (task->info.type == SW_EVENT_PACKAGE)
    {
        swPackage package;
        memcpy(&package, task->data, sizeof(package));
        swReactorThread *thread = swServer_get_thread(SwooleG.serv, task->info.from_id);
        thread->buffer_input->free(thread->buffer_input, package.data);
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SESSION_DISCARD_TIMEOUT_DATA, "[1]received the wrong data[%d bytes] from socket#%d", package.length, fd);
    }
    else
#endif
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SESSION_DISCARD_TIMEOUT_DATA, "[1]received the wrong data[%d bytes] from socket#%d", task->info.len, fd);
    }
    return SW_TRUE;
}

static sw_inline swConnection *swServer_connection_verify(swServer *serv, int session_id)
{
    swConnection *conn = swServer_connection_verify_no_ssl(serv, session_id);
    return conn;
}

static sw_inline swConnection *swServer_connection_verify_no_ssl(swServer *serv, int session_id)
{
    swSession *session = swServer_get_session(serv, session_id);
    int fd = session->fd;
    swConnection *conn = swServer_connection_get(serv, fd);
    if (!conn || conn->active == 0)
    {
        return NULL;
    }
    if (session->id != session_id || conn->session_id != session_id)
    {
        return NULL;
    }
    return conn;
}

```

### `php_swoole_onReceive` 回调函数

该回调函数首先要调用 `php_swoole_get_recv_data` 获取数据，然后 `sw_call_user_function_fast` 执行 `PHP` 的回调函数

```c
int php_swoole_onReceive(swServer *serv, swEventData *req)
{
    swFactory *factory = &serv->factory;
    zval *zserv = (zval *) serv->ptr2;

    zval *zfd;
    zval *zfrom_id;
    zval *zdata;
    zval *retval = NULL;

    SWOOLE_GET_TSRMLS;

    php_swoole_udp_t udp_info;
    swDgramPacket *packet;

    SW_MAKE_STD_ZVAL(zfd);
    SW_MAKE_STD_ZVAL(zfrom_id);
    SW_MAKE_STD_ZVAL(zdata);


    {
        ZVAL_LONG(zfrom_id, (long ) req->info.from_id);
        ZVAL_LONG(zfd, (long ) req->info.fd);
        php_swoole_get_recv_data(zdata, req, NULL, 0);
    }

    {
        zval **args[4];
        zval *callback = php_swoole_server_get_callback(serv, req->info.from_fd, SW_SERVER_CB_onReceive);
        if (callback == NULL || ZVAL_IS_NULL(callback))
        {
            swoole_php_fatal_error(E_WARNING, "onReceive callback is null.");
            return SW_OK;
        }

        args[0] = &zserv;
        args[1] = &zfd;
        args[2] = &zfrom_id;
        args[3] = &zdata;

        zend_fcall_info_cache *fci_cache = php_swoole_server_get_cache(serv, req->info.from_fd, SW_SERVER_CB_onReceive);
        if (sw_call_user_function_fast(callback, fci_cache, &retval, 4, args TSRMLS_CC) == FAILURE)
        {
            swoole_php_fatal_error(E_WARNING, "onReceive handler error.");
        }
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    sw_zval_ptr_dtor(&zfd);
    sw_zval_ptr_dtor(&zfrom_id);
    sw_zval_ptr_dtor(&zdata);
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    return SW_OK;
}

```

### `php_swoole_get_recv_data` 接受数据

- 如果使用的数据类型是 `SW_EVENT_PACKAGE`，那么数据存储在 `ringBuff` 共享内存池中，我们首先要把数据复制到 `zdata` 当中，然后释放共享内存
- 如果数据类型是 `SW_EVENT_PACKAGE_END`，那么数据存储在 `SwooleWG.buffer_input` 中

```c
void php_swoole_get_recv_data(zval *zdata, swEventData *req, char *header, uint32_t header_length)
{
    char *data_ptr = NULL;
    int data_len;

#ifdef SW_USE_RINGBUFFER
    swPackage package;
    if (req->info.type == SW_EVENT_PACKAGE)
    {
        memcpy(&package, req->data, sizeof (package));

        data_ptr = package.data;
        data_len = package.length;
    }
#else
    if (req->info.type == SW_EVENT_PACKAGE_END)
    {
        swString *worker_buffer = swWorker_get_buffer(SwooleG.serv, req->info.from_id);
        data_ptr = worker_buffer->str;
        data_len = worker_buffer->length;
    }
#endif
    else
    {
        data_ptr = req->data;
        data_len = req->info.len;
    }

    if (header_length >= data_len)
    {
        SW_ZVAL_STRING(zdata, "", 1);
    }
    else
    {
        SW_ZVAL_STRINGL(zdata, data_ptr + header_length, data_len - header_length, 1);
    }

    if (header_length > 0)
    {
        memcpy(header, data_ptr, header_length);
    }

#ifdef SW_USE_RINGBUFFER
    if (req->info.type == SW_EVENT_PACKAGE)
    {
        swReactorThread *thread = swServer_get_thread(SwooleG.serv, req->info.from_id);
        thread->buffer_input->free(thread->buffer_input, data_ptr);
    }
#endif
}

```

## `swoole_server->send` 向客户端发送数据

`worker` 进程向客户端发送数据时，会调用 `swoole_server->send` 函数，该函数会调用 `swServer_tcp_send` 函数

```c
PHP_METHOD(swoole_server, send)
{
    int ret;

    zval *zfd;
    zval *zdata;
    zend_long server_socket = -1;

    swServer *serv = swoole_get_object(getThis());

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz|l", &zfd, &zdata, &server_socket) == FAILURE)
    {
        return;
    }
    
    char *data;
    int length = php_swoole_get_send_data(zdata, &data TSRMLS_CC);

    convert: convert_to_long(zfd);
    uint32_t fd = (uint32_t) Z_LVAL_P(zfd);

    ret = swServer_tcp_send(serv, fd, data, length);
#ifdef SW_COROUTINE
    if (ret < 0 && SwooleG.error == SW_ERROR_OUTPUT_BUFFER_OVERFLOW && serv->send_yield)
    {
        zval_add_ref(zdata);
        php_swoole_server_send_yield(serv, fd, zdata, return_value);
    }
    else
#endif
    {
        SW_CHECK_RETURN(ret);
    }
}
```

### `swServer_tcp_send` 函数

- 如果使用 `stream` 模式，那么可以直接向 `serv->last_stream_fd` 发送数据即可
- 如果是普通模式，那么需要打包类型为 `SW_EVENT_TCP` 的数据，调用 `finish` 函数将数据放入 `pipe` 的缓冲区中
- 注意小数据 `_send.length` 为 0，大数据 `_send.length` 才会大于 0

```c
int swServer_tcp_send(swServer *serv, int fd, void *data, uint32_t length)
{
    swSendData _send;
    swFactory *factory = &(serv->factory);

    if (unlikely(swIsMaster()))
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_SEND_IN_MASTER,
                "can't send data to the connections in master process.");
        return SW_ERR;
    }

    /**
     * More than the output buffer
     */
    if (length > serv->buffer_output_size)
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_DATA_LENGTH_TOO_LARGE, "More than the output buffer size[%d], please use the sendfile.", serv->buffer_output_size);
        return SW_ERR;
    }
    else
    {
        if (fd == serv->last_session_id && serv->last_stream_fd > 0)
        {
            int _l = htonl(length);
            if (SwooleG.main_reactor->write(SwooleG.main_reactor, serv->last_stream_fd, (void *) &_l, sizeof(_l)) < 0)
            {
                return SW_ERR;
            }
            if (SwooleG.main_reactor->write(SwooleG.main_reactor, serv->last_stream_fd, data, length) < 0)
            {
                return SW_ERR;
            }
            return SW_OK;
        }

        _send.info.fd = fd;
        _send.info.type = SW_EVENT_TCP;
        _send.data = data;

        if (length >= SW_IPC_MAX_SIZE - sizeof(swDataHead))
        {
            _send.length = length;
        }
        else
        {
            _send.info.len = length;
            _send.length = 0;
        }
        return factory->finish(factory, &_send);
    }
    return SW_OK;
}

```

### `swFactoryProcess_finish` 函数

- 首先要验证数据的有效性，利用 `swServer_connection_verify_no_ssl` 获取到 `swConnection` 对象
- `resp->length` 大于 0，那么说明是大数据包，这个时候需要将数据放入 `worker->send_shm` 当中，然后将 `worker_id` 打包到 `swEventData` 对象
- 如果 `out_buffer` 管道缓存区不是空的，说明管道中有数据未发送完毕（有可能是共享内存数据未发送完毕），那么就利用函数 `swTaskWorker_large_pack` 将数据存放到临时文件中。(猜测防止发送到共享内存时被 `worker` 进程锁锁住)
- 如果是小数据包，那么就将数据打包到 `swEventData` 对象中
- `swWorker_send2reactor` 函数将用于将数据发送到 `reactor` 线程

```c
static sw_inline int swWorker_get_send_pipe(swServer *serv, int session_id, int reactor_id)
{
    int pipe_index = session_id % serv->reactor_pipe_num;
    /**
     * pipe_worker_id: The pipe in which worker.
     */
    int pipe_worker_id = reactor_id + (pipe_index * serv->reactor_num);
    swWorker *worker = swServer_get_worker(serv, pipe_worker_id);
    return worker->pipe_worker;
}

static int swFactoryProcess_finish(swFactory *factory, swSendData *resp)
{
    int ret, sendn;
    swServer *serv = factory->ptr;
    int session_id = resp->info.fd;

    swConnection *conn;
    if (resp->info.type != SW_EVENT_CLOSE)
    {
        conn = swServer_connection_verify(serv, session_id);
    }
    else
    {
        conn = swServer_connection_verify_no_ssl(serv, session_id);
    }
    if (!conn)
    {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_NOT_EXIST, "connection[fd=%d] does not exists.", session_id);
        return SW_ERR;
    }
    else if ((conn->closed || conn->removed) && resp->info.type != SW_EVENT_CLOSE)
    {
        int _len = resp->length > 0 ? resp->length : resp->info.len;
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_CLOSED, "send %d byte failed, because connection[fd=%d] is closed.", _len, session_id);
        return SW_ERR;
    }
    else if (conn->overflow)
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_OUTPUT_BUFFER_OVERFLOW, "send failed, connection[fd=%d] output buffer has been overflowed.", session_id);
        return SW_ERR;
    }

    swEventData ev_data;
    ev_data.info.fd = session_id;
    ev_data.info.type = resp->info.type;
    swWorker *worker = swServer_get_worker(serv, SwooleWG.id);

    /**
     * Big response, use shared memory
     */
    if (resp->length > 0)
    {
        if (worker == NULL || worker->send_shm == NULL)
        {
            goto pack_data;
        }

        //worker process
        if (SwooleG.main_reactor)
        {
            int _pipe_fd = swWorker_get_send_pipe(serv, session_id, conn->from_id);
            swConnection *_pipe_socket = swReactor_get(SwooleG.main_reactor, _pipe_fd);

            //cannot use send_shm
            if (!swBuffer_empty(_pipe_socket->out_buffer))
            {
                pack_data:
                if (swTaskWorker_large_pack(&ev_data, resp->data, resp->length) < 0)
                {
                    return SW_ERR;
                }
                ev_data.info.from_fd = SW_RESPONSE_TMPFILE;
                goto send_to_reactor_thread;
            }
        }

        swPackage_response response;
        response.length = resp->length;
        response.worker_id = SwooleWG.id;
        ev_data.info.from_fd = SW_RESPONSE_SHM;
        ev_data.info.len = sizeof(response);
        memcpy(ev_data.data, &response, sizeof(response));

        swTrace("[Worker] big response, length=%d|worker_id=%d", response.length, response.worker_id);

        worker->lock.lock(&worker->lock);
        memcpy(worker->send_shm, resp->data, resp->length);
    }
    else
    {
        //copy data
        memcpy(ev_data.data, resp->data, resp->info.len);

        ev_data.info.len = resp->info.len;
        ev_data.info.from_fd = SW_RESPONSE_SMALL;
    }

    send_to_reactor_thread: ev_data.info.from_id = conn->from_id;
    sendn = ev_data.info.len + sizeof(resp->info);

    swTrace("[Worker] send: sendn=%d|type=%d|content=%s", sendn, resp->info.type, resp->data);
    ret = swWorker_send2reactor(&ev_data, sendn, session_id);
    if (ret < 0)
    {
        swWarn("sendto to reactor failed. Error: %s [%d]", strerror(errno), errno);
    }
    return ret;
}

```

### `swTaskWorker_large_pack` 函数


```c
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

int swoole_tmpfile(char *filename)
{
#if defined(HAVE_MKOSTEMP) && defined(HAVE_EPOLL)
    int tmp_fd = mkostemp(filename, O_WRONLY | O_CREAT);
#else
    int tmp_fd = mkstemp(filename);
#endif

    if (tmp_fd < 0)
    {
        swSysError("mkstemp(%s) failed.", filename);
        return SW_ERR;
    }
    else
    {
        return tmp_fd;
    }
}

int swoole_sync_writefile(int fd, void *data, int len)
{
    int n = 0;
    int count = len, towrite, written = 0;

    while (count > 0)
    {
        towrite = count;
        if (towrite > SW_FILE_CHUNK_SIZE)
        {
            towrite = SW_FILE_CHUNK_SIZE;
        }
        n = write(fd, data, towrite);
        if (n > 0)
        {
            data += n;
            count -= n;
            written += n;
        }
        else if (n == 0)
        {
            break;
        }
        else
        {
            if (errno == EINTR || errno == EAGAIN)
            {
                continue;
            }
            swSysError("write(%d, %d) failed.", fd, towrite);
            break;
        }
    }
    return written;
}

```

### `swWorker_send2reactor` 发送数据

- `swWorker_send2reactor` 函数专门负责将 `swEventData` 数据发送到 `pipefd` 的缓冲区中，其使用的是 `main_reactor->write` 方法，我们之前在 `reactor` 中已经了解过。
- `swWorker_get_send_pipe` 用于计算发送给客户端的 `pipefd`。我们知道，用户可以在任何 `worker` 中调用 `swoole_server->send(int $fd, string $data, int $extraData = 0)` 向客户端发送数据，但是其中的 `fd` 并不一定是本 `worker` 进程负责的 `session_id`。我们可以从 `session_id` 中获取到 `swConnection`，进而获取到 `reactor_id` 线程，但是我们无法确定当前该连接被分配给了那个 `worker`。因此为了均衡各个 `worker`，首先计算出平均每个 `reactor` 负责的 `worker` 数量 `reactor_pipe_num`，然后利用 `session_id` 以取模的方式随机选择其中一个 `worker`，然后计算出该 `worker` 的 `id`，进而取出其 `pipe_worker`

```c
serv->reactor_pipe_num = serv->worker_num / serv->reactor_num

static sw_inline int swWorker_get_send_pipe(swServer *serv, int session_id, int reactor_id)
{
    int pipe_index = session_id % serv->reactor_pipe_num;
    /**
     * pipe_worker_id: The pipe in which worker.
     */
    int pipe_worker_id = reactor_id + (pipe_index * serv->reactor_num);
    swWorker *worker = swServer_get_worker(serv, pipe_worker_id);
    return worker->pipe_worker;
}

int swWorker_send2reactor(swEventData *ev_data, size_t sendn, int session_id)
{
    int ret;
    swServer *serv = SwooleG.serv;
    int _pipe_fd = swWorker_get_send_pipe(serv, session_id, ev_data->info.from_id);

    if (SwooleG.main_reactor)
    {
        ret = SwooleG.main_reactor->write(SwooleG.main_reactor, _pipe_fd, ev_data, sendn);
    }
    else
    {
        ret = swSocket_write_blocking(_pipe_fd, ev_data, sendn);
    }
    return ret;
}

```

## `swFactoryProcess_end` 关闭连接

当用户主动调用 `swoole_server->close` 函数的时候，就会调用本函数。`swFactoryProcess_end` 函数主要用于调用 `onClose` 函数，进而调用 ``swFactoryProcess_finish` 函数`

```c
static int swFactoryProcess_end(swFactory *factory, int fd)
{
    swServer *serv = factory->ptr;
    swSendData _send;
    swDataHead info;

    bzero(&_send, sizeof(_send));
    _send.info.fd = fd;
    _send.info.len = 0;
    _send.info.type = SW_EVENT_CLOSE;

    swConnection *conn = swWorker_get_connection(serv, fd);
    if (conn == NULL || conn->active == 0)
    {
        SwooleG.error = SW_ERROR_SESSION_NOT_EXIST;
        return SW_ERR;
    }
    else if (conn->close_force)
    {
        goto do_close;
    }
    else if (conn->closing)
    {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_CLOSING, "The connection[%d] is closing.", fd);
        return SW_ERR;
    }
    else if (conn->closed)
    {
        return SW_ERR;
    }
    else
    {
        do_close:
        conn->closing = 1;
        if (serv->onClose != NULL)
        {
            info.fd = fd;
            if (conn->close_actively)
            {
                info.from_id = -1;
            }
            else
            {
                info.from_id = conn->from_id;
            }
            info.from_fd = conn->from_fd;
            serv->onClose(serv, &info);
        }
        conn->closing = 0;
        conn->closed = 1;
        conn->close_errno = 0;
        return factory->finish(factory, &_send);
    }
}

```

