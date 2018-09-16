# Swoole 源码分析——Server模块之Timer模块

## 前言

`swoole` 的 `timer` 模块功能有三个：用户定时任务、剔除空闲连接、更新 `server` 时间。`timer` 模块的底层有两种，一种是基于 `alarm` 信号，一种是基于 `timefd`。

## `timer` 数据结构

`timer` 数据结构是 `swTimer`。其中 `heap` 是多个 `swTimer_node` 类型构成的一个数据堆，该数据堆按照下一次执行时间来排序，下次执行时间离当前时间越近，元素的位置越靠前；`map` 是 `swTimer_node` 类型的 `map`，其 `key` 是 `swTimer_node` 类型的 `id`，该数据结构可以通过 `id` 快速查找对应的 `swTimer_node` 元素；`num` 是 `swTimer_node` 元素个数；`use_pipe` 标志着 `worker` 进程中是否使用管道 `pipe` 来获知 `alarm` 信号已触发；`fd` 用于 `timefd`；`_current_id` 是当前最大 `swTimer_node` 的 `id`；`_next_id `就是下一个新建的 `swTimer_node` 的 `id` 值，是 `_current_id` + 1；`_next_msec` 是下次检查定时器的时间。

`_swTimer_node` 中 `heap_node` 是 `_swTimer` 中的数据堆元素；`data` 一般存储 `server`；`callback` 是定时器触发后需要执行的回调函数；`exec_msec` 是该元素应该执行的时间；`id` 是元素在 `swTimer` 中的 `id`；`type` 有三种：`SW_TIMER_TYPE_KERNEL`（`server` 内置定时函数）、`SW_TIMER_TYPE_CORO`（协程定时函数）、`SW_TIMER_TYPE_PHP`(`PHP` 定时函数)

```
struct _swTimer
{
    /*--------------timerfd & signal timer--------------*/
    swHeap *heap;
    swHashMap *map;
    int num;
    int use_pipe;
    int lasttime;
    int fd;
    long _next_id;
    long _current_id;
    long _next_msec;
    swPipe pipe;
    /*-----------------for EventTimer-------------------*/
    struct timeval basetime;
    /*--------------------------------------------------*/
    int (*set)(swTimer *timer, long exec_msec);
    swTimer_node* (*add)(swTimer *timer, int _msec, int persistent, void *data, swTimerCallback callback);
};

struct _swTimer_node
{
    swHeap_node *heap_node;
    void *data;
    swTimerCallback callback;
    int64_t exec_msec;
    uint32_t interval;
    long id;
    int type;                 //0 normal node 1 node for client_coro
    uint8_t remove;
};

```  

## `Timer` 定时器

### `swTimer_init` 创建定时器

- 创建定时器需要给定一个间隔时间，每隔这个时间就要检查 `swTimer` 中的 `_swTimer_node` 元素，如果时间已经超过了 `_swTimer_node` 元素的 `exec_msec` 时间，就要执行定时函数。
- `swTimer_now` 函数初始化 `basetime`：`swTimer_now` 函数可以获取当前时间，使用的是 `clock_gettime` 与 `CLOCK_MONOTONIC` 获取绝对时间，或者使用 `gettimeofday` 函数
- 如果是 `worker` 进程，那么调用 `swSystemTimer_init` 函数对定时器进行初始化；如果是 `master` 进程，那么调用 `swReactorTimer_init` 进行初始化


```
int swTimer_now(struct timeval *time)
{
#if defined(SW_USE_MONOTONIC_TIME) && defined(CLOCK_MONOTONIC)
    struct timespec _now;
    if (clock_gettime(CLOCK_MONOTONIC, &_now) < 0)
    {
        swSysError("clock_gettime(CLOCK_MONOTONIC) failed.");
        return SW_ERR;
    }
    time->tv_sec = _now.tv_sec;
    time->tv_usec = _now.tv_nsec / 1000;
#else
    if (gettimeofday(time, NULL) < 0)
    {
        swSysError("gettimeofday() failed.");
        return SW_ERR;
    }
#endif
    return SW_OK;
}

int swTimer_init(long msec)
{
    if (swTimer_now(&SwooleG.timer.basetime) < 0)
    {
        return SW_ERR;
    }


    SwooleG.timer.heap = swHeap_new(1024, SW_MIN_HEAP);
    if (!SwooleG.timer.heap)
    {
        return SW_ERR;
    }

    SwooleG.timer.map = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, NULL);
    if (!SwooleG.timer.map)
    {
        swHeap_free(SwooleG.timer.heap);
        SwooleG.timer.heap = NULL;
        return SW_ERR;
    }

    SwooleG.timer._current_id = -1;
    SwooleG.timer._next_msec = msec;
    SwooleG.timer._next_id = 1;
    SwooleG.timer.add = swTimer_add;

    if (swIsTaskWorker())
    {
        swSystemTimer_init(msec, SwooleG.use_timer_pipe);
    }
    else
    {
        swReactorTimer_init(msec);
    }

    return SW_OK;
}
```

### `swReactorTimer_init` 初始化

对于 `master` 进程，只需要设置 `main_reactor` 的超时时间即可，当发生超时事件之后，`main_reactor` 会调用 `onTimeout` 函数；或者一个事件循环最后，会调用 `onFinish` 函数；这两个函数都会最终调用 `swTimer_select`，来筛选那些已经到了执行时间的元素。

```
static int swReactorTimer_init(long exec_msec)
{
    SwooleG.main_reactor->check_timer = SW_TRUE;
    SwooleG.main_reactor->timeout_msec = exec_msec;
    SwooleG.timer.set = swReactorTimer_set;
    SwooleG.timer.fd = -1;
    return SW_OK;
}

static int swReactorEpoll_wait(swReactor *reactor, struct timeval *timeo)
{
    ...
    
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
    
    while (reactor->running > 0)
    {
        msec = reactor->timeout_msec;
        n = epoll_wait(epoll_fd, events, max_event_num, msec);
        if (n < 0)
        {
           ...
        }
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
        
        ...
    }
    
    ...
}

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
    
    ...
}

```

### `swSystemTimer_init` 初始化

- 对于 `worker` 进程来说，由于定时任务比较多而且复杂，就不能简单使用 `reactor` 超时来实现功能。
- `swSystemTimer_init` 采用 `SIGALRM` 闹钟信号或者 `timefd` 来触发中断 `reactor` 的等待。
- 对于 `timefd` 来说，需要使用 `timerfd_settime` 系统调用来设置超时时间，然后将 `timefd` 加入 `worker` 的 `reactor` 监控中，将其当做文件描述符来监控。当其就绪时，会调用 `swTimer_select` 执行定时函数。
- 对于普通 `SIGALRM` 信号来说，将 `timer->pipe` 放入 `reactor` 的监控中，使用 `setitimer` 来定时触发 `SIGALRM` 信号，设置信号处理函数。信号处理函数中，会向 `timer->pipe` 写入数据，进而触发 `swTimer_select` 执行定时函数。


```
int swSystemTimer_init(int interval, int use_pipe)
{
    swTimer *timer = &SwooleG.timer;
    timer->lasttime = interval;

#ifndef HAVE_TIMERFD
    SwooleG.use_timerfd = 0;
#endif

    if (SwooleG.use_timerfd)
    {
        if (swSystemTimer_timerfd_set(timer, interval) < 0)
        {
            return SW_ERR;
        }
        timer->use_pipe = 0;
    }
    else
    {
        if (use_pipe)
        {
            if (swPipeNotify_auto(&timer->pipe, 0, 0) < 0)
            {
                return SW_ERR;
            }
            timer->fd = timer->pipe.getFd(&timer->pipe, 0);
            timer->use_pipe = 1;
        }
        else
        {
            timer->fd = 1;
            timer->use_pipe = 0;
        }

        if (swSystemTimer_signal_set(timer, interval) < 0)
        {
            return SW_ERR;
        }
        swSignal_add(SIGALRM, swSystemTimer_signal_handler);
    }

    if (timer->fd > 1)
    {
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_TIMER, swSystemTimer_event_handler);
        SwooleG.main_reactor->add(SwooleG.main_reactor, SwooleG.timer.fd, SW_FD_TIMER);
    }
    timer->set = swSystemTimer_set;
    return SW_OK;
}

```

### `swSystemTimer_timerfd_set` 设置 `timefd` 

- 该函数目的是使用 `timerfd_settime` 系统调用，该系统调用需要 `timefd` 和 `itimerspec` 类型对象
- `timefd` 可以由 `timerfd_create` 系统函数创建
- `itimerspec` 对象需要当前时间和 `interval` 间隔时间共同设置。`it_value` 是首次超时时间，需要填写当前时间，并加上要超时的时间，值得注意的是 `tv_nsec` 加上去后一定要判断是否超出1000000000（如果超过要秒加一），否则会设置失败；`it_interval` 是后续周期性超时时间。

```
static int swSystemTimer_timerfd_set(swTimer *timer, long interval)
{

    struct timeval now;
    int sec = interval / 1000;
    int msec = (((float) interval / 1000) - sec) * 1000;

    if (gettimeofday(&now, NULL) < 0)
    {
        swWarn("gettimeofday() failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }

    struct itimerspec timer_set;
    bzero(&timer_set, sizeof(timer_set));

    if (interval < 0)
    {
        if (timer->fd == 0)
        {
            return SW_OK;
        }
    }
    else
    {
        timer_set.it_interval.tv_sec = sec;
        timer_set.it_interval.tv_nsec = msec * 1000 * 1000;

        timer_set.it_value.tv_sec = now.tv_sec + sec;
        timer_set.it_value.tv_nsec = (now.tv_usec * 1000) + timer_set.it_interval.tv_nsec;

        if (timer_set.it_value.tv_nsec > 1e9)
        {
            timer_set.it_value.tv_nsec = timer_set.it_value.tv_nsec - 1e9;
            timer_set.it_value.tv_sec += 1;
        }

        if (timer->fd == 0)
        {
            timer->fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK | TFD_CLOEXEC);
            if (timer->fd < 0)
            {
                swWarn("timerfd_create() failed. Error: %s[%d]", strerror(errno), errno);
                return SW_ERR;
            }
        }
    }

    if (timerfd_settime(timer->fd, TFD_TIMER_ABSTIME, &timer_set, NULL) == -1)
    {
        swWarn("timerfd_settime() failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }
    return SW_OK;
#else
    swWarn("kernel not support timerfd.");
    return SW_ERR;
#endif
}

```

### `swSystemTimer_signal_set` 设置信号超时时间

- `setitimer` 是一个比较常用的函数，可用来实现延时和定时的功能。
	- `ITIMER_REAL`：以系统真实的时间来计算，它送出 `SIGALRM` 信号。
	- `ITIMER_VIRTUAL`：以该进程在用户态下花费的时间来计算，它送出 `SIGVTALRM` 信号。
	- `ITIMER_PROF`：以该进程在用户态下和内核态下所费的时间来计算，它送出 `SIGPROF` 信号。
	- `it_interval` 为计时间隔，`it_value` 为延时时长，也就是距离现有时间第一次延迟触发的相对时间，而不是绝对时间。（所以我认为代码中 `gettimeofday` 函数是多余的，并不需要获取当前时间）


```
 */
static int swSystemTimer_signal_set(swTimer *timer, long interval)
{
    struct itimerval timer_set;
    int sec = interval / 1000;
    int msec = (((float) interval / 1000) - sec) * 1000;

    struct timeval now;
    if (gettimeofday(&now, NULL) < 0)
    {
        swWarn("gettimeofday() failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }
    bzero(&timer_set, sizeof(timer_set));

    if (interval > 0)
    {
        timer_set.it_interval.tv_sec = sec;
        timer_set.it_interval.tv_usec = msec * 1000;

        timer_set.it_value.tv_sec = sec;
        timer_set.it_value.tv_usec = timer_set.it_interval.tv_usec;

        if (timer_set.it_value.tv_usec > 1e6)
        {
            timer_set.it_value.tv_usec = timer_set.it_value.tv_usec - 1e6;
            timer_set.it_value.tv_sec += 1;
        }
    }

    if (setitimer(ITIMER_REAL, &timer_set, NULL) < 0)
    {
        swWarn("setitimer() failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }
    return SW_OK;
}

```

### `swSystemTimer_signal_handler` 超时信号处理函数

`swSystemTimer_signal_handler` 函数是 `SIGALARM` 信号的处理函数，该函数被触发说明 `epoll_wait` 函数被闹钟信号中断，此时本函数向 `timer.pipe` 写入数据，然后即返回。`reactor` 会检测到 `timer.pipe` 的写就绪，进而调用对应的回调函数 `swSystemTimer_event_handler` 

```
void swSystemTimer_signal_handler(int sig)
{
    SwooleG.signal_alarm = 1;
    uint64_t flag = 1;

    if (SwooleG.timer.use_pipe)
    {
        SwooleG.timer.pipe.write(&SwooleG.timer.pipe, &flag, sizeof(flag));
    }
}

```

### `swSystemTimer_event_handler` 写就绪回调函数

写就绪回调函数可能是由 `timer.pipe` 的写就绪触发，也可能是 `timefd` 的写就绪触发，无论哪个都会调用 `swTimer_select` 函数执行对应的定时函数。

```
int swSystemTimer_event_handler(swReactor *reactor, swEvent *event)
{
    uint64_t exp;
    swTimer *timer = &SwooleG.timer;

    if (read(timer->fd, &exp, sizeof(uint64_t)) != sizeof(uint64_t))
    {
        return SW_ERR;
    }
    SwooleG.signal_alarm = 0;
    return swTimer_select(timer);
}

```

### `swTimer_add` 添加元素

- `swTimer_add` 用于添加定时函数元素。本函数逻辑比较简单，新建一个 `swTimer_node` 对象，初始化赋值之后加入到 `timer->heap` 中，程序会自动根据其 `exec_msec` 进行有小到大的排序，然后再更新 `timer->map` 哈希表。
- 值得注意的是，当新添加的定时函数需要执行的时间小于当前 `timer` 下次执行时间的时候，我们需要调用 `timer->set` 函数更新 `time` 的间隔时间。在 `master` 进程中，这个 `set` 函数是 `swReactorTimer_set`，用于设置 `reactor` 的超时时间；在 `worker` 进程中，`set` 函数是 `swSystemTimer_set`，用于更新 `timerfd_settime` 或 `setitimer` 函数。
 
```
static swTimer_node* swTimer_add(swTimer *timer, int _msec, int interval, void *data, swTimerCallback callback)
{
    swTimer_node *tnode = sw_malloc(sizeof(swTimer_node));
    if (!tnode)
    {
        swSysError("malloc(%ld) failed.", sizeof(swTimer_node));
        return NULL;
    }

    int64_t now_msec = swTimer_get_relative_msec();
    if (now_msec < 0)
    {
        sw_free(tnode);
        return NULL;
    }

    tnode->data = data;
    tnode->type = SW_TIMER_TYPE_KERNEL;
    tnode->exec_msec = now_msec + _msec;
    tnode->interval = interval ? _msec : 0;
    tnode->remove = 0;
    tnode->callback = callback;

    if (timer->_next_msec < 0 || timer->_next_msec > _msec)
    {
        timer->set(timer, _msec);
        timer->_next_msec = _msec;
    }

    tnode->id = timer->_next_id++;
    if (unlikely(tnode->id < 0))
    {
        tnode->id = 1;
        timer->_next_id = 2;
    }
    timer->num++;

    tnode->heap_node = swHeap_push(timer->heap, tnode->exec_msec, tnode);
    if (tnode->heap_node == NULL)
    {
        sw_free(tnode);
        return NULL;
    }
    swHashMap_add_int(timer->map, tnode->id, tnode);
    return tnode;
}

static int swSystemTimer_set(swTimer *timer, long new_interval)
{
    if (new_interval == current_interval)
    {
        return SW_OK;
    }
    current_interval = new_interval;
    if (SwooleG.use_timerfd)
    {
        return swSystemTimer_timerfd_set(timer, new_interval);
    }
    else
    {
        return swSystemTimer_signal_set(timer, new_interval);
    }
}

```

### `swTimer_del` 删除元素

```
int swTimer_del(swTimer *timer, swTimer_node *tnode)
{
    if (tnode->remove)
    {
        return SW_FALSE;
    }
    if (SwooleG.timer._current_id > 0 && tnode->id == SwooleG.timer._current_id)
    {
        tnode->remove = 1;
        return SW_TRUE;
    }
    if (swHashMap_del_int(timer->map, tnode->id) < 0)
    {
        return SW_ERR;
    }
    if (tnode->heap_node)
    {
        //remove from min-heap
        swHeap_remove(timer->heap, tnode->heap_node);
        sw_free(tnode->heap_node);
    }
    sw_free(tnode);
    timer->num --;
    return SW_TRUE;
}
```

### `swTimer_select` 筛选定时函数

- `swTimer_select` 函数的筛选原理是从 `timer->heap` 中不断 `pop` 出定时元素，比较它们的 `exec_msec` 是否超过了当前时间，如果超过了时间，就执行对应的定时函数；如果没有超过，由于 `timer->heap` 是排序过后的数据堆，因此当前定时元素之后的都不会超过当前时间，也就是还没有到执行的时间。
- 如果当前的定时元素超过了当前时间，说明该元素应该执行定时函数。设置 `timer->_current_id` 为当前的 `id` 后，执行 `tnode->callback` 回调函数；如果当前定时元素不是一次执行的任务，而是需要每隔一段时间定时的任务，就要再次将元素放入 `timer->heap` 中；如果当前定时元素是一次执行的任务，就要将元素从 `timer->map`、`timer->map` 中删除
- 循环结束后，`tnode` 就是下一个要执行的定时元素，我们需要调用 `timer->set` 函数设置闹钟信号（`worker` 进程）或者 `reactor` 超时时间（`master` 进程）。

```
int swTimer_select(swTimer *timer)
{
    int64_t now_msec = swTimer_get_relative_msec();
    if (now_msec < 0)
    {
        return SW_ERR;
    }

    swTimer_node *tnode = NULL;
    swHeap_node *tmp;
    long timer_id;

    while ((tmp = swHeap_top(timer->heap)))
    {
        tnode = tmp->data;
        if (tnode->exec_msec > now_msec)
        {
            break;
        }

        timer_id = timer->_current_id = tnode->id;
        if (!tnode->remove)
        {
            tnode->callback(timer, tnode);
        }
        timer->_current_id = -1;

        //persistent timer
        if (tnode->interval > 0 && !tnode->remove)
        {
            while (tnode->exec_msec <= now_msec)
            {
                tnode->exec_msec += tnode->interval;
            }
            swHeap_change_priority(timer->heap, tnode->exec_msec, tmp);
            continue;
        }

        timer->num--;
        swHeap_pop(timer->heap);
        swHashMap_del_int(timer->map, timer_id);
        sw_free(tnode);
    }

    if (!tnode || !tmp)
    {
        timer->_next_msec = -1;
        timer->set(timer, -1);
    }
    else
    {
        timer->set(timer, tnode->exec_msec - now_msec);
    }
    return SW_OK;
}

```

## `Timer` 定时器的使用

### `master` 进程	 `swServer_start_proxy`

`timer` 模块在 `master` 进程中最重要的作用是每隔一秒更新 `serv->gs->now` 的值。除此之外，当 `reactor` 线程调度 `worker` 进程时，如果一段时间内没有任何空闲的 `worker` 进程空闲，`timer` 模块还负责写入错误日志。

```
static int swServer_start_proxy(swServer *serv)
{
    ...
    if (swTimer_init(1000) < 0)
    {
        return SW_ERR;
    }
    
    if (SwooleG.timer.add(&SwooleG.timer, 1000, 1, serv, swServer_master_onTimer) == NULL)
    {
        return SW_ERR;
    }
    ...
}

void swServer_master_onTimer(swTimer *timer, swTimer_node *tnode)
{
    swServer *serv = (swServer *) tnode->data;
    swServer_update_time(serv);
    if (serv->scheduler_warning && serv->warning_time < serv->gs->now)
    {
        serv->scheduler_warning = 0;
        serv->warning_time = serv->gs->now;
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SERVER_NO_IDLE_WORKER, "No idle worker is available.");
    }

    if (serv->hooks[SW_SERVER_HOOK_MASTER_TIMER])
    {
        swServer_call_hook(serv, SW_SERVER_HOOK_MASTER_TIMER, serv);
    }
}

void swServer_update_time(swServer *serv)
{
    time_t now = time(NULL);
    if (now < 0)
    {
        swWarn("get time failed. Error: %s[%d]", strerror(errno), errno);
    }
    else
    {
        serv->gs->now = now;
    }
}
```

### `worker` 进程超时停止

`worker` 进程将要停止时，并不会立刻停止，而是会等待事件循环结束后停止，这时为了防止 `worker` 进程不退出，还设置了 30s 的延迟，超过 30s 就会停止该进程。

```
static void swWorker_stop()
{
    swWorker *worker = SwooleWG.worker;
    swServer *serv = SwooleG.serv;
    worker->status = SW_WORKER_BUSY;
    
    ...

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

```

### `swoole_timer_tick` 添加定时任务

`timer` 模块另一个非常重要的功能是添加定时任务，一般是使用 `swoole_timer_tick` 函数、`swoole_timer_after` 函数、`swoole_server->tick` 函数、`swoole_server->after` 函数：
 
```
PHP_FUNCTION(swoole_timer_tick)
{
    long after_ms;
    zval *callback;
    zval *param = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lz|z", &after_ms, &callback, &param) == FAILURE)
    {
        return;
    }

    long timer_id = php_swoole_add_timer(after_ms, callback, param, 1 TSRMLS_CC);
    if (timer_id < 0)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_LONG(timer_id);
    }
}

PHP_FUNCTION(swoole_timer_after)
{
    long after_ms;
    zval *callback;
    zval *param = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lz|z", &after_ms, &callback, &param) == FAILURE)
    {
        return;
    }

    long timer_id = php_swoole_add_timer(after_ms, callback, param, 0 TSRMLS_CC);
    if (timer_id < 0)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_LONG(timer_id);
    }
}
```

### `php_swoole_add_timer` 函数

本函数主要调用 `SwooleG.timer.add` 函数将添加新的定时任务，值得注意的是 `swTimer_callback` 类型的对象 `cb` 和两个回调函数 `php_swoole_onInterval`、`php_swoole_onTimeout`，真正的回调函数存放在了 `swTimer_callback` 对象中，如果用户有参数设置，也会放入 `cb->data` 中。

```
long php_swoole_add_timer(int ms, zval *callback, zval *param, int persistent TSRMLS_DC)
{
    char *func_name = NULL;

    if (!swIsTaskWorker())
    {
        php_swoole_check_reactor();
    }

    php_swoole_check_timer(ms);
    swTimer_callback *cb = emalloc(sizeof(swTimer_callback));

    cb->data = &cb->_data;
    cb->callback = &cb->_callback;
    memcpy(cb->callback, callback, sizeof(zval));
    if (param)
    {
        memcpy(cb->data, param, sizeof(zval));
    }
    else
    {
        cb->data = NULL;
    }

    swTimerCallback timer_func;
    if (persistent)
    {
        cb->type = SW_TIMER_TICK;
        timer_func = php_swoole_onInterval;
    }
    else
    {
        cb->type = SW_TIMER_AFTER;
        timer_func = php_swoole_onTimeout;
    }

    sw_zval_add_ref(&cb->callback);
    if (cb->data)
    {
        sw_zval_add_ref(&cb->data);
    }

    swTimer_node *tnode = SwooleG.timer.add(&SwooleG.timer, ms, persistent, cb, timer_func);
    {
        tnode->type = SW_TIMER_TYPE_PHP;
        return tnode->id;
    }
}

void php_swoole_check_timer(int msec)
{
    if (unlikely(SwooleG.timer.fd == 0))
    {
        swTimer_init(msec);
    }
}

```

### `php_swoole_onInterval` 函数

本函数主要调用 `cb->callback`，如果有用户参数，还要将 `cb->data` 放入调用函数中。


```
void php_swoole_onInterval(swTimer *timer, swTimer_node *tnode)
{
    zval *retval = NULL;
    int argc = 1;

    zval *ztimer_id;

    swTimer_callback *cb = tnode->data;

    SW_MAKE_STD_ZVAL(ztimer_id);
    ZVAL_LONG(ztimer_id, tnode->id);

    {
        zval **args[2];
        if (cb->data)
        {
            argc = 2;
            sw_zval_add_ref(&cb->data);
            args[1] = &cb->data;
        }
        args[0] = &ztimer_id;

        if (sw_call_user_function_ex(EG(function_table), NULL, cb->callback, &retval, argc, args, 0, NULL TSRMLS_CC) == FAILURE)
        {
            swoole_php_fatal_error(E_WARNING, "swoole_timer: onTimerCallback handler error");
            return;
        }
    }

    if (tnode->remove)
    {
        php_swoole_del_timer(tnode TSRMLS_CC);
    }
}


```

### `php_swoole_onTimeout` 函数

与上一个函数类似，只是这次直接从 `timer` 中删除对应的元素。


```
void php_swoole_onTimeout(swTimer *timer, swTimer_node *tnode)
{
    {
        swTimer_callback *cb = tnode->data;
        zval *retval = NULL;

        {
            zval **args[2];
            int argc;

            if (NULL == cb->data)
            {
                argc = 0;
                args[0] = NULL;
            }
            else
            {
                argc = 1;
                args[0] = &cb->data;
            }

            if (sw_call_user_function_ex(EG(function_table), NULL, cb->callback, &retval, argc, args, 0, NULL TSRMLS_CC) == FAILURE)
            {
                swoole_php_fatal_error(E_WARNING, "swoole_timer: onTimeout handler error");
                return;
            }
        }

        php_swoole_del_timer(tnode TSRMLS_CC);
    }
}

```

## `Timer` 模块时间轮算法

时间轮算法是各大网络模块采用的剔除空闲连接的方法，原理是构建一个首尾相连的循环数组，每隔数组元素中有若干个连接。如果某个连接有数据发送过来，将连接从所在的数组元素中删除，将连接放入最新的数组元素中，这样有数据来往的连接会一直在新数组元素中，空闲的连接所在的数组元素渐渐的变成了旧数组元素。每隔一段时间就按顺序清空旧数组元素的全部连接。


### `swTimeWheel_new` 创建时间轮

时间轮的数据结构比较简单，由哈希表、`size`（循环数组总数量），`current` （循环数组当前最旧的数组元素，`current-1` 是循环数组中最新的数组元素）。`swTimeWheel_new` 函数很简单，就是创建这三个属性。

```
typedef struct
{
    uint16_t current;
    uint16_t size;
    swHashMap **wheel;

} swTimeWheel;

swTimeWheel* swTimeWheel_new(uint16_t size)
{
    swTimeWheel *tw = sw_malloc(sizeof(swTimeWheel));
    if (!tw)
    {
        swWarn("malloc(%ld) failed.", sizeof(swTimeWheel));
        return NULL;
    }

    tw->size = size;
    tw->current = 0;
    tw->wheel = sw_calloc(size, sizeof(void*));
    if (tw->wheel == NULL)
    {
        swWarn("malloc(%ld) failed.", sizeof(void*) * size);
        sw_free(tw);
        return NULL;
    }

    int i;
    for (i = 0; i < size; i++)
    {
        tw->wheel[i] = swHashMap_new(16, NULL);
        if (tw->wheel[i] == NULL)
        {
            swTimeWheel_free(tw);
            return NULL;
        }
    }
    return tw;
}
```


### `swTimeWheel_add` 添加连接

当 `main_reactor` 有新连接进入的时候，需要将新的连接添加到时间轮中，新的连接会被放到最新的数组元素中，也就是 `current-1` 的元素中，然后设置 `swConnection` 中的 `timewheel_index`。

```
void swTimeWheel_add(swTimeWheel *tw, swConnection *conn)
{
    uint16_t index = tw->current == 0 ? tw->size - 1 : tw->current - 1;
    swHashMap *new_set = tw->wheel[index];
    swHashMap_add_int(new_set, conn->fd, conn);

    conn->timewheel_index = index;

    swTraceLog(SW_TRACE_REACTOR, "current=%d, fd=%d, index=%d.", tw->current, conn->fd, index);
}

```

### `swTimeWheel_update` 函数

当连接有数据传输的时候，需要更新该连接在时间轮中的位置，将该连接从原有的数组元素中删除，然后添加到最新的数组元素中，也就是 `current-1` 中，然后更新 `swConnection` 中的 `timewheel_index`。

```
#define swTimeWheel_new_index(tw)   (tw->current == 0 ? tw->size - 1 : tw->current - 1)

void swTimeWheel_update(swTimeWheel *tw, swConnection *conn)
{
    uint16_t new_index = swTimeWheel_new_index(tw);
    swHashMap *new_set = tw->wheel[new_index];
    swHashMap_add_int(new_set, conn->fd, conn);

    swHashMap *old_set = tw->wheel[conn->timewheel_index];
    swHashMap_del_int(old_set, conn->fd);

    swTraceLog(SW_TRACE_REACTOR, "current=%d, fd=%d, old_index=%d, new_index=%d.", tw->current, conn->fd, new_index, conn->timewheel_index);

    conn->timewheel_index = new_index;
}

```

### `swTimeWheel_remove` 函数

在时间轮中删除该连接，

```
void swTimeWheel_remove(swTimeWheel *tw, swConnection *conn)
{
    swHashMap *set = tw->wheel[conn->timewheel_index];
    swHashMap_del_int(set, conn->fd);
    swTraceLog(SW_TRACE_REACTOR, "current=%d, fd=%d.", tw->current, conn->fd);
}

```

### `swTimeWheel_forward` 删除空闲连接

`swTimeWheel_forward` 将最旧的数组元素 `current` 中所有连接都关闭掉，然后将 `current` 递增。

```
void swTimeWheel_forward(swTimeWheel *tw, swReactor *reactor)
{
    swHashMap *set = tw->wheel[tw->current];
    tw->current = tw->current == tw->size - 1 ? 0 : tw->current + 1;

    swTraceLog(SW_TRACE_REACTOR, "current=%d.", tw->current);

    swConnection *conn;
    uint64_t fd;

    while (1)
    {
        conn = swHashMap_each_int(set, &fd);
        if (conn == NULL)
        {
            break;
        }

        conn->close_force = 1;
        conn->close_notify = 1;
        conn->close_wait = 1;
        conn->close_actively = 1;

        //notify to reactor thread
        if (conn->removed)
        {
            reactor->close(reactor, (int) fd);
        }
        else
        {
            reactor->set(reactor, fd, SW_FD_TCP | SW_EVENT_WRITE);
        }
    }
}
```

### `reactor` 线程中时间轮的创建

- 时间轮的创建在 `reactor` 线程进行事件循环之前，按照用户设置的连接最大空闲时间设置不同大小的时间轮，值得注意的是，时间轮最大是 `SW_TIMEWHEEL_SIZE`，也就是循环数组大小最大是 60。如果超过 60s 空闲时间，也仅仅建立 60 个元素的数组，但是这样会造成每个数组元素存放更多的连接。
- 值得注意的是，当允许空闲时间超过 60s 时，`heartbeat_interval * 1000` 是 `reactor` 的超时时间，例如空闲时间是 60s，那么每隔 6s，`reactor` 都会超时来检测空闲连接。当允许空闲时间小于 60s 时，`reactor` 统一每隔 1s 检测空闲连接。
- 不同于 `master` 进程和 `worker` 线程，`reactor` 的 `onFinish` 和 `onTimeout` 不再采用默认的 `swReactor_onTimeout` 与 `swReactor_onFinish` 函数，而是采用空闲连接检测的 `swReactorThread_onReactorCompleted` 函数，该函数会调用 `swTimeWheel_forward` 来剔除空闲连接。

```
#define SW_TIMEWHEEL_SIZE          60

static int swReactorThread_loop(swThreadParam *param)
{
    ...
    
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
    
    reactor->wait(reactor, NULL);
}
``` 


### `reactor` 线程中时间轮的添加 

当有新连接的时候，`conn->connect_notify` 会被置为 1，此时该连接文件描述符写就绪，然后就会调用 `swReactorThread_onWrite`，此时 `reactor` 线程将该连接添加到时间轮中。

```
static int swReactorThread_onWrite(swReactor *reactor, swEvent *ev)
{
    ...
    
    if (conn->connect_notify)
    {
        conn->connect_notify = 0;
        if (reactor->timewheel)
        {
            swTimeWheel_add(reactor->timewheel, conn);
        }
        
        ...
    }
    ...
}

```

### `reactor` 线程中时间轮的更新

```
static int swReactorThread_onRead(swReactor *reactor, swEvent *event)
{
    ...
    if (reactor->timewheel && swTimeWheel_new_index(reactor->timewheel) != event->socket->timewheel_index)
    {
        swTimeWheel_update(reactor->timewheel, event->socket);
    }
    ...
}


```

### `reactor` 线程中时间轮的剔除

当连接在允许的空闲时间之内没有任何数据发送，那么时间轮算法就要关闭该连接。关闭连接并不是直接 `close` 套接字，而是需要通知对应的 `worker` 进程调用 `onClose` 函数，然后才能关闭。具体的做法是设置 `swConnection` 的 `close_force`、`close_notify` 等成员变量为 1，并且关闭该连接的读就绪监听事件。


```
static void swReactorThread_onReactorCompleted(swReactor *reactor)
{
    swServer *serv = reactor->ptr;
    if (reactor->heartbeat_interval > 0 && reactor->last_heartbeat_time < serv->gs->now - reactor->heartbeat_interval)
    {
        swTimeWheel_forward(reactor->timewheel, reactor);
        reactor->last_heartbeat_time = serv->gs->now;
    }
}

void swTimeWheel_forward(swTimeWheel *tw, swReactor *reactor)
{
    ...
    
    conn->close_force = 1;
    conn->close_notify = 1;
    conn->close_wait = 1;
    conn->close_actively = 1;
    
    if (conn->removed)
    {
        reactor->close(reactor, (int) fd);
    }
    else
    {
        reactor->set(reactor, fd, SW_FD_TCP | SW_EVENT_WRITE);
    }
    ...
}

```

当该连接写就绪的时候，会调用 `swReactorThread_onWrite` 函数。这个时候就会调用 `swServer_tcp_notify` 函数，进而调用 `swFactoryProcess_notify`、`swFactoryProcess_dispatch`，最后调用 `swReactorThread_send2worker` 发送给了 `worker` 进程。

由于 `reactor` 启用的是水平触发，由于并未向该连接写入数据，因此很快又会触发写就绪事件调用 `swReactorThread_onWrite` 函数，这时如果 `disable_notify` 为 1（`dispatch_mode` 为 1 或 3），会直接执行 `swReactorThread_close` 函数关闭连接，假如此时 `conn->out_buffer` 中还有数据未发送，也会被抛弃。如果 `disable_notify` 为 0，则会继续向将要关闭的连接发送数据，直到接收到 `SW_CHUNK_CLOSE` 类型的消息。


```
static int swReactorThread_onWrite(swReactor *reactor, swEvent *ev)
{
    ...
    else if (conn->close_notify)
    {
        swServer_tcp_notify(serv, conn, SW_EVENT_CLOSE);
        conn->close_notify = 0;
        return SW_OK;
    }
    else if (serv->disable_notify && conn->close_force)
    {
        return swReactorThread_close(reactor, fd);
    }
    ...
}

int swServer_tcp_notify(swServer *serv, swConnection *conn, int event)
{
    swDataHead notify_event;
    notify_event.type = event;
    notify_event.from_id = conn->from_id;
    notify_event.fd = conn->fd;
    notify_event.from_fd = conn->from_fd;
    notify_event.len = 0;
    return serv->factory.notify(&serv->factory, &notify_event);
}

static int swFactoryProcess_notify(swFactory *factory, swDataHead *ev)
{
    memcpy(&sw_notify_data._send, ev, sizeof(swDataHead));
    sw_notify_data._send.len = 0;
    sw_notify_data.target_worker_id = -1;
    return factory->dispatch(factory, (swDispatchData *) &sw_notify_data);
}

static int swFactoryProcess_dispatch(swFactory *factory, swDispatchData *task)
{ 
   ...
   
   if (swEventData_is_stream(task->data.info.type))
   {
       swConnection *conn = swServer_connection_get(serv, fd);
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

`worker` 进程收到消息后会调用 `swWorker_onTask` 函数，进而调用 `swFactoryProcess_end` 函数，调用 `serv->onClose` 函数，并设置 `swConnection` 对象的 `closed` 为 1，然后调用 `swFactoryProcess_finish` 函数将数据包发送给 `reactor` 线程。

```
int swWorker_onTask(swFactory *factory, swEventData *task)
{
    switch (task->info.type)
    {
        ... 
        factory->end(factory, task->info.fd);
        break;
        ...
    }
}

static int swFactoryProcess_end(swFactory *factory, int fd)
{
    bzero(&_send, sizeof(_send));
    _send.info.fd = fd;
    _send.info.len = 0;
    _send.info.type = SW_EVENT_CLOSE;
   
   swConnection *conn = swWorker_get_connection(serv, fd);
   
   if (conn->close_force)
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

`reactor` 通过 `swReactorThread_onPipeReceive` 收到 `worker` 进程的连接关闭通知后，调用 `swReactorThread_send` 函数。如果连接已经被关闭，或者缓冲区中没有任何数据的时候，直接调用 `reactor->close` 函数，也就是 `swReactorThread_close` 函数；如果缓冲区还有数据，那么需要将消息放到 `conn->out_buffer` 中等待着该连接写就绪回调 `swReactorThread_close` 函数（此时 `close_notify` 已经为 0）。


```
int swReactorThread_send(swSendData *_send)
{
    ...
    if (_send->info.type == SW_EVENT_CLOSE && (conn->close_reset || conn->removed))
    {
        goto close_fd;
    }
    
    ...
    if (swBuffer_empty(conn->out_buffer))
    {
        if (_send->info.type == SW_EVENT_CLOSE)
        {
            close_fd:
            reactor->close(reactor, fd);
            return SW_OK;
        }
    }
    
    swBuffer_chunk *chunk;
    //close connection
    if (_send->info.type == SW_EVENT_CLOSE)
    {
        chunk = swBuffer_new_chunk(conn->out_buffer, SW_CHUNK_CLOSE, 0);
        chunk->store.data.val1 = _send->info.type;
    }
    
    if (reactor->set(reactor, fd, SW_EVENT_TCP | SW_EVENT_WRITE | SW_EVENT_READ) < 0
            && (errno == EBADF || errno == ENOENT))
    {
        goto close_fd;
    }

    ...
    close_fd:
        reactor->close(reactor, fd);
        return SW_OK;
}

static int swReactorThread_onWrite(swReactor *reactor, swEvent *ev)
{
    ...
    else if (conn->close_notify)
    {
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
        chunk = swBuffer_get_chunk(conn->out_buffer);
        if (chunk->type == SW_CHUNK_CLOSE)
        {
            close_fd: reactor->close(reactor, fd);
            return SW_OK;
        }
        ...
    }
    ...
}

```
`swReactorThread_close` 函数会删除 `swConnection` 在 `server` 中的所有痕迹，包括 `reactor` 中的监控，`serv->stats` 的成员变量，`port->connection_num` 递减，从时间轮中删除、`session` 中 `fd` 置空等等工作。而且，还要清空套接字缓存中的所有数据，直接向客户端发送关闭请求。`swReactor_close` 函数释放内存，关闭套接字文件描述符。

```
int swReactorThread_close(swReactor *reactor, int fd)
{
    swServer *serv = SwooleG.serv;

    if (conn->removed == 0 && reactor->del(reactor, fd) < 0)
    {
        return SW_ERR;
    }

    sw_atomic_fetch_add(&serv->stats->close_count, 1);
    sw_atomic_fetch_sub(&serv->stats->connection_num, 1);

    swTrace("Close Event.fd=%d|from=%d", fd, reactor->id);

    //free the receive memory buffer
    swServer_free_buffer(serv, fd);

    swListenPort *port = swServer_get_port(serv, fd);
    sw_atomic_fetch_sub(&port->connection_num, 1);

#ifdef SW_USE_SOCKET_LINGER
    if (conn->close_force)
    {
        struct linger linger;
        linger.l_onoff = 1;
        linger.l_linger = 0;
        if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(struct linger)) == -1)
        {
            swWarn("setsockopt(SO_LINGER) failed. Error: %s[%d]", strerror(errno), errno);
        }
    }
#endif

#ifdef SW_REACTOR_USE_SESSION
    swSession *session = swServer_get_session(serv, conn->session_id);
    session->fd = 0;
#endif

#ifdef SW_USE_TIMEWHEEL
    if (reactor->timewheel)
    {
        swTimeWheel_remove(reactor->timewheel, conn);
    }
#endif

    return swReactor_close(reactor, fd);
}

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