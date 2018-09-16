# Swoole 源码分析——内存模块之内存池

## 前言

`Swoole` 中为了更好的进行内存管理，减少频繁分配释放内存空间造成的损耗和内存碎片，程序设计并实现了三种不同功能的内存池：`FixedPool`，`RingBuffer` 和 `MemoryGlobal`。

其中 `MemoryGlobal` 用于全局变量 `SwooleG.memory_pool`，`RingBuffer` 用于 `reactor` 线程的缓冲区，`FixedPool` 用于 `swoole_table` 共享内存表。 

## `swMemoryPool` 内存池数据结构

无论是哪种内存池，它的基础数据结构都是 `swMemoryPool`:

```
typedef struct _swMemoryPool
{
	void *object;
	void* (*alloc)(struct _swMemoryPool *pool, uint32_t size);
	void (*free)(struct _swMemoryPool *pool, void *ptr);
	void (*destroy)(struct _swMemoryPool *pool);
} swMemoryPool;

```

可以看出来， `swMemoryPool` 更加类似于接口，规定了内存池需要定义的函数。

## `MemoryGlobal` 内存池实现

### `MemoryGlobal` 数据结构

首先看一下 `MemoryGlobal` 的数据结构：

```
typedef struct _swMemoryGlobal_page
{
    struct _swMemoryGlobal_page *next;
    char memory[0];
} swMemoryGlobal_page;

typedef struct _swMemoryGlobal
{
    uint8_t shared;
    uint32_t pagesize;
    swLock lock;
    swMemoryGlobal_page *root_page;
    swMemoryGlobal_page *current_page;
    uint32_t current_offset;
} swMemoryGlobal;

```
可以很明显的看出，`MemoryGlobal` 实际上就是一个单链表，`root_page` 是链表的头，`current_page` 就是链表的尾，`current_offset` 指的是最后一个链表元素的偏移量。

比较特殊的是 `MemoryGlobal` 单链表内存池的内存只能增加不会减少。

### `MemoryGlobal` 的创建

```
#define SW_MIN_PAGE_SIZE  4096

swMemoryPool* swMemoryGlobal_new(uint32_t pagesize, uint8_t shared)
{
    swMemoryGlobal gm, *gm_ptr;
    assert(pagesize >= SW_MIN_PAGE_SIZE);
    bzero(&gm, sizeof(swMemoryGlobal));

    gm.shared = shared;
    gm.pagesize = pagesize;

    swMemoryGlobal_page *page = swMemoryGlobal_new_page(&gm);
    if (page == NULL)
    {
        return NULL;
    }
    if (swMutex_create(&gm.lock, shared) < 0)
    {
        return NULL;
    }

    gm.root_page = page;

    gm_ptr = (swMemoryGlobal *) page->memory;
    gm.current_offset += sizeof(swMemoryGlobal);

    swMemoryPool *allocator = (swMemoryPool *) (page->memory + gm.current_offset);
    gm.current_offset += sizeof(swMemoryPool);

    allocator->object = gm_ptr;
    allocator->alloc = swMemoryGlobal_alloc;
    allocator->destroy = swMemoryGlobal_destroy;
    allocator->free = swMemoryGlobal_free;

    memcpy(gm_ptr, &gm, sizeof(gm));
    return allocator;
}

```

- 可以看到，每次申请创建 `MemoryGlobal` 内存不得小于 `2k`
- 创建的 `MemoryGlobal` 的 `current_offset` 被初始化为 `swMemoryGlobal` 与 `swMemoryPool` 的大小之和
- 返回的 `allocator` 类型是 `swMemoryPool`，其内存结构为：

	|  swMemoryGlobal | swMemoryPool | memory |
	| --- | --- | --- |

```
static swMemoryGlobal_page* swMemoryGlobal_new_page(swMemoryGlobal *gm)
{
    swMemoryGlobal_page *page = (gm->shared == 1) ? sw_shm_malloc(gm->pagesize) : sw_malloc(gm->pagesize);
    if (page == NULL)
    {
        return NULL;
    }
    bzero(page, gm->pagesize);
    page->next = NULL;

    if (gm->current_page != NULL)
    {
        gm->current_page->next = page;
    }

    gm->current_page = page;
    gm->current_offset = 0;

    return page;
}

```
链表元素的创建比较简单，就是申请内存，初始化单链表的各个变量。

### `MemoryGlobal` 内存的申请

```
static void *swMemoryGlobal_alloc(swMemoryPool *pool, uint32_t size)
{
    swMemoryGlobal *gm = pool->object;
    gm->lock.lock(&gm->lock);
    if (size > gm->pagesize - sizeof(swMemoryGlobal_page))
    {
        swWarn("failed to alloc %d bytes, exceed the maximum size[%d].", size, gm->pagesize - (int) sizeof(swMemoryGlobal_page));
        gm->lock.unlock(&gm->lock);
        return NULL;
    }
    if (gm->current_offset + size > gm->pagesize - sizeof(swMemoryGlobal_page))
    {
        swMemoryGlobal_page *page = swMemoryGlobal_new_page(gm);
        if (page == NULL)
        {
            swWarn("swMemoryGlobal_alloc alloc memory error.");
            gm->lock.unlock(&gm->lock);
            return NULL;
        }
        gm->current_page = page;
    }
    void *mem = gm->current_page->memory + gm->current_offset;
    gm->current_offset += size;
    gm->lock.unlock(&gm->lock);
    return mem;
}

```
- 申请内存之前需要先将互斥锁加锁以防多个线程或多个进程同时申请内存，导致数据混乱。
- 如果申请的内存大于单个链表元素的 `pagesize`，直接返回错误。
- 如果当前链表元素剩余的内存不足，那么就会重新申请一个新的链表元素
- 设置 `current_offset`，解锁互斥锁，返回内存地址。

### `MemoryGlobal` 内存的释放与销毁

```
static void swMemoryGlobal_free(swMemoryPool *pool, void *ptr)
{
    swWarn("swMemoryGlobal Allocator don't need to release.");
}

static void swMemoryGlobal_destroy(swMemoryPool *poll)
{
    swMemoryGlobal *gm = poll->object;
    swMemoryGlobal_page *page = gm->root_page;
    swMemoryGlobal_page *next;

    do
    {
        next = page->next;
        sw_shm_free(page);
        page = next;
    } while (page);
}

```

- `MemoryGlobal` 不需要进行内存的释放
- `MemoryGlobal` 的销毁就是循环单链表，然后释放内存

## `RingBuffer` 内存池实现

### `RingBuffer` 的数据结构

`RingBuffer` 类似于一个循环数组，每一次申请的一块内存在该数组中占据一个位置，这些内存块是可以不等长的，因此每个内存块需要有一个记录其长度的变量。

```
typedef struct
{
    uint16_t lock;
    uint16_t index;
    uint32_t length;
    char data[0];
} swRingBuffer_item;

typedef struct
{
    uint8_t shared;
    uint8_t status;
    uint32_t size;
    uint32_t alloc_offset;
    uint32_t collect_offset;
    uint32_t alloc_count;
    sw_atomic_t free_count;
    void *memory;
} swRingBuffer;

```

- `swRingBuffer` 中非常重要的成员变量是 `alloc_offset` 与 `collect_offset`，`alloc_offset` 是当前循环数组中的起始地址，`collect_offset` 代表当前循环数组中可以被回收的内存地址。
- `free_count` 是当前循环数组中可以被回收的个数。
- `status` 为 0 代表循环数组当前占用的内存空间并没有越过数组的结尾，也就是其地址是连续的，为 1 代表循环数组当前占用的内存空间一部分在循环数组的尾部，一部分在数组的头部。 

### `RingBuffer` 的创建

`RingBuffer` 的创建类似于 `MemoryGlobal`：


| RingBuffer | swMemoryPool | memory |
| --- | --- | --- |
	

```
swMemoryPool *swRingBuffer_new(uint32_t size, uint8_t shared)
{
    void *mem = (shared == 1) ? sw_shm_malloc(size) : sw_malloc(size);
    if (mem == NULL)
    {
        swWarn("malloc(%d) failed.", size);
        return NULL;
    }

    swRingBuffer *object = mem;
    mem += sizeof(swRingBuffer);
    bzero(object, sizeof(swRingBuffer));

    object->size = (size - sizeof(swRingBuffer) - sizeof(swMemoryPool));
    object->shared = shared;

    swMemoryPool *pool = mem;
    mem += sizeof(swMemoryPool);

    pool->object = object;
    pool->destroy = swRingBuffer_destory;
    pool->free = swRingBuffer_free;
    pool->alloc = swRingBuffer_alloc;

    object->memory = mem;

    swDebug("memory: ptr=%p", mem);

    return pool;
}

```

### `RingBuffer` 内存的申请

- 若 `free_count` 大于 0，说明此时数组中有待回收的内存，需要进行内存回收
- 若当前占用的内存不是连续的，那么当前内存池剩余的容量就是 `collect_offset - alloc_offset`
- 若当前占用的内存是连续的，
	- 而且数组当前 `collect_offset` 距离尾部的内存大于申请的内存数，那么剩余的容量就是 `size - alloc_offset`
	- 数组当前内存位置距离尾部容量不足，那么就将当前内存到数组尾部打包成为一个 `swRingBuffer_item` 数组元素，并标志为待回收元素，设置 `status` 为 1，设置 `alloc_offset` 为数组首地址，此时剩余的容量就是 `collect_offset` 的地址

```
static void* swRingBuffer_alloc(swMemoryPool *pool, uint32_t size)
{
    assert(size > 0);

    swRingBuffer *object = pool->object;
    swRingBuffer_item *item;
    uint32_t capacity;

    uint32_t alloc_size = size + sizeof(swRingBuffer_item);

    if (object->free_count > 0)
    {
        swRingBuffer_collect(object);
    }

    if (object->status == 0)
    {
        if (object->alloc_offset + alloc_size >= (object->size - sizeof(swRingBuffer_item)))
        {
            uint32_t skip_n = object->size - object->alloc_offset;
            if (skip_n >= sizeof(swRingBuffer_item))
            {
                item = object->memory + object->alloc_offset;
                item->lock = 0;
                item->length = skip_n - sizeof(swRingBuffer_item);
                sw_atomic_t *free_count = &object->free_count;
                sw_atomic_fetch_add(free_count, 1);
            }
            object->alloc_offset = 0;
            object->status = 1;
            capacity = object->collect_offset - object->alloc_offset;
        }
        else
        {
            capacity = object->size - object->alloc_offset;
        }
    }
    else
    {
        capacity = object->collect_offset - object->alloc_offset;
    }

    if (capacity < alloc_size)
    {
        return NULL;
    }

    item = object->memory + object->alloc_offset;
    item->lock = 1;
    item->length = size;
    item->index = object->alloc_count;

    object->alloc_offset += alloc_size;
    object->alloc_count ++;

    swDebug("alloc: ptr=%p", (void * )((void * )item->data - object->memory));

    return item->data;
}

```

### `RingBuffer` 内存的回收

- 当 `RingBuffer` 的 `free_count` 大于 0 的时候，就说明当前内存池存在需要回收的元素，每次在申请新的内存时，都会调用这个函数来回收内存。
- 回收内存时，本函数只会回收连续的多个空余的内存元素，若多个待回收的内存元素之间相互隔离，那么这些内存元素不会被回收。

```
static void swRingBuffer_collect(swRingBuffer *object)
{
    swRingBuffer_item *item;
    sw_atomic_t *free_count = &object->free_count;

    int count = object->free_count;
    int i;
    uint32_t n_size;

    for (i = 0; i < count; i++)
    {
        item = object->memory + object->collect_offset;
        if (item->lock == 0)
        {
            n_size = item->length + sizeof(swRingBuffer_item);

            object->collect_offset += n_size;

            if (object->collect_offset + sizeof(swRingBuffer_item) >object->size || object->collect_offset >= object->size)
            {
                object->collect_offset = 0;
                object->status = 0;
            }
            sw_atomic_fetch_sub(free_count, 1);
        }
        else
        {
            break;
        }
    }
}

```

### `RingBuffer` 内存的释放

内存的释放很简单，只需要设置 `lock` 为 0，并且增加 `free_count` 的数量即可：

```
static void swRingBuffer_free(swMemoryPool *pool, void *ptr)
{
    swRingBuffer *object = pool->object;
    swRingBuffer_item *item = ptr - sizeof(swRingBuffer_item);

    assert(ptr >= object->memory);
    assert(ptr <= object->memory + object->size);
    assert(item->lock == 1);

    if (item->lock != 1)
    {
        swDebug("invalid free: index=%d, ptr=%p", item->index,  (void * )((void * )item->data - object->memory));
    }
    else
    {
        item->lock = 0;
    }

    swDebug("free: ptr=%p", (void * )((void * )item->data - object->memory));

    sw_atomic_t *free_count = &object->free_count;
    sw_atomic_fetch_add(free_count, 1);
}

```

### `RingBuffer` 内存的销毁

```
static void swRingBuffer_destory(swMemoryPool *pool)
{
    swRingBuffer *object = pool->object;
    if (object->shared)
    {
        sw_shm_free(object);
    }
    else
    {
        sw_free(object);
    }
}

```

- 值得注意的是，`RingBuffer` 除了原子锁之外就没有任何锁了，在申请与释放过程的代码中也没有看出来是线程安全的无锁数据结构，个人认为 `RingBuffer` 并非是线程安全/进程安全的数据结构，因此利用这个内存池申请共享内存时，需要自己进行加锁。

## `FixedPool` 内存池实现

### `FixedPool` 数据结构

`FixedPool` 是随机分配内存池，将一整块内存空间切分成等大小的一个个小块，每次分配其中的一个小块作为要使用的内存，这些小块以双向链表的形式存储。

```
typedef struct _swFixedPool_slice
{
    uint8_t lock;
    struct _swFixedPool_slice *next;
    struct _swFixedPool_slice *pre;
    char data[0];

} swFixedPool_slice;

typedef struct _swFixedPool
{
    void *memory;
    size_t size;

    swFixedPool_slice *head;
    swFixedPool_slice *tail;

    /**
     * total memory size
     */
    uint32_t slice_num;

    /**
     * memory usage
     */
    uint32_t slice_use;

    /**
     * Fixed slice size, not include the memory used by swFixedPool_slice
     */
    uint32_t slice_size;

    /**
     * use shared memory
     */
    uint8_t shared;

} swFixedPool;

```

### `FixedPool` 内存池的创建

`FixedPool` 内存池的创建有两个函数 `swFixedPool_new` 与 `swFixedPool_new2`，其中 `swFixedPool_new2` 是利用已有的内存基础上来构建内存池，这个也是 `table` 共享内存表创建的方法。

```
swMemoryPool* swFixedPool_new2(uint32_t slice_size, void *memory, size_t size)
{
    swFixedPool *object = memory;
    memory += sizeof(swFixedPool);
    bzero(object, sizeof(swFixedPool));

    object->slice_size = slice_size;
    object->size = size - sizeof(swMemoryPool) - sizeof(swFixedPool);
    object->slice_num = object->size / (slice_size + sizeof(swFixedPool_slice));

    swMemoryPool *pool = memory;
    memory += sizeof(swMemoryPool);
    bzero(pool, sizeof(swMemoryPool));

    pool->object = object;
    pool->alloc = swFixedPool_alloc;
    pool->free = swFixedPool_free;
    pool->destroy = swFixedPool_destroy;

    object->memory = memory;

    /**
     * init linked list
     */
    swFixedPool_init(object);

    return pool;
}

```

内存池的创建和前两个大同小异，只是这次多了 `swFixedPool_init` 这个构建双向链表的过程：

```
static void swFixedPool_init(swFixedPool *object)
{
    swFixedPool_slice *slice;
    void *cur = object->memory;
    void *max = object->memory + object->size;
    do
    {
        slice = (swFixedPool_slice *) cur;
        bzero(slice, sizeof(swFixedPool_slice));

        if (object->head != NULL)
        {
            object->head->pre = slice;
            slice->next = object->head;
        }
        else
        {
            object->tail = slice;
        }

        object->head = slice;
        cur += (sizeof(swFixedPool_slice) + object->slice_size);

        if (cur < max)
        {
            slice->pre = (swFixedPool_slice *) cur;
        }
        else
        {
            slice->pre = NULL;
            break;
        }

    } while (1);
}

```

可以看出来，程序从内存空间的首部开始，每次初始化一个 `slice` 大小的空间，并插入到链表的头部，因此整个链表的内存地址和 `memory` 的地址是相反的。

### `FixedPool` 内存池的申请

```
static void* swFixedPool_alloc(swMemoryPool *pool, uint32_t size)
{
    swFixedPool *object = pool->object;
    swFixedPool_slice *slice;

    slice = object->head;

    if (slice->lock == 0)
    {
        slice->lock = 1;
        object->slice_use ++;
        /**
         * move next slice to head (idle list)
         */
        object->head = slice->next;
        
        slice->next->pre = NULL;

        /*
         * move this slice to tail (busy list)
         */
        object->tail->next = slice;
        slice->next = NULL;
        slice->pre = object->tail;
        object->tail = slice;

        return slice->data;
    }
    else
    {
        return NULL;
    }
}

```
- 首先获取内存池链表首部的节点，并判断该节点是否被占用，如果被占用，说明内存池已满，返回null（因为所有被占用的节点都会被放到尾部）；如果未被占用，则将该节点的下一个节点移到首部，并将该节点移动到尾部，标记该节点为占用状态，返回该节点的数据域。


### `FixedPool` 内存池的释放

```
static void swFixedPool_free(swMemoryPool *pool, void *ptr)
{
    swFixedPool *object = pool->object;
    swFixedPool_slice *slice;

    assert(ptr > object->memory && ptr < object->memory + object->size);

    slice = ptr - sizeof(swFixedPool_slice);

    if (slice->lock)
    {
        object->slice_use--;
    }

    slice->lock = 0;

    //list head, AB
    if (slice->pre == NULL)
    {
        return;
    }
    //list tail, DE
    if (slice->next == NULL)
    {
        slice->pre->next = NULL;
        object->tail = slice->pre;
    }
    //middle BCD
    else
    {
        slice->pre->next = slice->next;
        slice->next->pre = slice->pre;
    }

    slice->pre = NULL;
    slice->next = object->head;
    object->head->pre = slice;
    object->head = slice;
}

```

- 首先通过移动 `ptr` 指针获得 `slice` 对象，并将占用标记 `lock` 置为 0。如果该节点为头节点，则直接返回。如果不是头节点，则将该节点移动到链表头部。 

### `FixedPool` 内存池的销毁

```
static void swFixedPool_destroy(swMemoryPool *pool)
{
    swFixedPool *object = pool->object;
    if (object->shared)
    {
        sw_shm_free(object);
    }
    else
    {
        sw_free(object);
    }
}

```
