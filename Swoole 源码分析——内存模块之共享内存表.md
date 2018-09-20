# Swoole 源码分析——内存模块之共享内存表 

## 前言

`swoole_table` 一个基于共享内存和锁实现的超高性能，并发数据结构。用于解决多进程/多线程数据共享和同步加锁问题。

## `swoole_table` 的数据结构

- `swoole_table` 实际上就是一个开链法实现的哈希表，`memory` 是一个由哈希键与具体数据组成的数组，如果哈希冲突(不同的键值对应同一个哈希)，那么就会从 `pool` 中分配出一个元素作为数组元素的链表尾
- `size` 是创建共享内存表时设置的最大行数；`conflict_proportion` 是哈希冲突的最大比例，超过这个比例，共享内存表就不允许再添加新的行元素；`iterator` 是内存表的迭代器，可以利用它进行内存表数据的浏览；`columns` 是内存表的列元素集合，由于内存表的列元素也是一个 `key-value` 格式，因此也是一个哈希表 `swHashMap` 类型；`mask` 存放的是(最大行数-1)，专门进行哈希值与数组 `index` 的转化；`item_size` 是所有列元素的内存大小总和；

```c
typedef struct
{
    uint32_t absolute_index;
    uint32_t collision_index;
    swTableRow *row;
} swTable_iterator;

typedef struct
{
    swHashMap *columns;
    uint16_t column_num;
    swLock lock;
    size_t size;
    size_t mask;
    size_t item_size;
    size_t memory_size;
    float conflict_proportion;

    /**
     * total rows that in active state(shm)
     */
    sw_atomic_t row_num;

    swTableRow **rows;
    swMemoryPool *pool;

    swTable_iterator *iterator;

    void *memory;
} swTable;

```
- `swTableRow` 是内存表的行元素，其中 `lock` 是行锁；`active` 代表该行是否被启用；`next` 是哈希冲突的链表；`key` 是该行的键值，也就是哈希之前的原始键值;`data` 是真正的行数据，里面会加载各个列元素的值

```c
typedef struct _swTableRow
{
#if SW_TABLE_USE_SPINLOCK
    sw_atomic_t lock;
#else
    pthread_mutex_t lock;
#endif
    /**
     * 1:used, 0:empty
     */
    uint8_t active;
    /**
     * next slot
     */
    struct _swTableRow *next;
    /**
     * Hash Key
     */
    char key[SW_TABLE_KEY_SIZE];
    char data[0];
} swTableRow;

```
- `swTableColumn` 是内存表的单个列元素，`name` 是列的名字；`type` 是列的数据类型，可选参数为 `swoole_table_type`；`index` 说明当前的列元素在表列中的位置；`size` 是指列的数据类型占用的内存大小

```c
enum swoole_table_type
{
    SW_TABLE_INT = 1,
    SW_TABLE_INT8,
    SW_TABLE_INT16,
    SW_TABLE_INT32,
#ifdef __x86_64__
    SW_TABLE_INT64,
#endif
    SW_TABLE_FLOAT,
    SW_TABLE_STRING,
};

typedef struct
{
   uint8_t type;
   uint32_t size;
   swString* name;
   uint16_t index;
} swTableColumn;

```

## `swoole_table` 的构造

- `swoole_table->__construct(int $size, float $conflict_proportion = 0.2)` 这个共享内存表对象的创建对应于下面这个函数
- 哈希冲突百分比设定为最小 0.2，最大 1
- 行数并不是严格按照用户定义的数据而来，如果 `size` 不是为 2 的 `N` 次方，如 `1024`、`8192`,`65536` 等，底层会自动调整为接近的一个数字，如果小于 `1024` 则默认成 `1024`，即 `1024` 是最小值
- 创建过程中各个成员变量的意义可见上一小节

```c
swTable* swTable_new(uint32_t rows_size, float conflict_proportion)
{
    if (rows_size >= 0x80000000)
    {
        rows_size = 0x80000000;
    }
    else
    {
        uint32_t i = 10;
        while ((1U << i) < rows_size)
        {
            i++;
        }
        rows_size = 1 << i;
    }

    if (conflict_proportion > 1.0)
    {
        conflict_proportion = 1.0;
    }
    else if (conflict_proportion < SW_TABLE_CONFLICT_PROPORTION)
    {
        conflict_proportion = SW_TABLE_CONFLICT_PROPORTION;
    }

    swTable *table = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swTable));
    if (table == NULL)
    {
        return NULL;
    }
    if (swMutex_create(&table->lock, 1) < 0)
    {
        swWarn("mutex create failed.");
        return NULL;
    }
    table->iterator = sw_malloc(sizeof(swTable_iterator));
    if (!table->iterator)
    {
        swWarn("malloc failed.");
        return NULL;
    }
    table->columns = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, (swHashMap_dtor)swTableColumn_free);
    if (!table->columns)
    {
        return NULL;
    }

    table->size = rows_size;
    table->mask = rows_size - 1;
    table->conflict_proportion = conflict_proportion;

    bzero(table->iterator, sizeof(swTable_iterator));
    table->memory = NULL;
    return table;
}

```

## `swoole_table` 添加新的列

- `swoole_table->column(string $name, int $type, int $size = 0)` 对应下面的函数
- 列元素创建并初始化成功后，会调用 `swHashMap_add` 函数将列元素添加到 `table->columns` 中

```c
int swTableColumn_add(swTable *table, char *name, int len, int type, int size)
{
    swTableColumn *col = sw_malloc(sizeof(swTableColumn));
    if (!col)
    {
        return SW_ERR;
    }
    col->name = swString_dup(name, len);
    if (!col->name)
    {
        sw_free(col);
        return SW_ERR;
    }
    switch(type)
    {
    case SW_TABLE_INT:
        switch(size)
        {
        case 1:
            col->size = 1;
            col->type = SW_TABLE_INT8;
            break;
        case 2:
            col->size = 2;
            col->type = SW_TABLE_INT16;
            break;
#ifdef __x86_64__
        case 8:
            col->size = 8;
            col->type = SW_TABLE_INT64;
            break;
#endif
        default:
            col->size = 4;
            col->type = SW_TABLE_INT32;
            break;
        }
        break;
    case SW_TABLE_FLOAT:
        col->size = sizeof(double);
        col->type = SW_TABLE_FLOAT;
        break;
    case SW_TABLE_STRING:
        col->size = size + sizeof(swTable_string_length_t);
        col->type = SW_TABLE_STRING;
        break;
    default:
        swWarn("unkown column type.");
        swTableColumn_free(col);
        return SW_ERR;
    }
    col->index = table->item_size;
    table->item_size += col->size;
    table->column_num ++;
    return swHashMap_add(table->columns, name, len, col);
}

```

## `swoole_table` 的创建

- 通过 `swTable_get_memory_size` 函数计算整个共享内存表需要的内存总数，这个内存总数包含了哈希冲突需要的多余的内存占用。
- 申请了 `memory_size` 后，会将首地址赋值给 `table->rows`；值得注意的是 `table->rows` 是 `swTableRow **` 类型，后面还要通过循环给各个行元素赋值首地址
- 为了降低行锁的时间消耗，设置行锁为 `PTHREAD_PRIO_INHERIT`，提高行锁的优先级(如果更高优先级的线程因 `thrd1` 所拥有的一个或多个互斥锁而被阻塞,而这些互斥锁是用 `PTHREAD_PRIO_INHERIT` 初始化的,则 `thrd1` 的运行优先级为优先级 `pri1` 和优先级 `pri2` 中优先级较高的那一个,如果没有优先级继承，底优先级的线程可能会在很长一段时间内都得不到调度，而这会导致等待低优先级线程锁持有的锁的高优先级线程也等待很长时间（因为低优先级线程无法运行，因而就无法释放锁，所以高优先级线程只能继续阻塞在锁上）。使用优先级继承可以短时间的提高低优先级线程的优先级，从而使它可以尽快得到调度，然后释放锁。低优先级线程在释放锁后就会恢复自己的优先级。)
- `PTHREAD_MUTEX_ROBUST_NP`： 如果互斥锁的持有者“死亡”了，或者持有这样的互斥锁的进程 `unmap` 了互斥锁所在的共享内存或者持有这样的互斥锁的进程执行了 `exec` 调用，则会解除锁定该互斥锁。互斥锁的下一个持有者将获取该互斥锁,并返回错误 `EOWNWERDEAD`。
- `table->rows` 创建成功之后，就要对哈希冲突的行元素分配地址空间。可以看到，哈希冲突的行元素首地址为 `memory += row_memory_size * table->size`，并且利用已有的内存构建 `FixedPool` 随机内存池，`row_memory_size` 作为内存池内部元素的大小


```c
int swTable_create(swTable *table)
{
    size_t memory_size = swTable_get_memory_size(table);
    size_t row_memory_size = sizeof(swTableRow) + table->item_size;

    void *memory = sw_shm_malloc(memory_size);
    if (memory == NULL)
    {
        return SW_ERR;
    }

    table->memory_size = memory_size;
    table->memory = memory;

    table->rows = memory;
    memory += table->size * sizeof(swTableRow *);
    memory_size -= table->size * sizeof(swTableRow *);

#if SW_TABLE_USE_SPINLOCK == 0
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT);
    pthread_mutexattr_setrobust_np(&attr, PTHREAD_MUTEX_ROBUST_NP);
#endif

    int i;
    for (i = 0; i < table->size; i++)
    {
        table->rows[i] = memory + (row_memory_size * i);
        memset(table->rows[i], 0, sizeof(swTableRow));
#if SW_TABLE_USE_SPINLOCK == 0
        pthread_mutex_init(&table->rows[i]->lock, &attr);
#endif
    }

    memory += row_memory_size * table->size;
    memory_size -= row_memory_size * table->size;
    table->pool = swFixedPool_new2(row_memory_size, memory, memory_size);

    return SW_OK;
}

```
- 计算整个共享内存表的内存大小：
`(内存表行数+哈希冲突行数)*(行元素大小+各个列元素大小总和)+哈希冲突内存池头部大小+行元素指针大小*内存表行数`
- 比较难以理解的是最后那个 `行元素大小*内存表行数`，这个其实是在创建 `table->rows[table->size]` 这个指针数组，我们之前说过 `table->rows` 是个二维数组，这个数组里面存放的是多个 `swTableRow*` 类型的数据，例如 `table->rows[0]`等，`table->rows[0]` 等才是存放各个行元素首地址的地方，如果没有这个指针数组，那么每次去取行元素都要计算行元素的首地址，效率没有这么快。

```c
size_t swTable_get_memory_size(swTable *table)
{
    /**
     * table size + conflict size
     */
    size_t row_num = table->size * (1 + table->conflict_proportion);

    /*
     * header + data
     */
    size_t row_memory_size = sizeof(swTableRow) + table->item_size;

    /**
     * row data & header
     */
    size_t memory_size = row_num * row_memory_size;

    /**
     * memory pool for conflict rows
     */
    memory_size += sizeof(swMemoryPool) + sizeof(swFixedPool) + ((row_num - table->size) * sizeof(swFixedPool_slice));

    /**
     * for iterator, Iterate through all the elements
     */
    memory_size += table->size * sizeof(swTableRow *);

    return memory_size;
}

```

## `swoole_table` 添加新的数据

- 共享内存表添加新的元素需要调用三个函数，分别是 `swTableRow_set` 设置行的 `key` 值、`swTableColumn_get` 获取列元素，`swTableRow_set_value` 函数根据列的数据类型为 `row->data` 赋值，流程如下：

```c
static PHP_METHOD(swoole_table, set)
{
    zval *array;
    char *key;
    zend_size_t keylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sa", &key, &keylen, &array) == FAILURE)
    {
        RETURN_FALSE;
    }

    swTable *table = swoole_get_object(getThis());

    swTableRow *_rowlock = NULL;
    swTableRow *row = swTableRow_set(table, key, keylen, &_rowlock);

    swTableColumn *col;
    zval *v;
    char *k;
    uint32_t klen;
    int ktype;
    HashTable *_ht = Z_ARRVAL_P(array);

    SW_HASHTABLE_FOREACH_START2(_ht, k, klen, ktype, v)
    {
        col = swTableColumn_get(table, k, klen);

        else if (col->type == SW_TABLE_STRING)
        {
            convert_to_string(v);
            swTableRow_set_value(row, col, Z_STRVAL_P(v), Z_STRLEN_P(v));
        }
        else if (col->type == SW_TABLE_FLOAT)
        {
            convert_to_double(v);
            swTableRow_set_value(row, col, &Z_DVAL_P(v), 0);
        }
        else
        {
            convert_to_long(v);
            swTableRow_set_value(row, col, &Z_LVAL_P(v), 0);
        }
    }
    swTableRow_unlock(_rowlock);
}

```

### `swTableRow_set` 函数

- 我们先来看 `swTableRow_set` 函数，从下面的代码来看，这个函数主要的作用就是判断新添加的 `key` 是否造成了哈希冲突，如果没有冲突(`row->active=0`)，那么直接 `table->row_num` 自增，设置 `row->key` 就可以了。
- 如果发生哈希冲突，那么就要循环当前行元素的链表，直到（1）找到相同的 `key` 值，说明并不是真的发生了哈希冲突，而是用户要修改已有的行数据，那么就直接跳出函数，然后更改 `row->data` 的值；(2) 没有找到相同的 `key` 值，说明的确遇到了哈希冲突，不同的 `key` 值对应了相同的哈希值，此时已经循环到达链表的末尾，需要从内存池中构建出一个  `swTableRow` 行元素，放到链表的尾部

```c
swTableRow* swTableRow_set(swTable *table, char *key, int keylen, swTableRow **rowlock)
{
    if (keylen > SW_TABLE_KEY_SIZE)
    {
        keylen = SW_TABLE_KEY_SIZE;
    }

    swTableRow *row = swTable_hash(table, key, keylen);
    *rowlock = row;
    swTableRow_lock(row);

#ifdef SW_TABLE_DEBUG
    int _conflict_level = 0;
#endif

    if (row->active)
    {
        for (;;)
        {
            if (strncmp(row->key, key, keylen) == 0)
            {
                break;
            }
            else if (row->next == NULL)
            {
                table->lock.lock(&table->lock);
                swTableRow *new_row = table->pool->alloc(table->pool, 0);

#ifdef SW_TABLE_DEBUG
                conflict_count ++;
                if (_conflict_level > conflict_max_level)
                {
                    conflict_max_level = _conflict_level;
                }

#endif
                table->lock.unlock(&table->lock);

                if (!new_row)
                {
                    return NULL;
                }
                //add row_num
                bzero(new_row, sizeof(swTableRow));
                sw_atomic_fetch_add(&(table->row_num), 1);
                row->next = new_row;
                row = new_row;
                break;
            }
            else
            {
                row = row->next;
#ifdef SW_TABLE_DEBUG
                _conflict_level++;
#endif
            }
        }
    }
    else
    {
#ifdef SW_TABLE_DEBUG
        insert_count ++;
#endif
        sw_atomic_fetch_add(&(table->row_num), 1);
    }

    memcpy(row->key, key, keylen);
    row->active = 1;
    return row;
}

```

- 那么接下来我们看代码中 `swTable_hash` 这个函数是怎能计算哈希值的——我们发现哈希函数有两种:
	- `swoole_hash_php` 是 `php` 的经典哈希函数，也就是 `time33`/`DJB` 算法
	- `swoole_hash_austin` 是 `MurmurHash` 哈希算法，广泛应用在 `redis`、`Memcached` 等算法中
- 哈希计算之后，我们发现哈希值又与 `table->mask` 进行了逻辑与计算，目的是得到一个小于等于 `table->mask`(`rows_size - 1`) 的数字，作为行元素的 `index`

```c
static sw_inline swTableRow* swTable_hash(swTable *table, char *key, int keylen)
{
#ifdef SW_TABLE_USE_PHP_HASH
    uint64_t hashv = swoole_hash_php(key, keylen);
#else
    uint64_t hashv = swoole_hash_austin(key, keylen);
#endif
    uint64_t index = hashv & table->mask;
    assert(index < table->size);
    return table->rows[index];
}
```

- 我们接下来看行锁的加锁函数：
	- 若是普通的互斥锁，那么就直接使用 `pthread_mutex_lock` 即可，如果不是互斥锁，程序实现了一个自旋锁
	- 若是自旋锁，就调用 `swoole` 自定义的自旋锁加锁

```c
static sw_inline void swTableRow_lock(swTableRow *row)
{
#if SW_TABLE_USE_SPINLOCK
    sw_spinlock(&row->lock);
#else
    pthread_mutex_lock(&row->lock);
#endif
}
```

### `swTableColumn_get` 函数

从多个列元素组成的 `hashMap` 中根据 `column_key` 快速找到对应的列元素

```c
static sw_inline swTableColumn* swTableColumn_get(swTable *table, char *column_key, int keylen)
{
    return swHashMap_find(table->columns, column_key, keylen);
}

```

### `swTableRow_set_value` 函数

根据取出的列元素数据的类型，为 `row->data` 对应的位置上赋值，值得注意的是 `default` 实际上指的是 `SW_TABLE_STRING` 类型，这时会先储存字符串长度，再存储字符串值：

```c
static sw_inline void swTableRow_set_value(swTableRow *row, swTableColumn * col, void *value, int vlen)
{
    int8_t _i8;
    int16_t _i16;
    int32_t _i32;
#ifdef __x86_64__
    int64_t _i64;
#endif
    switch(col->type)
    {
    case SW_TABLE_INT8:
        _i8 = *(int8_t *) value;
        memcpy(row->data + col->index, &_i8, 1);
        break;
    case SW_TABLE_INT16:
        _i16 =  *(int16_t *) value;
        memcpy(row->data + col->index, &_i16, 2);
        break;
    case SW_TABLE_INT32:
        _i32 =  *(int32_t *) value;
        memcpy(row->data + col->index, &_i32, 4);
        break;
#ifdef __x86_64__
    case SW_TABLE_INT64:
        _i64 =  *(int64_t *) value;
        memcpy(row->data + col->index, &_i64, 8);
        break;
#endif
    case SW_TABLE_FLOAT:
        memcpy(row->data + col->index, value, sizeof(double));
        break;
    default:
        if (vlen > (col->size - sizeof(swTable_string_length_t)))
        {
            swWarn("[key=%s,field=%s]string value is too long.", row->key, col->name->str);
            vlen = col->size - sizeof(swTable_string_length_t);
        }
        memcpy(row->data + col->index, &vlen, sizeof(swTable_string_length_t));
        memcpy(row->data + col->index + sizeof(swTable_string_length_t), value, vlen);
        break;
    }
}

```

## `swoole_table` 获取数据

- 根据键值获取行元素需要调用三个函数：`swTableRow_get` 获取行对象元素，如果只取特定字段，那么会调用 `php_swoole_table_get_field_value`，如果需要去全部字段，那么会调用 `php_swoole_table_row2array`：

```c
static PHP_METHOD(swoole_table, get)
{
    char *key;
    zend_size_t keylen;

    char *field = NULL;
    zend_size_t field_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &key, &keylen, &field, &field_len) == FAILURE)
    {
        RETURN_FALSE;
    }

    swTableRow *_rowlock = NULL;
    swTable *table = swoole_get_object(getThis());

    swTableRow *row = swTableRow_get(table, key, keylen, &_rowlock);
    if (field && field_len > 0)
    {
        php_swoole_table_get_field_value(table, row, return_value, field, (uint16_t) field_len);
    }
    else
    {
        php_swoole_table_row2array(table, row, return_value);
    }
    swTableRow_unlock(_rowlock);
}

```

- `swTableRow_get` 函数 

利用 `key` 计算出行元素的 `index` 值，遇到存在哈希链表的情况，要不断对比 `key` 的值，直到找到完全相等的键值返回：

```c
swTableRow* swTableRow_get(swTable *table, char *key, int keylen, swTableRow** rowlock)
{
    if (keylen > SW_TABLE_KEY_SIZE)
    {
        keylen = SW_TABLE_KEY_SIZE;
    }

    swTableRow *row = swTable_hash(table, key, keylen);
    *rowlock = row;
    swTableRow_lock(row);

    for (;;)
    {
        if (strncmp(row->key, key, keylen) == 0)
        {
            if (!row->active)
            {
                row = NULL;
            }
            break;
        }
        else if (row->next == NULL)
        {
            row = NULL;
            break;
        }
        else
        {
            row = row->next;
        }
    }

    return row;
}

```

- `php_swoole_table_get_field_value` 函数

首先通过 `swHashMap_find` 函数根据 `field` 确定字段类型，如果是字符串，需要先获取字符串的长度：

```c
static inline void php_swoole_table_get_field_value(swTable *table, swTableRow *row, zval *return_value, char *field, uint16_t field_len)
{
    swTable_string_length_t vlen = 0;
    double dval = 0;
    int64_t lval = 0;

    swTableColumn *col = swHashMap_find(table->columns, field, field_len);
    
    if (col->type == SW_TABLE_STRING)
    {
        memcpy(&vlen, row->data + col->index, sizeof(swTable_string_length_t));
        SW_ZVAL_STRINGL(return_value, row->data + col->index + sizeof(swTable_string_length_t), vlen, 1);
    }
    else if (col->type == SW_TABLE_FLOAT)
    {
        memcpy(&dval, row->data + col->index, sizeof(dval));
        ZVAL_DOUBLE(return_value, dval);
    }
    else
    {
        switch (col->type)
        {
        case SW_TABLE_INT8:
            memcpy(&lval, row->data + col->index, 1);
            ZVAL_LONG(return_value, (int8_t) lval);
            break;
        case SW_TABLE_INT16:
            memcpy(&lval, row->data + col->index, 2);
            ZVAL_LONG(return_value, (int16_t) lval);
            break;
        case SW_TABLE_INT32:
            memcpy(&lval, row->data + col->index, 4);
            ZVAL_LONG(return_value, (int32_t) lval);
            break;
        default:
            memcpy(&lval, row->data + col->index, 8);
            ZVAL_LONG(return_value, lval);
            break;
        }
    }
}

```

### `php_swoole_table_row2array` 函数

与上一个函数相比，这个函数仅仅是换成了利用 `swHashMap_each` 遍历列元素，然后利用列元素取值的过程，取值之后，还有利用 `add_assoc_stringl_ex` 等 `zend` 的 `API`, 将值不断转化为 `PHP` 数组：

```c
#define sw_add_assoc_string                   add_assoc_string
#define sw_add_assoc_stringl_ex               add_assoc_stringl_ex
#define sw_add_assoc_stringl                  add_assoc_stringl
#define sw_add_assoc_double_ex                add_assoc_double_ex
#define sw_add_assoc_long_ex                  add_assoc_long_ex
#define sw_add_next_index_stringl             add_next_index_stringl

static inline void php_swoole_table_row2array(swTable *table, swTableRow *row, zval *return_value)
{
    array_init(return_value);

    swTableColumn *col = NULL;
    swTable_string_length_t vlen = 0;
    double dval = 0;
    int64_t lval = 0;
    char *k;

    while(1)
    {
        col = swHashMap_each(table->columns, &k);
        if (col == NULL)
        {
            break;
        }
        if (col->type == SW_TABLE_STRING)
        {
            memcpy(&vlen, row->data + col->index, sizeof(swTable_string_length_t));
            sw_add_assoc_stringl_ex(return_value, col->name->str, col->name->length + 1, row->data + col->index + sizeof(swTable_string_length_t), vlen, 1);
        }
        else if (col->type == SW_TABLE_FLOAT)
        {
            memcpy(&dval, row->data + col->index, sizeof(dval));
            sw_add_assoc_double_ex(return_value, col->name->str, col->name->length + 1, dval);
        }
        else
        {
            switch (col->type)
            {
            case SW_TABLE_INT8:
                memcpy(&lval, row->data + col->index, 1);
                sw_add_assoc_long_ex(return_value, col->name->str, col->name->length + 1, (int8_t) lval);
                break;
            case SW_TABLE_INT16:
                memcpy(&lval, row->data + col->index, 2);
                sw_add_assoc_long_ex(return_value, col->name->str, col->name->length + 1, (int16_t) lval);
                break;
            case SW_TABLE_INT32:
                memcpy(&lval, row->data + col->index, 4);
                sw_add_assoc_long_ex(return_value, col->name->str, col->name->length + 1, (int32_t) lval);
                break;
            default:
                memcpy(&lval, row->data + col->index, 8);
                sw_add_assoc_long_ex(return_value, col->name->str, col->name->length + 1, lval);
                break;
            }
        }
    }
}

```

## `swoole_table->incr` 字段值自增

```c
static PHP_METHOD(swoole_table, incr)
{
    char *key;
    zend_size_t key_len;
    char *col;
    zend_size_t col_len;
    zval* incrby = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|z", &key, &key_len, &col, &col_len, &incrby) == FAILURE)
    {
        RETURN_FALSE;
    }

    swTableRow *_rowlock = NULL;
    swTable *table = swoole_get_object(getThis());

    swTableRow *row = swTableRow_set(table, key, key_len, &_rowlock);

    swTableColumn *column;
    column = swTableColumn_get(table, col, col_len);
    if (column->type == SW_TABLE_STRING)
    {
        swTableRow_unlock(_rowlock);
        swoole_php_fatal_error(E_WARNING, "can't execute 'incr' on a string type column.");
        RETURN_FALSE;
    }
    else if (column->type == SW_TABLE_FLOAT)
    {
        double set_value = 0;
        memcpy(&set_value, row->data + column->index, sizeof(set_value));
        if (incrby)
        {
            convert_to_double(incrby);
            set_value += Z_DVAL_P(incrby);
        }
        else
        {
            set_value += 1;
        }
        swTableRow_set_value(row, column, &set_value, 0);
        RETVAL_DOUBLE(set_value);
    }
    else
    {
        int64_t set_value = 0;
        memcpy(&set_value, row->data + column->index, column->size);
        if (incrby)
        {
            convert_to_long(incrby);
            set_value += Z_LVAL_P(incrby);
        }
        else
        {
            set_value += 1;
        }
        swTableRow_set_value(row, column, &set_value, 0);
        RETVAL_LONG(set_value);
    }
    swTableRow_unlock(_rowlock);
}

```

## `swoole_table->incr` 字段值自减

```c
static PHP_METHOD(swoole_table, decr)
{
    char *key;
    zend_size_t key_len;
    char *col;
    zend_size_t col_len;
    zval *decrby = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|z", &key, &key_len, &col, &col_len, &decrby) == FAILURE)
    {
        RETURN_FALSE;
    }

    swTableRow *_rowlock = NULL;
    swTable *table = swoole_get_object(getThis());

    swTableRow *row = swTableRow_set(table, key, key_len, &_rowlock);

    swTableColumn *column;
    column = swTableColumn_get(table, col, col_len);
    if (column->type == SW_TABLE_STRING)
    {
        swTableRow_unlock(_rowlock);
        swoole_php_fatal_error(E_WARNING, "can't execute 'decr' on a string type column.");
        RETURN_FALSE;
    }
    else if (column->type == SW_TABLE_FLOAT)
    {
        double set_value = 0;
        memcpy(&set_value, row->data + column->index, sizeof(set_value));
        if (decrby)
        {
            convert_to_double(decrby);
            set_value -= Z_DVAL_P(decrby);
        }
        else
        {
            set_value -= 1;
        }
        swTableRow_set_value(row, column, &set_value, 0);
        RETVAL_DOUBLE(set_value);
    }
    else
    {
        int64_t set_value = 0;
        memcpy(&set_value, row->data + column->index, column->size);
        if (decrby)
        {
            convert_to_long(decrby);
            set_value -= Z_LVAL_P(decrby);
        }
        else
        {
            set_value -= 1;
        }
        swTableRow_set_value(row, column, &set_value, 0);
        RETVAL_LONG(set_value);
    }
    swTableRow_unlock(_rowlock);
}

```

## `swoole_table->del` 列表数据的删除

共享内存表的数据删除稍微有些复杂分为以下几个情况：

- 要删除的行元素没有哈希冲突的链表
	- 如果键值一致，那么利用 `bzero` 初始化该行元素，减小共享表行数
	- 如果键值不一致，说明并没有这行数据，那么直接解锁返回
- 要删除的行元素存在哈希冲突的链表，那么就要循环链表来找出键值一致的行元素
	- 如果遍历链表都没有找到，那么直接解锁返回
	- 如果发现是链表的头元素，那么将链表的第二个元素的数据赋值给头元素，然后从内存池中释放链表的第二个元素，减小共享表行数
	- 如果是链表的中间元素，那么和普通删除链表节点的方法一致，减小共享表行数

```c
int swTableRow_del(swTable *table, char *key, int keylen)
{
    if (keylen > SW_TABLE_KEY_SIZE)
    {
        keylen = SW_TABLE_KEY_SIZE;
    }

    swTableRow *row = swTable_hash(table, key, keylen);
    //no exists
    if (!row->active)
    {
        return SW_ERR;
    }

    swTableRow_lock(row);
    if (row->next == NULL)
    {
        if (strncmp(row->key, key, keylen) == 0)
        {
            bzero(row, sizeof(swTableRow) + table->item_size);
            goto delete_element;
        }
        else
        {
            goto not_exists;
        }
    }
    else
    {
        swTableRow *tmp = row;
        swTableRow *prev = NULL;

        while (tmp)
        {
            if ((strncmp(tmp->key, key, keylen) == 0))
            {
                break;
            }
            prev = tmp;
            tmp = tmp->next;
        }

        if (tmp == NULL)
        {
            not_exists:
            swTableRow_unlock(row);
            return SW_ERR;
        }

        //when the deleting element is root, we should move the first element's data to root,
        //and remove the element from the collision list.
        if (tmp == row)
        {
            tmp = tmp->next;
            row->next = tmp->next;
            memcpy(row->key, tmp->key, strlen(tmp->key));
            memcpy(row->data, tmp->data, table->item_size);
        }
        if (prev)
        {
            prev->next = tmp->next;
        }
        table->lock.lock(&table->lock);
        bzero(tmp, sizeof(swTableRow) + table->item_size);
        table->pool->free(table->pool, tmp);
        table->lock.unlock(&table->lock);
    }

    delete_element:
    sw_atomic_fetch_sub(&(table->row_num), 1);
    swTableRow_unlock(row);

    return SW_OK;
}

```

## `swoole_table->del` 列表数据的遍历

`swoole_table` 类实现了迭代器，可以使用 `foreach` 进行遍历。

```c
void swoole_table_init(int module_number TSRMLS_DC)
{
    #ifdef HAVE_PCRE
    zend_class_implements(swoole_table_class_entry_ptr TSRMLS_CC, 2, spl_ce_Iterator, spl_ce_Countable);
#endif
}

```

可以看到，`swoole` 在对 `swoole_table` 进行初始化的时候，为这个类继承了 `spl_iterator` 这个接口，我们知道，对继承了这个接口的类进行 `foreach`，不会触发原始的对象成员变量的遍历，而是会调用 `spl_iterator` 的 `rewind`、`next` 等方法：

```c
#ifdef HAVE_PCRE
static PHP_METHOD(swoole_table, rewind);
static PHP_METHOD(swoole_table, next);
static PHP_METHOD(swoole_table, current);
static PHP_METHOD(swoole_table, key);
static PHP_METHOD(swoole_table, valid);
#endif

```

关于为什么要 `PCRE` 这个正则表达式库的依赖，本人非常疑惑，希望有人能够解疑。

新版本 swoole 已经去除 PCRE 依赖！

### `rewind`

```c
static PHP_METHOD(swoole_table, rewind)
{
    swTable *table = swoole_get_object(getThis());
    if (!table->memory)
    {
        swoole_php_fatal_error(E_ERROR, "the swoole table does not exist.");
        RETURN_FALSE;
    }
    swTable_iterator_rewind(table);
    swTable_iterator_forward(table);
}

void swTable_iterator_rewind(swTable *table)
{
    bzero(table->iterator, sizeof(swTable_iterator));
}

```

- `rewind` 函数就是将数据迭代器返回到开始的位置，对于 `swTable` 来说，就是将 `absolute_index`、`collision_index`、`row` 等重置为 0 即可。

- `swTable_iterator_forward` 就是将迭代器向前进行一步，其中 `absolute_index` 类似于共享表的行索引，`collision_index` 类似于共享表的列索引。不同的是，对于没有哈希冲突的行，列索引只有一个 0，对于哈希冲突的行，列索引就是开链法的链表索引：

```c
static sw_inline swTableRow* swTable_iterator_get(swTable *table, uint32_t index)
{
    swTableRow *row = table->rows[index];
    return row->active ? row : NULL;
}

void swTable_iterator_forward(swTable *table)
{
    for (; table->iterator->absolute_index < table->size; table->iterator->absolute_index++)
    {
        swTableRow *row = swTable_iterator_get(table, table->iterator->absolute_index);
        if (row == NULL)
        {
            continue;
        }
        else if (row->next == NULL)
        {
            table->iterator->absolute_index++;
            table->iterator->row = row;
            return;
        }
        else
        {
            int i = 0;
            for (;; i++)
            {
                if (row == NULL)
                {
                    table->iterator->collision_index = 0;
                    break;
                }
                if (i == table->iterator->collision_index)
                {
                    table->iterator->collision_index++;
                    table->iterator->row = row;
                    return;
                }
                row = row->next;
            }
        }
    }
    table->iterator->row = NULL;
}

```

### `current`

`current` 方法很简单，取出当前迭代器的行元素，再转化为 `php` 数组即可

```c
static PHP_METHOD(swoole_table, current)
{
    swTable *table = swoole_get_object(getThis());
    if (!table->memory)
    {
        swoole_php_fatal_error(E_ERROR, "the swoole table does not exist.");
        RETURN_FALSE;
    }
    swTableRow *row = swTable_iterator_current(table);
    swTableRow_lock(row);
    php_swoole_table_row2array(table, row, return_value);
    swTableRow_unlock(row);
}

swTableRow* swTable_iterator_current(swTable *table)
{
    return table->iterator->row;
}

```

## `key`

取出当前迭代器的键值：

```c
static PHP_METHOD(swoole_table, key)
{
    swTable *table = swoole_get_object(getThis());
    if (!table->memory)
    {
        swoole_php_fatal_error(E_ERROR, "the swoole table does not exist.");
        RETURN_FALSE;
    }
    swTableRow *row = swTable_iterator_current(table);
    swTableRow_lock(row);
    SW_RETVAL_STRING(row->key, 1);
    swTableRow_unlock(row);
}

```

## `next`

`next` 就是迭代器向前进一步：

```c
static PHP_METHOD(swoole_table, next)
{
    swTable *table = swoole_get_object(getThis());
    if (!table->memory)
    {
        swoole_php_fatal_error(E_ERROR, "the swoole table does not exist.");
        RETURN_FALSE;
    }
    swTable_iterator_forward(table);
}

```
## `valid`

验证当前行元素是否为空：

```c
static PHP_METHOD(swoole_table, valid)
{
    swTable *table = swoole_get_object(getThis());
    if (!table->memory)
    {
        swoole_php_fatal_error(E_ERROR, "the swoole table does not exist.");
        RETURN_FALSE;
    }
    swTableRow *row = swTable_iterator_current(table);
    RETURN_BOOL(row != NULL);
}

```