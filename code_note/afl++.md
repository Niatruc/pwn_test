* 备注
    * `afl-fuzz`
        * 默认通过共享内存获取测试用例. (`main`函数开始处有`afl->shmem_testcase_mode = 1;`). 在编译时指定`USEMMAP`, 则使用`mmap`映射文件
        * 在记录时间时, 相比`afl`使用的`gettimeofday(&tv, &tz)`函数, 改用了`clock_gettime(CLOCK_MONOTONIC_COARSE, &ts)`函数, 获取的时间戳是相对系统启动时间而不是相对`1970-01-01`. 
        * `fork server`
            * 如果使用共享内存, 则生成的测试用例会拷贝到`fsrv->shmem_fuzz`(在`afl_fsrv_write_to_testcase`函数中可看到). 
            * 共享内存的前4个字节存测试用例的长度(`fsrv->shmem_fuzz_len`指向此处), 剩余部分才是测试用例内容(由`fsrv->shmem_fuzz`指向)

# Unicorn模式
* 备注
    * 调试中可看到在fork server启动前用`_may_use_shm_testcase`方法获取测试用例, 之后主要用`_may_use_mmap_testcase`, 但是其中`!this->afl_use_shm_testcase_`这个判断失败(也就是说实际仍是通过共享内存获取测试用例), 所以`_may_use_mmap_testcase`几乎没做任何事. 