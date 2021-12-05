# 空指针
```cpp
// C
#define NULL (void*)0

// C++
#define NULL 0
```

# 格式字符串
%Z: ANSI
%wZ: Unicode
%2x: 

# 执行程序
* Console程序: 最先执行的是`mainCRTStartup`函数, 然后`main`. `mainCRTStartup`会用`CRTInit`完成C库, C的初始化函数, C++库, C++的初始化函数的初始化工作.
* 有windows界面的程序: `WinMainCRTStartup` -> `WinMain`
* 在`main`执行前执行自定义代码:
    * gcc: 使用`attribute`关键字, 声明 `constructor`和`destructor`函数: `__attribute((constructor)) void before() {}`
    * VC: 如下定义`.CRT$XIU`段, 链接器就会形成日下的C初始化函数表：

       [__xi_a, ..., before1(xiu), ..., __xi_z]

       以及C++初始化函数表：

       [__xc_a, ..., before2(xcu), ..., __xc_z]
        ```cpp
        void before_main () {}
        typedef void func();
        #pragma data_seg(".CRT$XIU")
        static func *before[] = { before_main };
        #pragma data_seg()
        ```
    * C++: 全局对象的初始化函数会在`main`前执行. 下面的`g_iValue`赋值也会先执行, 故而`func`先于`main`执行.
        ```cpp
        A a;
        int g_iValue = func();
        ```

# 数据长度(32位及64位系统)
|数据类型或数据|长度(字节)|
|-|-|
|char|1|
|short|2|
|long|4或8|
|int|4|
|float|4|
|double|8|
|double*|4或8|
|bool|1|
|"str"|4|
|100i64|8|

# 对齐
结构体成员所在地址需是该成员大小的整数倍. 下面结构体大小: 16, 1 + 1 + 2(补齐给i) + 4 + 8
```c
struct a {
    char c1;
    char c2;
    long i;
    double f;
}
```

# 变量存储位置
* 全局变量: 静态区(`.data`存已初始化变量, `.bss`存未初始化变量). 用了`static`关键字声明的变量不可被其它文件通过`extern`导入.
* 在函数中定义的局部变量: 
    * `char s1[] = "123";` `s1`和"123"都存在栈上, 因而`s1`的值将是栈上地址(指向"123"); 
    * `char *s2 = "123";` "123"存在`.rdata`中;
    * `static int c = 10;` 作用域为函数内, 类似于闭包中的变量(会在函数执行完后仍保留); 存于`.data`
* 局部变量的地址不可被返回(编译不通过)

# 内存布局
* x86为32位寻址, 因此寻址空间上限为4GB, 也可通过PAE(Physical address extension)扩到36位(64GB)
* x64理论最大寻址2^64. Windows支持44位(16TB). Linux则48位(256TB)
* 栈大小: 
    *Windows: 应用栈默认1M(可用编译指令`/stack`指定). 内核栈: 12K(x86), 24K(x64)
    * Linux: 应用栈10M(`ulimit -s`查看或设置). 内核栈4K或8K

# 