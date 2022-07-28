1. 请分别用C，C++内存分配函数分配一个1024字节的内存并释放它.
```cpp
// C
void *buf = malloc(1024);
free(buf);

// C++
char *buf = new char[1024];
delete buf;

```

2. 请写出下面C语言类型的长度(假设在64位系统中)(注意: 填以字节为单位的阿拉伯数字).
```cpp
sizeof(char) = ?
// 1

sizeof(short) = ?
// 2

sizeof(int) = ?
// 4

sizeof(long) = ?
// 4

sizeof(float) = ?
// 4

sizeof(double) = ?
// 8

sizeof(double *) = ?
// 8

sizeof(bool) = ?
// 1

sizeof("123456") = ?
// 7

sizeof(100i64) = ?
// 8
```

3. 分析下列程序中每个变量的存储位置，作用域，与生命周期.
```cpp
int a = 1;  // .data节, 整个项目, 程序执行期间
char *p1; // .bss节, 整个项目, 程序执行期间
static int x = 10; // .data节, 本文件, 程序执行期间
int main(void) 
{ 
    int b = 0; // 栈, main函数, main函数执行期间
    char s1[] = "123"; // 栈, main函数, main函数执行期间(栈上存了"123\0")
    char *p2; // 栈, main函数, main函数执行期间
    char *s2 = "123"; // 栈, main函数, main函数执行期间("123\0"存于.rdata节, s2指向之)
    static int c = 10; // .data节, main函数, 程序执行期间
    p1 = (char *)malloc(128); // 堆, 整个项目, 程序执行期间
    free(p1); 
    return 0; 
} 
```

4. 试分析下面程序的输出.
```cpp
void fun(char c[]) 
{ 
    printf("%d\n" , sizeof(c)); 
}
void fun2(char &c) 
{ 
    printf("%d\n" , sizeof(c)); 
}
void fun3(char(&c)[9]) 
{ 
    printf("%d\n" , sizeof(c)); 
} 
int main() 
{ 
    char c[] = "12345678"; 
    printf("%d\n" , sizeof(c));// 9
    fun(c); // 4
    fun2(*c); // 1
    fun3(c); // 9
    return 0; 
}
```

5. 实现一个算法，将一个字符串逆置，如“Hello world”逆置后变为“dlrow olleH ”.