# 算法
* 程序 = 算法(包括数据结构) + api调用 + "hello world" + 字符串处理 + 内存管理
* 时间复杂度
    * O(log n): 一个折半查找
    * O(n): 一个循环
    * O(n log n): 一个循环套一个折半
    * O(n^2): 嵌套循环
    * O(2^n): 
* 两个指针跑步法
    * 例子
        * 计算一个链表的中间节点
        * 判断单向链表是否有循环

## 例题
* 统计整数x的二进制形式中1的个数
    * 思路: 每次`x = x & (x - 1)` 可将x中一个1消去.

        <img alt="" src="./pic/count_bit_1.jpg" width="30%" height="30%">

    * 代码
        ```c
        int i = 0;
        while (x != 0) {
            x &= (x-1);
            i ++;
        }
        ```
* 内存拷贝
    * 思路: 如果dst位置在src区域中, 则要从src的结尾开始逐字节拷到dst(也是末尾开始)

        <img alt="" src="./pic/memcpy.jpg" width="30%" height="30%">

* 数值交换
    * 异或法
        ```cpp
        a = a ^ b;
        a = a ^ b;
        b = a ^ b;
        ```

* 判断系统是低位还是高位优先
    ```cpp
    int num = 1;
    char *p = (char *) &num;    // 若值是1, 则为低位优先
    ```

* 改变整数存储顺序
    ```cpp
    unsigned int num = 0x12345678;
    while (num > 0) {
        converted_num = (converted_num << 8) + (char) num;
        num >>= 8;
    }
    ```

* 字符串逆置
    1. 得到首尾字符位置, 分别赋予两个指针变量p, q
    2. p向后移动, q向前移动, 交换\*p和\*q字符

* 句子逆置("how are you ?" -> "? you are how")
    1. 将字符串逆置
    2. 将每个单词逆置

* 旋转字符串("hello"旋转两个字符: "llohe") (跟上面的思路一样)
    1. 先把"he" "llo"逆置
    2. 再把字符串逆置

