[https://paper.seebug.org/841/](https://paper.seebug.org/841/)

# AFL
[https://github.com/mirrorer/afl](https://github.com/mirrorer/afl)

```sh
afl-clang test.c -o test	//对待测试的程序进行插桩
mkdir in out
cd in
touch SEED.txt
cd ..
echo aaa > in/SEED.txt	//将SEED作为初始种子写入in文件夹中的SEED文件中
afl-fuzz -i in -o out -- ./test @@	//执行fuzzing，in表示输入文件夹，out表示输出文件夹，test是插桩编译后的可执行程序
# wait for crashes
```