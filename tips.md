查看系统的libc版本:
```sh
    ldd --version
```

# 泄漏栈地址
## 利用**envp参数
条件:
1. 已泄漏libc基址
2. 能泄漏任意地址内容