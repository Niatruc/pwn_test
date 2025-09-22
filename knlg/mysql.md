# Mariadb
* 设置root的初始密码
    * `sudo mysql`, 进入交互界面
    * 输入命令: 
        ```sql
            use mysql;
            -- UPDATE mysql.user SET password = PASSWORD('newpassward') WHERE user = 'root';
            SET password=PASSWORD('newpassward'); -- 设置root密码
            FLUSH PRIVILEGES;
        ```
* 登录: `mysql -u root -p`
* 使任意IP可登录: 
    * 修改`/etc/mysql/mariadb.conf.d/50-server.cnf`: 
        ```conf
            bind-address = 0.0.0.0
        ```
    * 进入交互界面, 执行: 
        ```sql
            CREATE USER 'monty'@'%' IDENTIFIED BY 'some_pass'; -- 创建用户
            GRANT ALL PRIVILEGES ON *.* TO 'monty'@'%' WITH GRANT OPTION; -- 赋予权限
        ```

# Sql语句
* 数据查询语言DQL(select等)
    ```sql
    ```
* 数据操纵语言DML(insert, delete, update等)
    ```sql
    ```
* 数据定义语言DDL(create, alter, drop, rename, truncate等)
    ```sql
        create table t2 like t1; -- 用t1的元数据创建空表t2
    ```
* 数据控制语言DCL(grant, revoke等)
    ```sql
    ```