#include <sys/ptrace.h>
 #include <sys/types.h>
 #include <sys/wait.h>
 #include <unistd.h>
 #include <stdio.h>
 #include <sys/reg.h>
//   #include <linux/user.h> /* For constants
//                                     ORIG_RAX etc */
 int main()
  {
    pid_t child;
     long orig_eax;
     printf("fork之前...\n"); // 子进程不会执行这句
     child = fork();
      if(child == 0) {
         ptrace(PTRACE_TRACEME, 0, NULL, NULL);
         execl("/bin/ls", "ls", NULL);
     }
      else {
         wait(NULL);
         orig_eax = ptrace(PTRACE_PEEKUSER,
                           child, 4 * ORIG_RAX,
                           NULL);
         printf("The child made a "
                "system call %ld ", orig_eax);
         ptrace(PTRACE_CONT, child, NULL, NULL);
     }
     return 0;
 }