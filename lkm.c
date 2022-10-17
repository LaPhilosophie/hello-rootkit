// lkm.c
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/module.h>
// 自定义设备,访问时返回Hello,World。
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ice");
MODULE_DESCRIPTION("A simple example Linux module.");
MODULE_VERSION("1.0");

#define DEVICE_NAME "lkm_example"
#define EXAMPLE_MSG "Hello, World!\n"
#define MSG_BUFFER_LEN 15

static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);

/* This structure points to all of the device functions */
static struct file_operations file_ops = {
    .open = device_open,
    .release = device_release,
    .read = device_read,
    .write = device_write};

static int major_num;
static int device_open_count = 0;
static char msg_buffer[MSG_BUFFER_LEN];
static char *msg_ptr;

static int device_open(struct inode *inode, struct file *file)
{
    /* If device is open, return busy */
    if (device_open_count)
    {
        return -EBUSY;
    }
    device_open_count++;
    try_module_get(THIS_MODULE);
    return 0;
}

/* Called when a process closes our device */
static int device_release(struct inode *inode, struct file *file)
{
    /* Decrement the open counter and usage count. Without this, the module would not unload. */
    device_open_count--;
    module_put(THIS_MODULE);
    return 0;
}

/* When a process reads from our device, this gets called. */
static ssize_t device_read(struct file *flip, char *buffer, size_t len, loff_t *offset)
{
    int bytes_read = 0;
    /* If we’re at the end, loop back to the beginning */
    if (*msg_ptr == 0)
    {
        msg_ptr = msg_buffer;
    }
    /* Put data in the buffer */
    while (len && *msg_ptr)
    {
        /* Buffer is in user data, not kernel, so you can’t just reference
         * with a pointer. The function put_user handles this for us */
        put_user(*(msg_ptr++), buffer++);
        len--;
        bytes_read++;
    }
    return bytes_read;
}

/* Called when a process tries to write to our device */
static ssize_t device_write(struct file *flip, const char *buffer, size_t len, loff_t *offset)
{
    /* This is a read-only device */
    printk(KERN_ALERT "This operation is not supported.\n");
    return -EINVAL;
}


static int __init lkm_example_init(void)
{
    /* Fill buffer with our message */
    strncpy(msg_buffer, EXAMPLE_MSG, MSG_BUFFER_LEN);
    /* Set the msg_ptr to the buffer */
    msg_ptr = msg_buffer;
    /* Try to register character device */
    major_num = register_chrdev(0, "lkm_example", &file_ops);
    if (major_num < 0)
    {
        printk(KERN_ALERT "Could not register device: %d\n", major_num);
        return major_num;
    }
    else
    {
        printk(KERN_INFO "lkm_example module loaded with device major number %d\n", major_num);
        return 0;
    }
}

static void __exit lkm_example_exit(void)
{
    /* Remember — we have to clean up after ourselves. Unregister the character device. */
    unregister_chrdev(major_num, DEVICE_NAME);
    printk(KERN_INFO "Goodbye, World!\n");
}

static int __init mod_init(void)
{
    printk(KERN_ALERT "Module install successful##!\n");
    return 0;
}

static void __exit mod_exit(void)
{
    printk(KERN_ALERT "Module uninstall successful!\n");
}

// module_init(mod_init);
// module_exit(mod_exit);
module_init(lkm_example_init);
module_exit(lkm_example_exit);
