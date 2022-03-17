#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

static noinline void createStaticCheckError(void) {
    char *ptr = kmalloc(10 * sizeof(char), GFP_KERNEL);
    BUG_ON(20 > 10 * sizeof(char));
}

static int __init testChecksInit(void) {
    pr_info("static vs dynamic analysis module");
    createStaticCheckError();
    return 0;
}

module_init(testChecksInit);
MODULE_LICENSE("GPL");