#include <linux/kernel.h>	//Needed for KERN_INFO
#include <linux/module.h>	//needed by all modules
#include <linux/init.h>		//Needed for the module_init/exit macros

#define PRINT_DEBUG    \
        printk(KERN_DEBUG "[%s]_FUNC:%s_LINE:%d\n", __FILE__ , __FUNCTION__ , __LINE__)

MODULE_DESCRIPTION("A kernel data structure inspection module");
MODULE_AUTHOR("MTA Students");
MODULE_LICENSE("GPL");

/* init - module initialization callback
 *  @return :  0 if everything went well ==> module is loaded
 *            -1 if an error ocurred     ==> module is not loaded
 */

//static int varName __initdata = 2;

static int __init init(void)
{
    printk(KERN_DEBUG "Hello World!\n");
    PRINT_DEBUG;

	//A non 0 return means init failed; module can't be loaded
    return 0;
}

/* fini - module removal callback
 */
static void __exit fini(void)
{
    
    PRINT_DEBUG;
    printk(KERN_DEBUG "Goodbye cruel, cruel world!\n");
}

/* register on_init and on_exit event handlers */
module_init(init);
module_exit(fini);
