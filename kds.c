#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>

#include <linux/string.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/hashtable.h>
#include <linux/xarray.h>
#include <linux/bitmap.h>

#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/fdtable.h>

#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/hdreg.h>
#include <linux/cdrom.h>
#include <linux/elevator.h>

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/pid.h>

#define MYMAJOR 64
#define SIZE_OF_KB 1024
#define WR_VALUE _IOW('a', 'a', char *)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MTA Students");
MODULE_DESCRIPTION("Kernel Module For Data Structure Inspection");

static char *param = NULL;
static size_t length = 0;

module_param(param, charp, 0); // parametrii primiti la incarcarea modulului in kernel, de tip charp, cu masca de permisiuni 0
                               // chap -> pointer la char
                               // 0 -> nu sunt permisiuni speciale

MODULE_PARM_DESC(param, "string ce contine un numar de intregi intre 0 to 100"); // string ce descrie ce parametri trb sa primeasca kernelul

// lista inlantuita
struct kds_linked_list
{
    int data;
    struct list_head list; // defineste urmatorul nod din lista
};

LIST_HEAD(kds_list_head); // defineste primul nod din lista

// read black tree

struct rb_root kds_rb_root = RB_ROOT; // defineste radacina arborelui

struct kds_rb_node
{
    int data;
    struct rb_node node; // defineste o structura nod (contine din stanga si nod dreapta)
};

/* hash table */
struct kds_hash_table
{
    DECLARE_HASHTABLE(table, 10); // declar un hashtable
};

struct kds_ht_node
{
    int data;
    struct hlist_node node; // defineste un element din hash
};

/* xarray */
DEFINE_XARRAY(kds_xarray); // declar un xarray

/* bitmap */
DECLARE_BITMAP(kds_bitmap, 10); // declar un bitmap cu maxim 10 intregi

static void bitmap(void)
{
    char *token, *cursor;
    u8 bit;

    if ((cursor = kmalloc(length + 1, GFP_KERNEL)) && strncpy(cursor, param, length)) // copiaza in cursor lista de parametri
    {
        printk(KERN_INFO "Begin bitmap test:\n");

        while ((token = strsep(&cursor, " \t\n"))) // pentru fiecare intreg dat ca parametru
        {
            long num;
            int inum, i, c = 0;

            if (kstrtol(token, 10, &num)) // conversie de la string token la long num in baza 10
                continue;

            bitmap_zero(kds_bitmap, 10); // seteaza toti bitii pe 0
            inum = (int)num;
            for (i = 9; i >= 0; i--)
            {
                int res = inum >> i;            // luam fiecare bit al numarului, incepand cu primul
                if (res & 1)                    // daca bitul obtinut este 1
                    set_bit(9 - c, kds_bitmap); // seteaza bitul 9-c din bitmap (incepe cu primul bit, nu ultimul)
                c++;
            }

            printk(KERN_INFO "bits that are turned on for %d:\n", inum);
            for_each_set_bit(bit, kds_bitmap, 10) // pentru fiecare bit setat din bitmap printam pozitia
            {
                printk(KERN_INFO "%u\n", bit);
            }
            printk(KERN_INFO "finished one iteration\n");
        }

        bitmap_zero(kds_bitmap, 10); // setam toti bitii pe 0 pt a nu ramane informatii in memorie

        kfree(cursor); // dezalocam vectorul de parametri copiat

        printk(KERN_INFO "End bitmap test\n");
    }
}

static void xarray(void)
{
    char *token, *cursor;

    if ((cursor = kmalloc(length + 1, GFP_KERNEL)) && strncpy(cursor, param, length)) // copiaza in cursor lista de parametri
    {
        int *result;
        unsigned long index;
        printk(KERN_INFO "Begin xarray test:\n");

        while ((token = strsep(&cursor, " \n\t"))) // pentru fiecare intreg dat ca parametru
        {
            long num;
            int *new_node;

            if (kstrtol(token, 10, &num)) // conversie de la string token la long num in baza 10
                continue;

            if ((new_node = kmalloc(sizeof(*new_node), GFP_KERNEL))) // aloca sizeof(*new_node) de bytes in kernel
            {
                *new_node = (int)num;
                xa_store(&kds_xarray, *new_node, new_node, GFP_KERNEL); // stocheaza intrarea in xarray
            }
        }

        xa_for_each(&kds_xarray, index, result) // itereaza peste intrarile din xarray
        {
            printk(KERN_INFO "%d\n", *result);

            if (*result % 2)
            {
                xa_set_mark(&kds_xarray, index, XA_MARK_0); // seteaza un mark pe intrare
            }
        }

        printk(KERN_INFO "Begin xarray odd number test:\n");
        xa_for_each_marked(&kds_xarray, index, result, XA_MARK_0) // itereaza marcarile
        {
            printk(KERN_INFO "%d\n", *result);

            if (*result % 2)
            {
                xa_set_mark(&kds_xarray, index, XA_MARK_0); // seteaza un mark pe intrare
            }
        }
        printk(KERN_INFO "End xarray odd number test:\n");

        printk(KERN_INFO "Removing xarray entries...\n");
        xa_for_each(&kds_xarray, index, result)
        {
            kfree(xa_erase(&kds_xarray, *result)); // elibereaza memoria fiecarui element din xarray
        }

        xa_destroy(&kds_xarray); // elibereaza memoria alocata de xarray

        kfree(cursor); // elibereaza lista de parametri copiata

        printk(KERN_INFO "End xarray test\n");
    }
}

static void hash_table(void)
{
    char *token, *cursor;
    struct kds_hash_table *ht;

    ht = kmalloc(sizeof(*ht), GFP_KERNEL); // aloca memorie pentru hashtable
    if (ht == NULL)
        return;

    hash_init(ht->table); // initializeaza hashtable

    if ((cursor = kmalloc(length + 1, GFP_KERNEL)) && strncpy(cursor, param, length)) // copiaza in cursor lista de parametri
    {
        int bkt;
        struct hlist_node *temp;
        struct kds_ht_node *cursor2;

        printk(KERN_INFO "Begin hash table test:\n");

        while ((token = strsep(&cursor, " \t\n"))) // pentru fiecare intreg dat ca parametru
        {
            long num;
            struct kds_ht_node *new_node;

            if (kstrtol(token, 10, &num)) // daca un parametru nu este intreg il ignora
                continue;

            if ((new_node = kmalloc(sizeof(*new_node), GFP_KERNEL))) // aloca memorie in mod kernel pentru o noua pozitie in tabel
            {
                new_node->data = (int)num;
                hash_add(ht->table, &new_node->node, new_node->data); // adauga elementul in tabel
            }
        }

        hash_for_each_safe(ht->table, bkt, temp, cursor2, node)
        {
            struct hlist_node *temp2;
            struct kds_ht_node *cursor3;

            printk(KERN_INFO "%d\n", cursor2->data);

            hash_for_each_possible_safe(ht->table, cursor3, temp2, node, cursor2->data) // pentru fiecare intrare din hashtable
            {
                printk(KERN_INFO "hash table lookup prints: %d\n", cursor3->data);
            }

            hash_del(&cursor2->node); // elibereaza memorie pentru fiecare element din hashtable
            kfree(cursor2);
        }

        kfree(cursor); // elibereaza lista de parametri copiata anterior

        printk(KERN_INFO "End hash table test\n");
    }

    kfree(ht); // elibereaza memoria alocata de hashtable
}

// functie care imi insereaza un nod in red black tree
static void __kds_rb_insert(struct kds_rb_node *rb_node)
{
    struct rb_node **link = &kds_rb_root.rb_node; // luam nodul corespunzator radacinii arborelui
    struct rb_node *parent = NULL;
    struct kds_rb_node *entry;

    while (*link)
    {
        parent = *link;
        entry = rb_entry(parent, struct kds_rb_node, node); // retine nodul curent

        if (rb_node->data < entry->data) // in functie de valoarea din campul de date, vom merge pe nodul din stanga sau din dreapta
            link = &parent->rb_left;
        else
            link = &parent->rb_right;
    }

    rb_link_node(&rb_node->node, parent, link);    // seteaza nodurile copil din stanga si din dreapta ca fiind NULL
    rb_insert_color(&rb_node->node, &kds_rb_root); // se seteaza culoarea pentru nodul adaugat(red sau black)
}

static void rb_tree(void)
{
    char *token, *cursor;
    struct rb_node *cursor2;

    if ((cursor = kmalloc(length + 1, GFP_KERNEL)) && strncpy(cursor, param, length)) // copiaza in cursor lista de parametri
    {
        printk(KERN_INFO "Begin red black tree test:\n");

        while ((token = strsep(&cursor, " \n\t"))) // pentru fiecare parametru din lista de parametri
        {
            long num;
            struct kds_rb_node *new_node;

            if (kstrtol(token, 10, &num)) // daca nu este numar intreg il ignor
                continue;

            if ((new_node = kmalloc(sizeof(*new_node), GFP_KERNEL))) // aloc spatiu pentru numarul intreg gasit
            {
                new_node->data = (int)num; // introduc numarul in campul de date al unui nod
                __kds_rb_insert(new_node); // inserez nodul in arbore
            }
        }

        cursor2 = rb_first(&kds_rb_root); // luam primul nod al arborelui (in ordinea de sortare)
        while (cursor2)                   // cat timp mai am noduri in arbore
        {
            struct rb_node *temp;
            struct kds_rb_node *entry;

            entry = rb_entry(cursor2, struct kds_rb_node, node); // retune nodul curent
            printk(KERN_INFO "%d\n", entry->data);               // afisam campul de date din nodul curent
            temp = cursor2;
            cursor2 = rb_next(cursor2);   // luam urmatorul nod in ordinea de sortare
            rb_erase(temp, &kds_rb_root); // eliminam nodul prin care tocmai am trecut
            kfree(rb_entry(temp, struct kds_rb_node, node));
            kfree(cursor); // eliberam memoria pentru lista de parametri copiata anterior

            printk(KERN_INFO "End red black tree test\n");
        }
    }
}

static void linked_list(void)
{
    char *token, *cursor;
    struct kds_linked_list *cursor2, *temp;

    if ((cursor = kmalloc(length + 1, GFP_KERNEL)) && strncpy(cursor, param, length)) // copiaza in cursor lista de parametri
    {
        printk(KERN_INFO "Begin linked list test:\n");

        while ((token = strsep(&cursor, " \n\t"))) // pentru fiecare element din lista de parametri
        {
            long num;
            struct kds_linked_list *linked_list;

            if (kstrtol(token, 10, &num)) // daca nu este intreg il ignora
                continue;

            if ((linked_list = kmalloc(sizeof(*linked_list), GFP_KERNEL))) // aloca spatiu pentru intregul gasit
            {
                linked_list->data = (int)num;
                INIT_LIST_HEAD(&linked_list->list);                // creeaza un nod in care punem intregul
                list_add_tail(&linked_list->list, &kds_list_head); // legam nodul creat la finalul listei existente
            }
        }

        list_for_each_entry_safe(cursor2, temp, &kds_list_head, list) // pentru fiecare nod din lista
        {
            printk(KERN_INFO "%d\n", cursor2->data);
            list_del(&cursor2->list);
            kfree(cursor2); // dezalocam nodul
        }

        kfree(cursor);

        printk(KERN_INFO "End linked list test\n");
    }
}

void do_basic(void)
{
    char *token, *cursor;

    if (param && (length = strlen(param)) && (cursor = kmalloc(length + 1, GFP_KERNEL)) && strncpy(cursor, param, length)) // copiaza in cursor lista de parametri
    {
        while ((token = strsep(&cursor, " \t\n"))) // pentru fiecare element din lista de parametri
        {
            long num;

            if (kstrtol(token, 10, &num) != 0) // daca parametrul dat nu este numar, nu il ia in considerare
                continue;

            printk(KERN_INFO "%d\n", (int)num);
        }
        kfree(cursor); // dezaloca cursorul

        linked_list();
        rb_tree();
        hash_table();
        xarray();
        bitmap();
    }
    else
    {
        printk(KERN_INFO "%s\n", "No valid program arguments passed to the kernel module!");
    }
}

void showAllProcess(void)
{
    struct task_struct *task;
    size_t process_counter = 0;
    printk(KERN_INFO " Process \t Pid \n");
    for_each_process(task)
    {
        pr_info(" %s\t\t%d\n", task->comm, task->pid);
        ++process_counter;
    }
    printk(KERN_INFO " Number of process: %zu\n", process_counter);
}

int showProcessByPid(int pid)
{

    struct task_struct *task;
    struct task_struct *parent;
    struct pid *pid_struct;
    struct mm_struct *mm;

    unsigned long vm_size = 0;
    unsigned long start_stack = -1;
    unsigned long end_of_stack = -1;
    unsigned long size_of_stack = 0;

    pid_struct = find_get_pid(pid);
    task = pid_task(pid_struct, PIDTYPE_PID);

    if (task == NULL)
    {
        printk(KERN_INFO "Process %d not found! \n\n", pid);
        return -1;
    }
    parent = task->parent;
    mm = task->mm;

    printk(KERN_INFO "\nProcess name : %s", task->comm);
    printk(KERN_INFO "Process pid: %d\n", task->pid);
    printk(KERN_INFO "Process ppid: %d", parent->pid);
    printk(KERN_INFO "Process vid: %d\n", (int)task_pid_vnr(task));
    printk(KERN_INFO "Process nice value: %d", (int)task_nice(task));
    printk(KERN_INFO "Process group : %d", (int)task_tgid_nr(task));

    printk(KERN_INFO "Code-segment-start:   0x%-12lx code-segment-end:   0x%-12lx code-segment-size:   %-10lu kB\n",
           mm->start_code, mm->end_code, (mm->end_code - mm->start_code));

    printk(KERN_INFO "Data-segment-start:   0x%-12lx data-segment-end:   0x%-12lx data-segment-size:   %-10lu kB\n",
           mm->start_data, mm->end_data, (mm->end_data - mm->start_data));

    printk(KERN_INFO "Stack-segment-start:  0x%lx stack-segment-end:  0x%lx stack-segment-size:  %-10lu kB\n",
           start_stack, end_of_stack, (size_of_stack));

    printk(KERN_INFO "Heap-segment-start:   0x%-12lx heap-segment-end:   0x%-12lx heap-segment-size:   %-10lu kB\n",
           mm->start_brk, mm->brk, (mm->brk - mm->start_brk));

    printk(KERN_INFO "Main-arguments-start: 0x%lx main-arguments-end: 0x%lx main-arguments-size: %-10lu kB\n",
           mm->arg_start, mm->arg_end, (mm->arg_end - mm->arg_start));

    printk(KERN_INFO "Env-variables-start:  0x%lx env-variables-end:  0x%lx env-variables-size:  %-10lu kB\n",
           mm->env_start, mm->env_end, (mm->env_end - mm->env_start));

    printk(KERN_INFO "Number of frames used by the process (RSS) is: %lu\n", 4 * get_mm_rss(mm));

    printk(KERN_INFO "Total Virtual Memory used by process is: %lu kB\n", (vm_size / SIZE_OF_KB));

    printk(KERN_INFO "\nParent tree:\n\n");

    do
    {
        task = task->parent;
        printk(KERN_INFO "\t|___parent process: %s, PID: %d\t", task->comm, task->pid);

    } while (task->pid != 0);

    return 0;
}

int do_process(void)
{

    int ret = 0;
    long pid;
    char *token;

    printk(KERN_INFO "%s\n", param);
    if (param == NULL)
    {
        // daca modul nu  are nici un parametru va afisa toate procesele curente
        showAllProcess();
    }
    else
    {
        // parametrul dat este pidul unui proces -> afiseaza informatii despre procesul respectiv
        while ((token = strsep(&param, " \t\n")))
        {
            if (token == NULL)
                break;
            ret = kstrtol(token, 10, &pid);
            printk(KERN_ALERT "\tPROCESS:\n");
            ret = showProcessByPid(pid);
        }
    }
    return 0;
}

// void dump_io_queue (void){

//     struct request_queue q;
//     struct request rq;

//     printk ("Dumping I/0 queue:\n");

//     spin_lock_irq(q.queue_lock);

//     list_for_each_entry(&q, &blk_queue_list, queue_list)
//     {
//         printk ("Queue for device %s:\n", q.backing_dev_info-nrame):
//          list_for_each_entry(&rq, &q.queue_head, queuelist)
//          {
//              printk("Request type: %d, sector: %lu\n", rq.cmd_type, blk_rq_pos(&rq));
//          }
//     }
//                 spin_unlock_irq(q.queue_lock);
//  }

//     static void print_io_queue (struct request_queue *q) 
// {
//     struct blk_mq_hw_ctx *hctx;
//     struct blk_mq_ctx *ctx;
//      int i, j;

//     printk ("Queue name: %s\n", q->request_fn->name) ;

//     for (i = 0; i < q->nr_hw_queues; i++) {
//          hctx = q->queue_hw_ctx[1];
//         printk("Hardware queue %d:\n", i);
//         printk("Dispatched: %lu\n", hctx->dispatched);
//         printk("Running: %lu\n", hctx->run);

//  for (j=0;j<hctx->nr_ctx; j++) {
//     ctx =hctx->ctxs[j];
//     printk("CPU %d:\n", ctx->cpu);
//     printk("Enqueued: %lu\n", ctx->enqueued);
//     printk("Active: %lu\n", ctx->active);
//      }
//  }
// }

static inline int init_tag_set(struct blk_mq_tag_set *set, void *data)
{ 
    //set->ops &mq_ops;
    set->nr_hw_queues = 1;
    set->nr_maps = 1;
    set->queue_depth = 128;
    set->numa_node = NUMA_NO_NODE;
    set->flags = BLK_MQ_F_SHOULD_MERGE|BLK_MQ_F_STACKING;
    set->cmd_size = 0;
    set->driver_data= data;
    return blk_mq_alloc_tag_set (set);
}

static void print_io_queue(struct request_queue *q)
{
    printk(KERN_INFO "Queue name: %s\n", q->kobj.name);
    printk(KERN_INFO "Queue ID: %d\n", q->id);
    printk(KERN_INFO "Queue depth: %d\n", q->nr_hw_queues);
    // printk ("Queue requests in flight: %d\n", q->rq.count [BLK_RW_ASYNC]);
}

int do_IO(void)
{    
    struct blk_mq_tag_set tag_set;
    int ret =init_tag_set(&tag_set, NULL);
    struct request_queue *q = blk_mq_init_queue(&tag_set);

    if (ret)
    { 
    pr_err("Failed to allocate tag set\n");
    return -1;
    }
    
    print_io_queue(q);
    printk(KERN_INFO "Init works\n");
    // if (!q) {
    // return -ENOMEM;
    // }
     
    // blk_mq_free_tag_set(&tag_set);
    // blk_mq_destroy_queue(q);

    return 0;
}

void showFiles(void)
{
    int i = 0;
    char *cwd;
    struct path files_path;
    char *buf = (char *)kmalloc(100 * sizeof(char), GFP_KERNEL);

    //--file nu are un alt parametru -> afiseaza toate fisierele deschise in respectivul moment
    struct files_struct *current_files = current->files;        // current returns a pointer to the task_struct of the current process
    struct fdtable *files_table = files_fdtable(current_files); // facem referinta la structura files_struct printr-un macro
                                                                // takes care of the memory barrier requirements for lock-free dereference

    if (files_table == NULL)
    {
        return;
    }

    for (i = 0;; i++)
    {

        if (files_table->fd == NULL)
        {
            break;
        }
        if (files_table->fd[i] == NULL)
            break;

        files_path = files_table->fd[i]->f_path;

        // converteste dentry in nume de cale ASCII
        cwd = d_path(&files_path, buf, 100 * sizeof(char)); // Convert a dentry into an ASCII path name

        if (cwd == NULL)
            break;

        printk(KERN_INFO "Open file with fd %d  %s\n", i, cwd);
    }

    kfree(buf);
}

void showFilesByPid(long pid)
{
    struct task_struct *task;
    struct pid *pid_struct;
    struct files_struct *current_files;
    struct fdtable *files_table;
    int i = 0;
    char *cwd;
    struct path files_path;
    char *buf = (char *)kmalloc(100 * sizeof(char), GFP_KERNEL);

    pid_struct = find_get_pid(pid);
    task = pid_task(pid_struct, PIDTYPE_PID);

    current_files = task->files;                // current returns a pointer to the task_struct of the current process
    files_table = files_fdtable(current_files); // facem referinta la structura files_struct printr-un macro
                                                // takes care of the memory barrier requirements for lock-free dereference

    printk(KERN_INFO "%p", files_table->fd[0]);

    for (i = 0; files_table->fd[i] != NULL; i++)
    {
        files_path = files_table->fd[i]->f_path;            // converteste dentry in nume de cale ASCII
        cwd = d_path(&files_path, buf, 100 * sizeof(char)); // Convert a dentry into an ASCII path name

        printk(KERN_INFO "Open file with fd %d  %s\n", i, cwd);
    }
}

int showFileDetails(char *filePath)
{

    int error;
    struct inode *inode;
    struct path path;

    error = kern_path(filePath, LOOKUP_FOLLOW, &path);
    if (error != 0)
    {
        printk(KERN_INFO "File '%s' isn't open or doesn't exist!\n", filePath);
        return error;
    }

    inode = path.dentry->d_inode;

    printk(KERN_INFO "File name: %s\n", filePath);                                 // numele fisierului
    printk(KERN_INFO "File's inode number:\t\t%lu\n", inode->i_ino);               // inode number
    printk(KERN_INFO "User ID:\t\t\t%u\n", inode->i_uid.val);                      // user id
    printk(KERN_INFO "Group ID:\t\t\t%u\n", inode->i_gid.val);                     // group id
    printk(KERN_INFO "File's permisions:\t\t%u\n", inode->i_mode);                 // permisiuni de acces
    printk(KERN_INFO "File's number of hardlinks:\t\t%u\n", inode->i_nlink);       // numarul de hardlink-uri ale fisierului
    printk(KERN_INFO "File's reference counter:\t\t%d\n", inode->i_count.counter); // cate procese a deschis fisierul
    printk(KERN_INFO "Seconds from last mtime:\t\t%lld\n", inode->i_mtime.tv_sec); // nr sec de la ultimul mtime
    printk(KERN_INFO "Seconds from last atime:\t\t%lld\n", inode->i_atime.tv_sec); // nr sec de la ultimul atime
    printk(KERN_INFO "Seconds from last ctime:\t\t%lld\n", inode->i_ctime.tv_sec); // nr sec de la ultimul ctime
    printk(KERN_INFO "File's size in bytes:\t\t%lld\n", inode->i_size);            // dimensiunea fisierului in octeti
    printk(KERN_INFO "File's size in blocks:\t\t%llu\n", inode->i_blocks);         // dimensiunea fisierului in blocuri
    printk(KERN_INFO "Block's size in bites:\t\t%d\n", inode->i_blkbits);          // dimensiunea blocului in bites

    return 0;
}

int do_file(void)
{
    int ret = 0;
    char *token;
    long num = 0;

    // modulul nu are parametri -> afiseaza toate fisierele deschise din sistem
    if (param == NULL)
    {
        showFiles();
        return 0;
    }
    if (!kstrtol(param, 10, &num)) // daca nu este intreg il ignora
    {                              // printk(KERN_INFO "merge");

        showFilesByPid(num);
        return 0;
    }
    else
        // parametrul dat este numele unui fisier -> afiseaza informatii despre fisierul respectiv
        while ((token = strsep(&param, " \t\n")))
        {
            if (token == NULL)
                break;
            ret = showFileDetails(token);
            if (ret != 0) // eroare
                return ret;
        }
    return ret;
}

void run_module(void)
{
    int ret = 0;
    char *option;

    option = (char *)kmalloc(sizeof(char) * 100, GFP_KERNEL);
    option = strsep(&param, " \n\t");

    if (strcmp(option, "--basic") == 0 || strcmp(option, "-b") == 0)
        do_basic();

    else if (strcmp(option, "--process") == 0 || strcmp(option, "-p") == 0)
        ret = do_process();

    else if (strcmp(option, "--dev") == 0 || strcmp(option, "-d") == 0)
        do_IO();

    else if (strcmp(option, "--file") == 0 || strcmp(option, "-f") == 0)
        ret = do_file();

    kfree(param);
    param = NULL;

    return;
}

static int driver_open(struct inode *device_file, struct file *instance)
{
    printk("/dev/kds - open was called!\n");
    return 0;
}

static int driver_close(struct inode *device_file, struct file *instance)
{
    printk("/dev/kds - close was called!\n");
    return 0;
}

char answer[100];
static long int driver_modify(struct file *file, unsigned cmd, unsigned long arg)
{
    switch (cmd)
    {
    case WR_VALUE:
        if (copy_from_user(&answer, (char *)arg, sizeof(answer)))
            printk("Error copying data from user!\n");
        else
        {
            param = kmalloc(strlen(answer) + 1, GFP_KERNEL);
            strcpy(param, answer);
            printk(KERN_INFO "Parameters: |%s|\n", param);
            run_module();
        }
        break;

        // case RD_VALUE:
        // 	if(copy_to_user((char *) arg, &answer, sizeof(answer)))
        // 		printk("Error copying data to user!\n");
        // 	else
        // 		printk("The answer was copied!\n");
        // 	break;
    }
    return 0;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = driver_open,
    .release = driver_close,
    .unlocked_ioctl = driver_modify};

static int __init kds_init(void)
{
    int retval;

    printk(KERN_INFO "Module loaded ...\n");

    /* register device nr. */
    retval = register_chrdev(MYMAJOR, "kds", &fops);
    if (retval == 0)
    {
        printk("Registered Device number Major: %d, Minor: %d\n", MYMAJOR, 0);
    }
    else if (retval > 0)
    {
        printk("Registered Device number Major: %d, Minor: %d\n", retval >> 20, retval & 0xfffff);
    }
    else
    {
        printk("Could not register device number!\n");
        return -1;
    }

    return 0;
}

static void __exit kds_exit(void)
{
    unregister_chrdev(MYMAJOR, "kds");
    printk(KERN_INFO "Module exiting ...\n");
}

module_init(kds_init);
module_exit(kds_exit);
