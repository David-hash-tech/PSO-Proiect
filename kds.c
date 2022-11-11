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

        while ((token = strsep(&cursor, " "))) // pentru fiecare intreg dat ca parametru
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

        while ((token = strsep(&cursor, " "))) // pentru fiecare intreg dat ca parametru
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

        while ((token = strsep(&cursor, " "))) // pentru fiecare intreg dat ca parametru
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

        while ((token = strsep(&cursor, " "))) // pentru fiecare parametru din lista de parametri
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
        }

        kfree(cursor); // eliberam memoria pentru lista de parametri copiata anterior

        printk(KERN_INFO "End red black tree test\n");
    }
}

static void linked_list(void)
{
    char *token, *cursor;
    struct kds_linked_list *cursor2, *temp;

    if ((cursor = kmalloc(length + 1, GFP_KERNEL)) && strncpy(cursor, param, length)) // copiaza in cursor lista de parametri
    {
        printk(KERN_INFO "Begin linked list test:\n");

        while ((token = strsep(&cursor, " "))) // pentru fiecare element din lista de parametri
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

static int __init kds_init(void)
{
    char *token, *cursor;
    printk(KERN_INFO "Module loaded ...\n");

    if (param && (length = strlen(param)) && (cursor = kmalloc(length + 1, GFP_KERNEL)) && strncpy(cursor, param, length)) // copiaza in cursor lista de parametri
    {
        while ((token = strsep(&cursor, " "))) // pentru fiecare element din lista de parametri
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

    return 0;
}

static void __exit kds_exit(void)
{
    printk(KERN_INFO "Module exiting ...\n");
}

module_init(kds_init);
module_exit(kds_exit);