#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

#define MAX_ARGS 3
#define USER_VADDR_BOTTOM ((void *) 0x0804000)

struct lock filesys_lock;
void syscall_init(void);
static void syscall_handler(struct intr_frame *f);
int write (int fd, const void *buffer, unsigned size);
void get_arg (struct intr_frame *f, int *arg, int n);
void check_valid_buffer (void *buffer, unsigned size);
void check_valid_ptr(const void *vaddr);
int user_to_kernel_ptr(const void *vaddr);


void
syscall_init(void)
{
    lock_init(&filesys_lock);
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f)
{
    int args[MAX_ARGS];
    check_valid_ptr((const void*) f->esp);
    switch (* (int *) f->esp)
    {
        case SYS_WRITE:
            {
                get_arg(f, &args[0], 3);
                check_valid_buffer((void *) args[1], (unsigned) args[2]);
                args[1] = user_to_kernel_ptr((const void *) args[1]);
                f->eax = write(args[0], (const void *) args[1], (unsigned) args[2]);
                break;
            }
    }
}

int write (int fd, const void *buffer, unsigned size)
{
    if (fd == STDOUT_FILENO) {
        putbuf(buffer, size);
        return size;
    }
}


void
get_arg (struct intr_frame *f, int *arg, int n)
{
    int i;
    int *ptr;

    for (i = 0; i < n; i++) {
        ptr = (int *) f->esp + i + 1;
        check_valid_ptr((const void *) ptr);
        arg[i] = *ptr;
    }
}

void
check_valid_buffer (void *buffer, unsigned size)
{
    unsigned i;
    char* local_buffer = (char *) buffer;
    for (i = 0; i < size; i++) {
        check_valid_ptr((const void*) local_buffer);
        local_buffer++;
    }
}





void check_valid_ptr(const void *vaddr)
{
    if (!is_user_vaddr(vaddr) || vaddr < USER_VADDR_BOTTOM)
    {
        thread_exit();
    }
}

int user_to_kernel_ptr(const void *vaddr)
{
    check_valid_ptr(vaddr);
    void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
    if (!ptr) {
        thread_exit();
    }
    return (int) ptr;
}




/*
static void syscall_exit (int *, struct intr_frame *);
static void syscall_halt (int *, struct intr_frame *);
static void syscall_exec (int *, struct intr_frame *);
static void syscall_create (int *, struct intr_frame *);
static void syscall_remove (int *, struct intr_frame *);
static void syscall_wait (int *, struct intr_frame *);
static void syscall_open (int *, struct intr_frame *);
static void syscall_filesize (int *, struct intr_frame*);
static void syscall_read (int *, struct intr_frame *);
static void syscall_write (int *, struct intr_frame *);
static void syscall_seek (int *, struct intr_frame *);
static void syscall_tell (int *, struct intr_frame *);
static void syscall_close (int *, struct intr_frame *);

static void (*syscall_list[13]) (int *, struct intr_frame *);
static int syscall_argc[13];

static int get_byte_user (const uint8_t *uaddr);
static int get_word_user (const int *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static int* syscall_get_args(struct intr_frame *f);

static struct lock filesys_lock;

static void syscall_handler (struct intr_frame *f);

* Reads a byte at user virtual address UADDR
 * UADDR must be below PHYS_BASE.
 * Returns the byte value if successful, -1 if a segfault
 * occurred. *
static int
get_byte_user (const uint8_t *uaddr)
{
    int result;
    asm ("movl $1f, %0; movzbl %1, %0; 1:"
         : "=&a" (result) : "m" (*uaddr));
    return result;
}

static int
get_word_user (const int *uaddr)
{
    int result;
    asm ("movl $1f, %0; movl %1, %0; 1:"
         : "=&a" (result) : "m" (*uaddr));
    return result;
}

* Writes BYTE to user address UDST
 * UDST must be below PHYS_BASE.
 * Returns true if successful, false if a segfault occured *
static bool
put_user (uint8_t *udst, uint8_t byte)
{
    int error_code;
    asm ("movl $1f, %0; movb %b2, %1; 1:"
         : "=&a" (error_code), "=m" (*udst) : "r" (byte));
    return error_code != -1;
}

static int *
syscall_get_args( struct intr_frame *f)
{
    int *args = (int *) malloc(4);
    int syscall_num = get_word_user((int *)(f->esp));
    int argc = syscall_argc[syscall_num];
    int i;

    for (i = 0; i <= argc; i++) {
        args[i] = get_word_user((int *)(f->esp) + i);
        // check for validity?
    }

    return args;
}



void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  lock_init (&filesys_lock);

  syscall_list[SYS_HALT] = &syscall_halt;
  syscall_list[SYS_EXIT] = &syscall_exit;
  syscall_list[SYS_EXEC] = &syscall_exec;
  syscall_list[SYS_WAIT] = &syscall_wait;
  syscall_list[SYS_CREATE] = &syscall_create;
  syscall_list[SYS_REMOVE] = &syscall_remove;
  syscall_list[SYS_OPEN] = &syscall_open;
  syscall_list[SYS_FILESIZE] = &syscall_filesize;
  syscall_list[SYS_READ] = &syscall_read;
  syscall_list[SYS_WRITE] = &syscall_write;
  syscall_list[SYS_SEEK] = &syscall_seek;
  syscall_list[SYS_TELL] = &syscall_tell;
  syscall_list[SYS_CLOSE] = &syscall_close;

  syscall_argc[SYS_HALT] = 0;
  syscall_argc[SYS_EXIT] = 1;
  syscall_argc[SYS_EXEC] = 1;
  syscall_argc[SYS_WAIT] = 1;
  syscall_argc[SYS_CREATE] = 2;
  syscall_argc[SYS_REMOVE] = 1;
  syscall_argc[SYS_OPEN] = 1;
  syscall_argc[SYS_FILESIZE] = 1;
  syscall_argc[SYS_READ] = 3;
  syscall_argc[SYS_WRITE] = 2;
  syscall_argc[SYS_SEEK] = 1;
  syscall_argc[SYS_TELL] = 2;
  syscall_argc[SYS_CLOSE] = 1;
}

static void
syscall_handler (struct intr_frame *f) 
{
  printf ("system call!\n");
  int syscall_num = get_word_user((int *)(f->esp));

  int *args = syscall_get_args(f);
  syscall_list[syscall_num](args, f);
  free(args);
  thread_exit ();
}

static void
syscall_halt (int *args UNUSED, struct intr_frame *f UNUSED)
{
    shutdown_power_off();
}


static void
syscall_exit (int *args, struct intr_frame *f)
{
    //thread_current()->ret = args[1];
    printf("%s: exit(%d)\n", thread_current()->name, args[1]);
    f->eax = args[1];
    thread_exit();
}


static void
syscall_exec (int *args, struct intr_frame *f)
{

    // validate!

    lock_acquire(&filesys_lock);
    tid_t pid = process_execute((char *) args[1]);
    lock_release(&filesys_lock);
    f->eax = pid;
}

static void
syscall_wait (int *args, struct intr_frame *f)
{
    f->eax = process_wait(args[1]);
}


static void
syscall_create (int *args, struct intr_frame *f)
{
    //validate!!

    lock_acquire(&filesys_lock);   
    f->eax = filesys_create((char *)args[1], args[2]);
    lock_release(&filesys_lock);
}

static void
syscall_remove (int *args, struct intr_frame *f)
{

    // validate
    lock_acquire(&filesys_lock);
    f->eax = filesys_remove((char *)args[1]);
    lock_release(&filesys_lock);
}

static void
syscall_open (int *args, struct intr_frame *f)
{

    // validate

    lock_acquire(&filesys_lock);
    struct file *file = filesys_open((char *) args[1]);
    lock_release(&filesys_lock);

    int fd;
    if (file == NULL) {
        fd = -1;
    } else {
        fd = thread_add_fd(file);
    }

    f->eax = fd;
}

static void
syscall_filesize (int *args, struct intr_frame *f)
{
    struct thread *t = thread_current();
    struct file_handle *fh = thread_get_fh(&t->files, args[1]);

    // validate    

    f->eax = file_length(fh->file);
}


static void
syscall_read (int *args, struct intr_frame *f)
{
    struct thread *t = thread_current();
    if (args[1] == 0) {
        int i;
        uint8_t *buf = (uint8_t *) args[2];

        //validate

        lock_acquire(&filesys_lock);
        for (i = 0; i < args[3]; i++) {
            buf[i] = input_getc();
        }
        lock_release(&filesys_lock);
    } else {
        uint8_t *buf = (uint8_t *) args[2];


        // validate

        struct file_handle *fh = thread_get_fh(&t->files, args[1]);
        
        if (fh == NULL) {
            printf("%s: exit(%d)\n", thread_current()->name, -1);
            thread_exit();
        }

        lock_acquire(&filesys_lock);
        off_t read = file_read(fh->file, buf, args[3]);
        lock_release(&filesys_lock);

        f->eax = read;
    }
}

static void
syscall_write (int *args, struct intr_frame *f)
{

    struct thread *t = thread_current();
    if (args[1] == 1) {

        uint8_t *buf = (uint8_t *) args[2];
        //validate the buf

        size_t size = args[3];

        //int wrote = 0;
        lock_acquire(&filesys_lock);
        putbuf((char *) buf, size);
        lock_release(&filesys_lock);
        f->eax = size;
    } else {
        uint8_t *buf = (uint8_t *) args[2];
        //validate the buf

        struct file_handle *fh = thread_get_fh(&t->files, args[1]);
        
        if (fh == NULL) {
            printf("%s: exit(%d)\n", t->name, -1);
            thread_exit();
        }

        lock_acquire(&filesys_lock);
        off_t wrote = file_write(fh->file, buf, args[3]);
        lock_release(&filesys_lock);

        f->eax = wrote;
    }
}

static void
syscall_seek (int *args, struct intr_frame *f UNUSED)
{
    struct thread *t = thread_current();
    struct file_handle *fh = thread_get_fh (&t->files, args[1]);
    
    if (fh == NULL) {
        printf("%s: exit(%d)\n", t->name, -1);
        thread_exit();
    }

    lock_acquire(&filesys_lock);
    file_seek(fh->file, args[2]);
    lock_release(&filesys_lock);
}

static void
syscall_tell (int *args, struct intr_frame *f)
{
    struct thread *t = thread_current();
    struct file_handle *fh = thread_get_fh(&t->files, args[1]);
    
    if (fh == NULL) {
        printf("%s: exit(%d)\n", t->name, -1);
        thread_exit();
    }

    lock_acquire(&filesys_lock);
    off_t position = file_tell(fh->file);
    // keep out of locks?
    f->eax = position;
    lock_release(&filesys_lock);
}

static void
syscall_close (int *args, struct intr_frame *f)
{
    struct thread *t = thread_current();
    struct file_handle *fh = thread_get_fh(&t->files, args[1]);
    
    if (fh == NULL) {
        printf("%s: exit(%d)\n", t->name, -1);
        thread_exit();
    }

    lock_acquire(&filesys_lock);
    file_close(fh->file);
    thread_remove_file(fh);
    lock_release(&filesys_lock);
}

*/      
