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
void halt(void);
void exit(int status);
tid_t exec(const char *cmd_line);
int wait(tid_t tid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell (int fd);
void close(int fd);





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
        case SYS_HALT:
            {
                halt();
                break;
            }
        case SYS_EXIT:
            {
                get_arg(f, args, 1);
                f->eax = args[1];
                exit(args[0]);
                break;
            }
        case SYS_EXEC:
            {
                get_arg(f, args, 1);
                args[0] = user_to_kernel_ptr((const void *) args[0]);
                f->eax = exec((const char *) args[0]);
                break;
            }
        case SYS_WAIT:
            {
                get_arg(f, args, 1);
                f->eax = wait(args[0]);
                break;
            }
        case SYS_CREATE:
            {
                get_arg(f, args, 2);
                args[0] = user_to_kernel_ptr((const void *) args[0]);
                f->eax = create((const char *) args[0], (unsigned) args[1]);
                break;
            }

        case SYS_REMOVE:
            {
                get_arg(f, args, 1);
                args[0] = user_to_kernel_ptr((const void *) args[0]);
                f->eax = remove((const char *) args[0]);
                break;
            }
        case SYS_OPEN:
            {
                get_arg(f, args, 1);
                args[0] = user_to_kernel_ptr((const void *) args[0]);
                f->eax = open((const char *) args[0]);
                break;
            }
        case SYS_FILESIZE:
            {
                get_arg(f, args, 1);
                f->eax = filesize(args[0]);
            }
        case SYS_READ:
            {
                get_arg(f, args, 3);
                check_valid_buffer((void *) args[1], (unsigned) args[2]);
                args[1] = user_to_kernel_ptr((const void *) args[1]);
                f->eax = read(args[0], (void *) args[1], (unsigned) args[2]);
                break;
            }   
        case SYS_WRITE:
            {
                get_arg(f, args, 3);
                check_valid_buffer((void *) args[1], (unsigned) args[2]);
                args[1] = user_to_kernel_ptr((const void *) args[1]);
                f->eax = write(args[0], (const void *) args[1], (unsigned) args[2]);
                break;
            }
        case SYS_SEEK:
            {
                get_arg(f, args, 2);
                seek(args[0], (unsigned) args[1]);
                break;
            }
        case SYS_TELL:
            {
                get_arg(f, args, 1);
                f->eax = tell(args[0]);
                break;
            }
        case SYS_CLOSE:
            {
                get_arg(f, args, 1);
                close(args[0]);
                break;
            }
    }
}

void 
halt(void)
{
    shutdown_power_off();
}

void
exit(int status)
{
    printf("%s: exit(%d)\n", thread_current()->name, status);
    thread_exit();
}

tid_t
exec(const char *cmd_line)
{
    lock_acquire(&filesys_lock);
    tid_t pid = process_execute(cmd_line);
    lock_release(&filesys_lock);
    return pid;
}

int
wait(tid_t tid)
{
    return process_wait(tid);
}

bool
create(const char *file, unsigned initial_size)
{
    lock_acquire(&filesys_lock);
    bool i = filesys_create(file, initial_size);
    lock_release(&filesys_lock);
    return i;
}

bool
remove(const char *file)
{
    lock_acquire(&filesys_lock);
    bool i = filesys_remove(file);
    lock_release(&filesys_lock);
    return i;
}

int
open(const char *file)
{
    lock_acquire(&filesys_lock);
    struct file *f = filesys_open(file);
    lock_release(&filesys_lock);

    int fd;
    if (f == NULL) {
        fd = -1;
    } else {
        fd = thread_add_fd(f);
    }

    return fd;
}

int
filesize(int fd)
{
    struct thread *t = thread_current();
    struct file_handle *fh = thread_get_fh(&t->files, fd);

    return file_length(fh->file);
}

int
read(int fd, void *buffer, unsigned size)
{
    struct thread *t = thread_current();
    if (fd == 0) {
        int i;
        uint8_t *buf = buffer;

        lock_acquire(&filesys_lock);
        for (i = 0; i < size; i++) {
            buf[i] = input_getc();
        }
        lock_release(&filesys_lock);
    } else {
        uint8_t *buf = buffer;

        struct file_handle *fh = thread_get_fh(&t->files, fd);
        
        if (fh == NULL) {
            printf("%s: exit(%d)\n", thread_current()->name, -1);
            thread_exit();
        }

        lock_acquire(&filesys_lock);
        off_t read = file_read(fh->file, buf, size);
        lock_release(&filesys_lock);

        return read;
    }
}

    

int 
write (int fd, const void *buffer, unsigned size)
{
    struct thread *t = thread_current();
    if (fd == STDOUT_FILENO) {
        lock_acquire(&filesys_lock);
        putbuf(buffer, size);
        lock_release(&filesys_lock);
        return size;
    } else { 
         uint8_t *buf = buffer;

        struct file_handle *fh = thread_get_fh(&t->files, fd);
        
        if (fh == NULL) {
            printf("%s: exit(%d)\n", t->name, -1);
            thread_exit();
        }

        lock_acquire(&filesys_lock);
        off_t wrote = file_write(fh->file, buf, size);
        lock_release(&filesys_lock);

        return wrote;
    }
}
       
void
seek(int fd, unsigned position)
{
    struct thread *t = thread_current();
    struct file_handle *fh = thread_get_fh (&t->files, fd);
    
    if (fh == NULL) {
        printf("%s: exit(%d)\n", t->name, -1);
        thread_exit();
    }

    lock_acquire(&filesys_lock);
    file_seek(fh->file, position);
    lock_release(&filesys_lock);
}
   
unsigned
tell (int fd)
{
    struct thread *t = thread_current();
    struct file_handle *fh = thread_get_fh(&t->files, fd);
    
    if (fh == NULL) {
        printf("%s: exit(%d)\n", t->name, -1);
        thread_exit();
    }

    lock_acquire(&filesys_lock);
    off_t position = file_tell(fh->file);
    lock_release(&filesys_lock);
    return position;
}

void
close(int fd)
{
    struct thread *t = thread_current();
    struct file_handle *fh = thread_get_fh(&t->files, fd);
    
    if (fh == NULL) {
        printf("%s: exit(%d)\n", t->name, -1);
        thread_exit();
    }

    lock_acquire(&filesys_lock);
    file_close(fh->file);
    thread_remove_file(fh);
    lock_release(&filesys_lock);
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
