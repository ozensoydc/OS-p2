#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_write (int *, struct intr_frame *);

static void (*syscall_functions[13]) (int *, struct intr_frame *);
static int syscall_argc[13];

static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);

static struct lock filesys_lock;

/* Reads a byte at user virtual address UADDR
 * UADDR must be below PHYS_BASE.
 * Returns the byte value if successful, -1 if a segfault
 * occurred. */
static int
get_byte_user (const uint8_t *uaddr)
{
    int result;
    asm ("movl $1f, %0; movzbl %1, %0; 1:"
         : "=&a" (result) : "m" (*uaddr));
    return result;
}

static int
get_word_user (const uint8_t *uaddr)
{
    int result;
    asm ("movl $1f, %0; movl %1, %0; 1:"
         : "=&a" (result) : "m" (*uaddr));
    return result;
}

/* Writes BYTE to user address UDST
 * UDST must be below PHYS_BASE.
 * Returns true if successful, false if a segfault occured */
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
    int *args = (int *) malloc(3);
    int syscall_num = get_word_user((int *)(f->esp));
    int argc = syscall_argc[syscall_num];

    for (int i = 0; i <= 13; i++) {
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

  syscall_list[SYS_WRITE] = &syscall_write;
  syscall_argc[SYS_WRITE] = 3;
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
syscall_write (int *args, struct intr_frame *f)
{
    uint8_t *buffer = (uint8_t *) args[2];
    size_t size = args[3];

    if (args[1] == 1) {
        lock_acquire(&filesys_lock);
        uint8_t *buf = (uint8_t *) args[2];
        putbuf((char *) buffer, size);
        lock_release(*filesys_lock);
        f->eax = size;
    } 
}
