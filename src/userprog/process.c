#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
void read_bytes(void* v_addr,int n);
char* revert_words(char* word, int n);
void shift_down(void* v_addr,int n);
/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  struct thread* p_thread = thread_current();
  
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    //sema_up(p_thread->child_lock);
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);
  sema_down(p_thread->child_lock);
  if (tid == TID_ERROR){
    palloc_free_page (fn_copy); 
  }
  
  sema_up(p_thread->child_lock);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  printf("in start_process\n");
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

    /* If load failed, quit. */
  if (!success) 
    thread_exit ();
  
  /*setting up the stack*/
  char* cmd_line = (char *) malloc(strlen(file_name)+1);
  mempcpy(cmd_line,file_name,strlen(file_name)+1);
  char *save_token;
  int arg_length=0;
  char *token=strtok_r(cmd_line," ", &save_token);
  char *cmd_name=token;
  int argc=0;
  int cum_length=0;
  int temp=0;
  int tmp_len=0;
  /* create an array to hold the args*/
  char **args=(char **)malloc((strlen(file_name)+1)*sizeof(char));
  if(args==NULL){
    printf("Ran out of memory trying to allocate %d bytes.\n", 
	   strlen(file_name)+1);
  }
  args[0]=token;
  argc++;
  
  /* acquire argc */
  while(token=strtok_r(NULL," ", &save_token)){
    args[argc]=token;
    cum_length+=strlen(token)+1;
    printf("wrote %s to index %d\n",args[argc],argc);
    argc++;
  }
  
  /* acquire addresses */
  int arg_len;
  int **arg_addresses=(int **)malloc(argc*sizeof(int*));
  for(temp=argc-1;temp>=0;temp--){
    arg_len=strlen(args[temp])+1;
    if_.esp -= arg_len;
    arg_addresses[temp]=if_.esp;
    mempcpy(if_.esp,args[temp],arg_len);
  }
  
  /* word align */
  int w_a = cum_length % 4;
  if(w_a!=0){
    if_.esp-= 4-w_a; //if word align is not zero, go 4-w_a bytes on stack
    cum_length+=4-w_a;
  }
  
  /* 0 sentinel argument */
  cum_length+=4;
  *(int *) if_.esp = 0;

  /* push addresses of the arguments */
  
  for(temp=argc-1;temp>=0;temp--){
    cum_length+=4;
    if_.esp-=4;
    *(void **)if_.esp=arg_addresses[temp];
  }
  
  /*argv*/
  cum_length+=4;
  if_.esp-=4;
  *(char **)if_.esp = if_.esp+4;
  
  /*argc*/
  cum_length+=4;
  if_.esp-=4;
  *(int *)if_.esp = argc;
  
  /*fake return address*/
  cum_length+=4;
  if_.esp-=4;
  *(int*)if_.esp=0;
  
  /* Deallocating memory */
  free(arg_addresses);
  free(args);
  


  palloc_free_page (file_name);
  

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  while(1){
  }
  return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, const char* file_name);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  printf("in load\n");
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  /* Pass only the executable name */
  printf("filename in load: %s \n", file_name);
  char* cmd_line=(char *)malloc(strlen(file_name)+1);
  mempcpy(cmd_line,file_name,strlen(file_name)+1);//=NULL;
  //strlcpy(cmd_line,file_name,sizeof(cmd_line));
  printf("strlcpy file_name: %s\n",cmd_line);
  char* tok_char;//=(char *)malloc(sizeof(100));
  char* exec = strtok_r(cmd_line," ",&tok_char);
  printf("exec: %s\n", exec);
  file = filesys_open (exec);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp,file_name))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, const char* file_name) 
{
  printf("entered setup_stack file_name: %s\n",file_name);
  uint8_t *kpage;
  bool success = false;
  int cmd_size=strlen(file_name);
  /* checking that size of command line is not greater than PGSIZE*/
  if(cmd_size>PGSIZE){
    return NULL;
  }
  else{
    
    kpage = palloc_get_page (PAL_USER | PAL_ZERO);
    
    if (kpage != NULL) 
      {
	success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, 
				kpage, true);
	if (success){
	  /*push the command line string onto stack*/
	  /*printf("here is what the file_name is %s\n",file_name);
	  memcpy(kpage + PGSIZE - cmd_size, file_name, cmd_size);
	  char* cmd_line=(char *)malloc(strlen(file_name)+1);
	  mempcpy(cmd_line,file_name,strlen(file_name)+1);
	  printf("copied cmd_line: %s\n",cmd_line);
	  char* save_token;
	  char* token=strtok_r(cmd_line," ", &save_token);
	  printf("token is %s at line464\n", token);
	  struct thread *t = thread_current();
	  void* userpage_v = 
	  pagedir_get_page(t->pagedir,
			   ((uint8_t *)PHYS_BASE) - PGSIZE);
	  int counter_args=0; //counts how many args are put in
	  int args_cum_size=0;
	  while(token!=NULL){
	    /* kernel v_addr corresponding to physical address of
	       token*/
	  /*printf("token is %s\n",token);
	    char* cmd_token=(char*)malloc(sizeof(strlen(token)+1));
	    mempcpy(cmd_token,token,strlen(token)+1);
	    printf("cmd_token is %s\n",cmd_token);
	    args_cum_size+=strlen(cmd_token)+1;
	    
	    cmd_token=revert_words(token,strlen(token)+1);
	    
	    counter_args++;
	    memcpy(kpage + PGSIZE - args_cum_size,(void*)cmd_token,
		   strlen(cmd_token)+1);
	    
	    printf("bytes down: %d\n",args_cum_size);
	    
	    token=strtok_r(NULL," ",&save_token);
	  }
	  
	  memcpy(kpage+PGSIZE-args_cum_size,
		 revert_byte_order(kpage+PGSIZE-args_cum_size,args_cum_size),
		 args_cum_size);
	  
	  /*shift one byte right, and add a null to the end*/
	  /*shift_down(kpage+PGSIZE-args_cum_size,args_cum_size);
	  read_bytes(kpage+PGSIZE-args_cum_size,args_cum_size);
	  void* last_arg_addr=(void*)kpage+PGSIZE-args_cum_size;
	  /*word align*/
	  /*uint8_t w_a=0;
	  args_cum_size+=sizeof(w_a);
	  memcpy(kpage+PGSIZE-args_cum_size,
		 &(w_a),sizeof(w_a));
	  printf("w_a at %x is %hu \n",kpage+PGSIZE-args_cum_size,w_a);
	  /*from here on args_cum_size also servers to keep track
	    of how far below kpage+PGSIZE we are in bytes */
	  
	  /*set up null sentinel at counter_args++*/
	  /* char* n_sentinel=0;
	  args_cum_size+=sizeof(n_sentinel);
	  memcpy(kpage+PGSIZE-args_cum_size,&n_sentinel,
		 sizeof(n_sentinel));
	  printf("n_sentinel at %x is %s\n",kpage+PGSIZE-args_cum_size,
		 n_sentinel);
	  
	  int num_pointers=counter_args;
	  int arg_count=counter_args+1;
	  int addr=(int) last_arg_addr;
	  for(; counter_args>0; counter_args--){
	    
	    memcpy(kpage+PGSIZE-args_cum_size-counter_args*sizeof(int),
		   addr,sizeof(int));
	    printf("written %x at %x\n",addr,
		   kpage+PGSIZE-args_cum_size-counter_args*sizeof(int));
	    printf("points to %s\n",kpage+PGSIZE-args_cum_size-
				     counter_args*sizeof(int));
	    printf("in the address %s\n",last_arg_addr);
	    last_arg_addr=last_arg_addr+strlen((char*)last_arg_addr)+1;
	    addr=(int)last_arg_addr;
	  }
	  args_cum_size+=num_pointers*sizeof(char*);
	  /*pointer to argv*/
	  /*void* argv=(void *)(kpage+PGSIZE-args_cum_size);
	  int argv_addr=(int)argv;
	  args_cum_size+=sizeof(int);
	  memcpy(kpage+PGSIZE-args_cum_size,argv_addr,sizeof(int));
	  printf("writes %x at %s\n",kpage+PGSIZE-args_cum_size,
		 kpage+PGSIZE-args_cum_size);
	  /*insert number of argcount*/
	  /*args_cum_size+=sizeof(int);
	  memcpy(kpage+PGSIZE-args_cum_size,&arg_count,sizeof(arg_count));
	  printf("writes %d in %x\n",*(kpage+PGSIZE-args_cum_size),
		 kpage+PGSIZE-args_cum_size);
	  /*insert return address*/
	  /*args_cum_size+=sizeof(userpage_v);
	  void* userpage_vpgsize = userpage_v+PGSIZE;
	  
	  memcpy(kpage+PGSIZE-args_cum_size,&userpage_vpgsize,
		 sizeof(&userpage_vpgsize));
	  printf("and the return is %x\n",userpage_vpgsize);*/
	  *esp = PHYS_BASE;
	  
	}
	else
	  palloc_free_page (kpage);
      }
    return success;
  }
  
}

/* shift bytes 1 byte down */
void shift_down(void* v_addr,int n){
  int i=0;
  char* buf=(char*)v_addr;
  for(;i<n;i++){
    if(i==n-1){
      buf[i]='\0';
    }
    else{
      buf[i]=buf[i+1];
    }
  }
  return;
}

/* Given a position in a stack, read through n bytes towards the top of the
   stack.  This is mostly for debugging */
void read_bytes(void* v_addr,int n){
  int i;
  char* ch=(char *) v_addr;
  for(i=0;i<n;i++){
    printf("it reads: %c at addr: %x\n",*(ch+i),v_addr+i);
  }
}

/*given a position in a stack, moves down to find the first instance of
  a null pointer, upon finding it , returns the address of the 
  previous byte*/
void* where_is_null(void* v_addr){
  char* p_return;
  char* p_compare=(char*)v_addr-2;
  while(p_compare!=NULL){
    printf("pointer points to %s\n",p_compare);
    p_compare=(char*)v_addr-1;
  }
  p_return=p_compare+1;
  return p_return;
}
/* inverts a word */

char* revert_words(char* word, int n){
  char temp;
  int i=0;
  int recurse=n/2;
  for(;i<recurse;i++){
    temp=word[i];
    printf("take %c swap with %c in rev_word\n",
	   temp,*(word+n-i-1));
    word[i]=word[n-i-1];
    word[n-i-1]=temp;
  }
  i=0;
  for(;i<n;i++){
    if(i==n-1){
      word[i]='\0';
    }
    else{
      word[i]=word[i+1];
      printf("%d char is now %c\n",word[i]);
    }
  }
  read_bytes(word,n);
  return word;
}
/*reverse bits takes the address to a pointer, and the number of bytes
  there on to inverse, and reverts byte order*/
void* revert_byte_order(void* v_addr,int to_revert){
  //int counter;
  printf("in revert_byte_order, first thing is %s\n",(char*)v_addr);
  char* rev=(char *)malloc(to_revert);
  char temp;
  rev = (char *) v_addr;
  int i=0;
  int to_recurse=to_revert/2;
  for(;i<to_recurse;i++){
    temp=rev[i];
    printf("take %c swap with %c\n",*(rev+i),*(rev+to_revert-i-1));
    rev[i]=rev[to_revert-i-1];
    rev[to_revert-i-1]=temp;
  }
  return (void*) rev;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
