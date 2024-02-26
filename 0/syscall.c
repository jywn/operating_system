#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "../devices/shutdown.h"
#include "threads/vaddr.h"


// static void syscall_handler (struct intr_frame *);
void safe_address(const void* vaddr);//CHECK WHETHER ADDRESS IS SAFE

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  switch (*(uint32_t *)f->esp)
  {
  case SYS_HALT :
    shutdown_power_off();
    break;//ok!

  case SYS_EXIT : {
    struct thread* t = thread_current();
    char copy_file_name[256];
    char *thread_name_for_print;
    char *dump;
    strlcpy(copy_file_name, t->name, strlen(t->name) + 1);
    thread_name_for_print = strtok_r(copy_file_name, " ", &dump);
    printf("%s: exit(%d)\n", thread_name_for_print, t->status);
    thread_current()->exit_status = *(uint32_t *)(f->esp + 4);
    thread_exit();
    break;
  }

  case SYS_EXEC :
    printf("exec yet\n");
    char* tmp_cmd = *(uint32_t *)(f->esp + 4);
    char cmd[256];
    int i;
    for(i=0; tmp_cmd[i] != '\0' && tmp_cmd[i] != ' '; i++) 
      cmd[i] = tmp_cmd[i];
    cmd[i] = '\0';
    struct file* fp = NULL;
    fp = filesys_open(cmd);
    if(!fp) *(uint32_t *)(f->eax) = -1;
    *(uint32_t *)(f->eax) = process_execute(cmd);
    break;

  case SYS_WAIT :
    printf("wait yet\n");
    pid_t pid = *(uint32_t *)(f->esp + 4);
    struct thread* t = thread_current();
    process_wait(pid);
    thread_exit();
    break;

  case SYS_READ :
    //printf("sysnum(9): %d\narg0(fd 0): %d\narg1(buff):%d\nargs2(size):%d\n", *(uint32_t *)(f->esp), *(uint32_t *)(f->esp + 4), *(uint32_t *)(f->esp + 8), *(uint32_t *)(f->esp + 12));
    //printf("read yet\n");
    if(*(uint32_t *)(f->esp + 4) != 1) *(uint32_t *)(f->eax) = -1;
    for(int i=0; i < *(uint32_t *)(f->esp + 12); i++){
      if(input_getc()=='\0')
        break;
    }
    return i;
    break;

  case SYS_WRITE :
    if(*(uint32_t *)(f->esp + 4) != 1) *(uint32_t *)(f->eax) = -1;
    putbuf(*(uint32_t *)(f->esp + 8), *(uint32_t *)(f->esp + 12));
    *(uint32_t *)(f->eax) = *(uint32_t *)(f->esp + 12);
    break;

  default:
    break;
  }
}

void 
safe_address(const void* vaddr)
{
  if(!is_user_vaddr(vaddr)){}
    // exit(0);
}
