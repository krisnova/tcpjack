/******************************************************************************\
*                                                                             *
*                     ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗                     *
*                     ████╗  ██║██╔═══██╗██║   ██║██╔══██╗                    *
*                     ██╔██╗ ██║██║   ██║██║   ██║███████║                    *
*                     ██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║                    *
*                     ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║                    *
*                     ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝                    *
*               Written By: Kris Nóva    <admin@krisnova.net>                 *
*                                                                             *
\******************************************************************************/

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "tcpjack.h"

struct ProcEntry proc_entry_from_pid(pid_t pid) {
  struct ProcEntry proc_entry = {
      .comm = "------",
      .pid = 0,
  };
  char *comm = malloc(1024);
  memset(comm, 0, 1024);
  char proc_comm_path[64];
  snprintf(proc_comm_path, 64, "/proc/%d/comm", pid);
  FILE *comm_f = fopen(proc_comm_path, "r");
  if (comm_f == NULL) return proc_entry;
  while (fgets(comm, 1024, comm_f)) {
    comm[strcspn(comm, "\n")] = 0;
    struct ProcEntry proc_entry = {.pid = pid, .comm = comm};
    return proc_entry;
  }
  return proc_entry;
}

struct ProcEntry proc_entry_from_ino(ino_t ino) {
  struct ProcEntry proc_entry = {
      .comm = "------",
      .pid = 0,
  };
  struct dirent *procdentry;  // Procfs
  char needle[64] = "";
  snprintf(needle, 64, "socket:[%lu]", ino);
  DIR *procdp = opendir("/proc");
  if (procdp == NULL) return proc_entry;
  while ((procdentry = readdir(procdp)) != NULL) {
    struct dirent *procsubdentry;  // Procfs Subdir
    char proc_dir[64];
    snprintf(proc_dir, 64, "/proc/%s/fd", procdentry->d_name);
    DIR *procsubdp = opendir(proc_dir);
    if (procsubdp == NULL) {
      continue;
    }
    while ((procsubdentry = readdir(procsubdp)) != NULL) {
      char proc_fd_path[64];
      char fd_content[64] = "";
      snprintf(proc_fd_path, 64, "/proc/%s/fd/%s", procdentry->d_name,
               procsubdentry->d_name);
      readlink(proc_fd_path, fd_content, 64);
      if (strcmp(fd_content, needle) == 0) {
        // Found the process
        pid_t pid = atoi(procdentry->d_name);
        closedir(procdp);
        closedir(procsubdp);
        return proc_entry_from_pid(pid);
      }
    }
    closedir(procsubdp);
  }
  closedir(procdp);
  return proc_entry;
}

int fd_from_ino(ino_t ino) {
  struct dirent *procdentry;  // Procfs
  char needle[64] = "";
  snprintf(needle, 64, "socket:[%lu]", ino);
  DIR *procdp = opendir("/proc");
  if (procdp == NULL) return -1;
  while ((procdentry = readdir(procdp)) != NULL) {
    struct dirent *procsubdentry;  // Procfs Subdir
    char proc_dir[64];
    snprintf(proc_dir, 64, "/proc/%s/fd", procdentry->d_name);
    DIR *procsubdp = opendir(proc_dir);
    if (procsubdp == NULL) {
      continue;
    }
    while ((procsubdentry = readdir(procsubdp)) != NULL) {
      char proc_fd_path[64];
      char fd_content[64] = "";
      snprintf(proc_fd_path, 64, "/proc/%s/fd/%s", procdentry->d_name,
               procsubdentry->d_name);
      readlink(proc_fd_path, fd_content, 64);
      if (strcmp(fd_content, needle) == 0) {
        // Found it!
        pid_t pid = atoi(procdentry->d_name);
        closedir(procdp);
        closedir(procsubdp);
        // TODO Working here on file descriptor hijacking

        // int syscall(SYS_pidfd_open, pid_t pid, unsigned int flags);
        int pidfd = syscall(SYS_pidfd_open, pid, 0);

        // int syscall(SYS_pidfd_getfd, int pidfd, int targetfd, unsigned int flags);
        return syscall(SYS_pidfd_getfd, pidfd, atoi(procsubdentry->d_name), 0);
      }
    }
    closedir(procsubdp);
  }
  closedir(procdp);
  return -10;
}

void print_proc_entry(struct ProcEntry proc_entry) {
  // TODO Clean this up
  printf("%d %s\n", proc_entry.pid, proc_entry.comm);
  free(proc_entry.comm);
}