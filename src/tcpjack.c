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

#include "tcpjack.h"

#include <stdio.h>
#include <stdlib.h>

void asciiheader() {
  printf("\e[0;33m  _             _            _    \e[0m\n");
  printf("\e[0;33m | |           (_)          | |   \e[0m\n");
  printf("\e[0;33m | |_ ___ _ __  _  __ _  ___| | __\e[0m\n");
  printf("\e[0;33m | __/ __| '_ \\| |/ _` |/ __| |/ /\e[0m\n");
  printf("\e[0;33m | || (__| |_) | | (_| | (__|   < \e[0m\n");
  printf("\e[0;33m  \\__\\___| .__/| |\\__,_|\\___|_|\\_\\ \e[0m\n");
  printf("\e[0;33m         | |  _/ |                \e[0m\n");
  printf("\e[0;33m         |_| |__/   \e[0mv%s              \n", VERSION);
  printf("\n");
  printf(
      "\e[1;34mAuthor\e[0m: \e[0;34mKris Nóva\e[0m "
      "<\e[0;32mkrisnova@krisnova.net\e[0m>\n");
  printf("\n");
  printf("TCP Hijack and instrumentation tool.\n");
  printf("Use tcpjack to trace TCP connections and send\n");
  printf("exciting payloads across already established TCP streams.\n");
  printf("\n");
}

void usage() {
  asciiheader();
  printf("Usage: \n");
  printf("tcpjack [options] <inode>\n");
  printf("\n");
  printf("Options:\n");
  printf("-h, help           Display help and usage.\n");
  printf("-l, list           List established TCP connections and inodes.\n");
  printf("-t, trace  <ino>   Trace (layer 3) connection by inode.\n");
  printf("-p, pid    <pid>   Trace (layer 3) connection by pid.\n");
  printf("-j, jack   <ino>   Send data to existing TCP connection.\n");
  printf("\n");
  exit(0);
}

/**
 * config is the CLI options that are used throughout boopkit
 */
struct config {
  int list;
  int trace;
  int pid;
  int jack;
} cfg;

/**
 * clisetup is used to initalize the program from the command line
 *
 * @param argc
 * @param argv
 */
void clisetup(int argc, char **argv) {
  cfg.list = 0;
  cfg.trace = 0;
  cfg.pid = 0;
  cfg.jack = 0;
  for (int i = 0; i < argc; i++) {
    if (argv[i][0] == '-') {
      switch (argv[i][1]) {
        case 'h':
          usage();
          break;
        case 'l':
          cfg.list = 1;
          break;
        case 't':
          cfg.trace = 1;
          break;
        case 'p':
          cfg.pid = 1;
          break;
        case 'j':
          cfg.jack = 1;
          break;
      }
    }
  }
  if (argc < 2) {
    usage();
  }
}

int main(int argc, char **argv) {
  clisetup(argc, argv);

  // -l list
  if (cfg.list == 1) {
    struct TCPList tcplist = list();
    print_list(tcplist);
    return 0;
  }

  // -t trace <ino>
  if (cfg.trace == 1 && argc == 3) {
    char *inode = argv[2];
    char *term;
    ino_t ino = (unsigned long)(unsigned int)strtol(inode, &term, 10);
    if (errno != 0 || ino == 0) {
      printf("Invalid or bad inode number.\n");
      return -1;
    }
    struct ProcEntry proc_entry = proc_entry_from_ino(ino);
    if (proc_entry.pid == 0) {
      printf("Unable to trace inode %lu. Error finding proc entry for inode.\n",
             ino);
      return -2;
    }
    struct TraceReport tps_report = trace_proc_entry(proc_entry);
    print_trace_report(tps_report);
    return 0;
  }

  // -p pid <pid>
  if (cfg.pid == 1 && argc == 3) {
    char *pidstr = argv[2];
    char *term;
    pid_t pid = strtol(pidstr, &term, 10);
    if (errno != 0 || pid == 0) {
      printf("Invalid or bad pid.\n");
      return -1;
    }
    struct ProcEntry proc_entry = proc_entry_from_pid(pid);
    if (proc_entry.pid == 0) {
      printf("Unable to trace pid %d. Unable to find process entry for pid.\n",
             pid);
      return -2;
    }
    struct TraceReport tps_report = trace_proc_entry(proc_entry);
    print_trace_report(tps_report);
    return 0;
  }

  // -j jack <ino>
  if (cfg.jack == 1 && argc == 3) {
    char *inode = argv[2];
    char *term;
    ino_t ino = (unsigned long)(unsigned int)strtol(inode, &term, 10);
    if (errno != 0 || ino == 0) {
      printf("Invalid or bad inode number.\n");
      return -1;
    }
    struct ProcEntry proc_entry = proc_entry_from_ino(ino);
    if (proc_entry.pid == 0) {
      printf("Unable to trace inode %lu. Error finding proc entry for inode.\n",
             ino);
      return -2;
    }
    int fd = proc_entry.jacked_fd;
    if (fd < 0) {
      if (errno == 1) {
        printf("Permission denied.\n");
        return -99;
      }
      printf(
          "Error hijacking file descriptor for established TCP connection! %d "
          "%d\n",
          fd, errno);
      return 0;
    }
    char ch;
    while (read(STDIN_FILENO, &ch, 1) > 0) {
      int z = write(fd, &ch, 1);
      if (z != 1) {
        printf("Error writing to hijacked connection! %d\n", errno);
        return -7;
      }
    }
    return 0;
  }
  // Default case
  usage();
  return 0;
}