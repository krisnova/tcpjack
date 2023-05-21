/******************************************************************************\
*                                                                            *
*                    ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗                     *
*                    ████╗  ██║██╔═══██╗██║   ██║██╔══██╗                    *
*                    ██╔██╗ ██║██║   ██║██║   ██║███████║                    *
*                    ██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║                    *
*                    ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║                    *
*                    ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝                    *
*              Written By: Kris Nóva    <admin@krisnova.net>                 *
*                                                                            *
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
  printf("\e[1;34mAuthor\e[0m: \e[0;34mKris Nóva\e[0m <\e[0;32mkrisnova@krisnova.net\e[0m>\n");
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
  printf("-l, list           List established TCP connections.\n");
  printf("\n");
  exit(0);
}

/**
 * config is the CLI options that are used throughout boopkit
 */
struct config {
  int list;
} cfg;

/**
 * clisetup is used to initalize the program from the command line
 *
 * @param argc
 * @param argv
 */
void clisetup(int argc, char **argv) {
  cfg.list = 0;
  for (int i = 0; i < argc; i++) {
    if (argv[i][0] == '-') {
      switch (argv[i][1]) {
        case 'h':
          usage();
          break;
        case 'l':
          cfg.list = 1;
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
  if (cfg.list == 1) {
    // List established TCP connections.
    struct TCPList tcplist = list();
    print_list(tcplist);
    return 0;
  }
  if (argc == 2) {
    char *inode = argv[1];
    ino_t ino = (unsigned long)(unsigned int)atoi(inode);
    struct ProcEntry proc_entry = proc_entry_from_ino(ino);
    print_proc_entry(proc_entry);
    return 0;
  }
  return 0;
}