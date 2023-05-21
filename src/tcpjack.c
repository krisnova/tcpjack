// =========================================================================== //
//             Apache2.0 Copyright (c) 2022 Kris Nóva <krisnova@krisnova.net>       //
//                                                                             //
//                 ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓                 //
//                 ┃   ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗   ┃                 //
//                 ┃   ████╗  ██║██╔═████╗██║   ██║██╔══██╗  ┃                 //
//                 ┃   ██╔██╗ ██║██║██╔██║██║   ██║███████║  ┃                 //
//                 ┃   ██║╚██╗██║████╔╝██║╚██╗ ██╔╝██╔══██║  ┃                 //
//                 ┃   ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║  ┃                 //
//                 ┃   ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝  ┃                 //
//                 ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛                 //
//                                                                             //
//                        This machine kills fascists.                         //
//                                                                             //
// =========================================================================== //

#include <stdio.h>
#include "tcpjack.h"

void usage() {
  printf("\ntcpjack v%s\n", VERSION);
  printf("Written By: Kris Nóva <krisnova@krisnova.net>\n\n");
  printf("TCP hijack and instrumentation tool.\nWork with established TCP connections.\n");
  printf("\n");
  printf("Usage: \n");
  printf("tcpjack [options]\n");
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
  return 0;
}