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

#include <arpa/inet.h>
#include "tcpjack.h"

struct TraceReport trace_ino(ino_t ino);
struct TraceReport trace_pid(pid_t pid){

}
struct TraceReport trace_proc_entry(struct ProcEntry proc_entry);
