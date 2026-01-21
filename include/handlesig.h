#ifndef _HANDLESIG_H_
#define _HANDLESIG_H_ 1


#include <sys/types.h>

extern int hdl_sock; 
extern int ssl_sock;
extern pid_t ssl_proc; 
extern pid_t db_proc; 
int handle_sig();

#endif
