#ifndef _HANDLESIG_H_
#define _HANDLESIG_H_


#include <sys/types.h>

extern int hdl_sock; 
extern pid_t ssl_proc; 
extern pid_t db_proc; 
int handle_sig();

#endif
