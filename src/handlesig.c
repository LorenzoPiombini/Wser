#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "handlesig.h"
#include "monitor.h"
#include "network.h"
#include "default.h"

static char prog[] = "wser";
int hdl_sock = -1;
static void handler(int signo);

int handle_sig()
{
	/*set up signal handler*/
	struct sigaction act;
	memset(&act,0,sizeof(struct sigaction));

	struct sigaction act_child_process;
	memset(&act_child_process,0,sizeof(struct sigaction));
	act.sa_handler = &handler;
	act_child_process.sa_handler = SIG_IGN;
	act_child_process.sa_flags = SA_NOCLDWAIT;

	if(/*sigaction(SIGSEGV, &act, NULL) == -1 ||*/
			sigaction(SIGINT,&act,NULL) == -1 || 
			sigaction(SIGPIPE,&act,NULL) == -1 ||
			sigaction(SIGCHLD,&act_child_process,NULL) == -1){
		fprintf(stderr,"(%s): cannot handle the signal.\n",prog);
		return -1;
	}
	return 0;
}

static void handler(int signo)
{
	switch(signo){
	/*case SIGSEGV:*/
	case SIGINT:
	case SIGPIPE:
		stop_monitor();	
		stop_listening(hdl_sock);
		if(signo == SIGINT)
			fprintf(stderr,"\b\b(%s):cleaning on interrupt, recived %s.\n",prog,"SIGINT");
		else if(signo== SIGPIPE)
			fprintf(stderr,"(%s):cleaning on interrupt, recived %s.\n",prog,"SIGPIPE");
		else 
			fprintf(stderr,"(%s):cleaning on interrupt, recived %s.\n",prog,"SIGSEGV");
		break;
	default:
		break;
	}
	exit(-1);
}
