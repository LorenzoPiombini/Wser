#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
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
	struct sigaction act = {0};
	act.sa_handler = &handler;
	if(sigaction(SIGSEGV, &act, NULL) == -1 ||
			sigaction(SIGINT,&act,NULL) == -1 || 
			sigaction(SIGPIPE,&act,NULL) == -1 ){
		fprintf(stderr,"(%s): cannot handle the signal.\n",prog);
		return -1;
	}
	return 0;
}

static void handler(int signo)
{
	switch(signo){
	case SIGSEGV:
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
