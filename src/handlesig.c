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
int ssl_sock = -1;
int db_sock = -1;
pid_t db_proc = -1;
pid_t ssl_proc = -1;


static void handler_main_process(int signo);
static void handler_ssl_process(int signo);
static void handler_db_process(int signo);

int handle_sig_main_process()
{
	/*set up signal handler*/
	struct sigaction act;
	memset(&act,0,sizeof(struct sigaction));

	struct sigaction act_child_process;
	memset(&act_child_process,0,sizeof(struct sigaction));
	act.sa_handler = &handler_main_process;
	act_child_process.sa_handler = SIG_IGN;
	act_child_process.sa_flags = SA_NOCLDWAIT;

	if(/*sigaction(SIGSEGV, &act, NULL) == -1 ||*/
			sigaction(SIGINT,&act,NULL) == -1 || 
			sigaction(SIGPIPE,&act,NULL) == -1 ||
			sigaction(SIGTERM,&act,NULL) == -1 ||
			sigaction(SIGCHLD,&act_child_process,NULL) == -1){
		fprintf(stderr,"(%s): cannot handle the signal.\n",prog);
		return -1;
	}
	return 0;
}

int handle_sig_ssl_process()
{
	/*set up signal handler*/
	struct sigaction act;
	memset(&act,0,sizeof(struct sigaction));

	struct sigaction act_child_process;
	memset(&act_child_process,0,sizeof(struct sigaction));
	act.sa_handler = &handler_ssl_process;
	act_child_process.sa_handler = SIG_IGN;
	act_child_process.sa_flags = SA_NOCLDWAIT;
	
	if(/*sigaction(SIGSEGV, &act, NULL) == -1 ||*/
			sigaction(SIGINT,&act,NULL) == -1 || 
			sigaction(SIGPIPE,&act,NULL) == -1 ||
			sigaction(SIGTERM,&act,NULL) == -1 ||
			sigaction(SIGCHLD,&act_child_process,NULL) == -1){
		fprintf(stderr,"(%s): cannot handle the signal.\n",prog);
		return -1;
	}
	return 0;
}

int handle_sig_db_process()
{
	/*set up signal handler*/
	struct sigaction act;
	memset(&act,0,sizeof(struct sigaction));

	struct sigaction act_child_process;
	memset(&act_child_process,0,sizeof(struct sigaction));
	act.sa_handler = &handler_db_process;
	act_child_process.sa_handler = SIG_IGN;
	act_child_process.sa_flags = SA_NOCLDWAIT;
	
	if(/*sigaction(SIGSEGV, &act, NULL) == -1 ||*/
			sigaction(SIGINT,&act,NULL) == -1 || 
			sigaction(SIGPIPE,&act,NULL) == -1 ||
			sigaction(SIGTERM,&act,NULL) == -1 ||
			sigaction(SIGCHLD,&act_child_process,NULL) == -1){
		fprintf(stderr,"(%s): cannot handle the signal.\n",prog);
		return -1;
	}

	return 0;
}

static void handler_ssl_process(int signo)
{
	switch(signo){
	case SIGINT:
	case SIGTERM:
	case SIGPIPE:
		if(db_proc != -1)
			kill(db_proc,SIGTERM);
		stop_listening(ssl_sock);
		break;
	default:

	}
}

static void handler_main_process(int signo)
{
	switch(signo){
	/*case SIGSEGV:*/ /* in production you might want this on*/
	case SIGINT:
	case SIGTERM:
	case SIGPIPE:
		stop_monitor();	
		stop_listening(hdl_sock);
		/*terminate all the child*/
		if(ssl_proc != -1){
			SSL_CTX_free(ctx); /*i don't think we need this*/
			kill(ssl_proc,SIGKILL);
		}

		if(signo == SIGINT)
			fprintf(stderr,"\b\b(%s):cleaning on interrupt, recived %s.\n",prog,"SIGINT");
		else if(signo == SIGPIPE)
			fprintf(stderr,"\b\b(%s):cleaning on interrupt, recived %s.\n",prog,"SIGPIPE");
		else if(signo == SIGTERM)
			fprintf(stderr,"\b\b(%s):cleaning on interrupt, recived %s.\n",prog,"SIGTERM");
		else 
			fprintf(stderr,"\b\b(%s):cleaning on interrupt, recived %s.\n",prog,"SIGSEGV");
		break;
	default:
		break;
	}
}

static void handler_db_process(int signo)
{
	switch(signo){
	case SIGINT:
	case SIGTERM:
	case SIGPIPE:
		close(db_sock);
		/*TODO: undersand what action you have to take for this*/
		break;
	default:
	}


}
