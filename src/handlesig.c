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
int http_sock = -1;
int reload_certificate = 0; /*CA certificate automation*/
pid_t db_proc = -1;
pid_t ssl_proc = -1;
pid_t http_proc = -1;


static void handler_main_process(int signo);
static void handler_ssl_process(int signo, siginfo_t *info,void*);
static void handler_http_process(int signo);
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

int handle_sig_http_process()
{

	/*set up signal handler*/
	struct sigaction act;
	memset(&act,0,sizeof(struct sigaction));

	struct sigaction act_child_process;
	memset(&act_child_process,0,sizeof(struct sigaction));
	act.sa_handler = &handler_http_process;
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
	act.sa_sigaction = &handler_ssl_process;
	act_child_process.sa_handler = SIG_IGN;
	act_child_process.sa_flags = SA_NOCLDWAIT;
	
	if(/*sigaction(SIGSEGV, &act, NULL) == -1 ||*/
			sigaction(SIGHUP,&act,NULL) == -1 || 
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

static void handler_http_process(int signo)
{
	switch(signo){
	case SIGINT:
	case SIGTERM:
	case SIGPIPE:
		fprintf(stderr,"the http process recieved sig no %d\n",signo);
		if(ssl_proc == -1 && db_proc != -1)
			kill(db_proc,SIGKILL);
		break;
	default:
		stop_listening(http_sock);
		kill(http_proc,SIGKILL);
	}
}

static void handler_ssl_process(int signo,siginfo_t *info,void*)
{
	switch(signo){
	case SIGHUP:
		/*Reload certificate*/
		reload_certificate = 1;
		break;
	case SIGINT:
	case SIGTERM:
	case SIGPIPE:
		fprintf(stderr,"the ssl process recieved sig no %d legalay from pid %d",signo,info->si_pid);
		if(db_proc != -1)
			kill(db_proc,SIGTERM);
		break;
	default:
		stop_listening(ssl_sock);
		kill(ssl_proc,SIGKILL);
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
		if(ssl_proc != -1)
			kill(ssl_proc,SIGTERM);

		if(http_proc != -1)
			kill(http_proc,SIGTERM);

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
