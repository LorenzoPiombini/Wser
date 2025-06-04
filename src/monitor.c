#include <stdio.h>  
#include <sys/epoll.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include "monitor.h"

static char prog[] = "wser"; 


struct epoll_event ev;
struct epoll_event events[MAX_EVENTS];
int epollfd = -1;
int nfds = -1;


#define MAX_SK_LIST 256
static int sock_list[MAX_SK_LIST];
static int look_for_free_index();
static int free_socket_list(int sock);


int start_monitor(int sock)
{
	memset(sock_list,-1,sizeof(int) * 256);
	if ((epollfd = epoll_create1(0)) == -1){
		fprintf(stderr,"(%s): failed to initialize monitor, %s:%d.\n",prog,__FILE__,__LINE__);
		return -1;
	}

	if(add_socket_to_monitor(sock, EPOLLIN) == -1) return -1;

	return 0;
}

int monitor_events()
{
	errno = 0;
	nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
	if(nfds == -1){
		if(errno == EINTR) return errno;
		fprintf(stderr,"(%s): epoll_wait() failed %s:%d.\n",prog,__FILE__,__LINE__);
		return -1;
	}
	return nfds;
}

int add_socket_to_monitor(int sock,int event)
{
	int index = look_for_free_index();

	if(index == -1) return -1;

	sock_list[index] = sock;
		
	errno = 0;
	ev.events = event;
	ev.data.fd = sock;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sock, &ev) == -1) {
		if(errno == EEXIST) {
			sock_list[index] = -1;
			return errno;
		}

		sock_list[index] = -1;
        	fprintf(stderr,"(%s): cannot add socket to monitor",prog);
		return -1;
	}

	return 0;
}

int remove_socket_from_monitor(int sock)
{

	if (epoll_ctl(epollfd, EPOLL_CTL_DEL, sock,NULL) == -1) {
               fprintf(stderr,"(%s): cannot remove socket from monitor",prog);
	       close(sock);
               return -1;
	}

	if (free_socket_list(sock) == -1) {
		fprintf(stderr,"(%s):socket %d not found in list.\n",prog,sock);
		return -1;
	}

	close(sock);
	return 0;
}

int modify_monitor_event(int sock, int event)
{
	ev.events = event;
	ev.data.fd = sock;
	if (epoll_ctl(epollfd, EPOLL_CTL_MOD, sock, &ev) == -1) {
               fprintf(stderr,"(%s): cannot add socket to monitor",prog);
               return -1;
	}

	return 0;
}

void stop_monitor()
{

	for(int i =0; i < MAX_SK_LIST; i++){
		if(sock_list[i] == -1) continue;

		remove_socket_from_monitor(sock_list[i]);
	}
	close(epollfd);
}

static int look_for_free_index()
{
	for(int i = 0; i < MAX_SK_LIST; i++)
		if(sock_list[i] == -1) return i;

	return -1;
}

static int free_socket_list(int sock)
{
	for(int i = 0; i < MAX_SK_LIST; i++){
		if (sock_list[i] == sock) {
			sock_list[i] = -1;
			return 0;
		}
	}
	return -1;
}
