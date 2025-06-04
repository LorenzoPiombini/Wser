#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#include <ifaddrs.h>
#include "network.h"       
#include "monitor.h"       

static char prog[] = "wser";
static int parse_URL(char *URL, struct Url *url);
#define LISTEN_BACKLOG 50

int listen_port_80(uint16_t *port)
{

	int try = 10;/* number of tryes in case of error*/
	struct sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(*port); 
	addr.sin_addr.s_addr = INADDR_ANY;
	errno = 0;
	int sock_fd = socket(AF_INET,SOCK_STREAM | SOCK_NONBLOCK,0);
	if(sock_fd == -1) return -1;
		

sock_setup:

       	if(bind(sock_fd, (struct sockaddr *)&addr,sizeof(addr)) == -1){
		close(sock_fd);
		if(*port != 8080)
			*port = 8080;
		else
			(*port)++;

		while(errno == EACCES){
			if(try == 0) break;
			errno = 0;
			addr.sin_port = htons(*port); 
			sock_fd = socket(AF_INET,SOCK_STREAM | SOCK_NONBLOCK,0);
			try--;
		}
		
		if(errno == 0) goto sock_setup;
		return -1;
	}

	if(listen(sock_fd,LISTEN_BACKLOG) == -1){
		close(sock_fd);
		return -1;
	}

	return sock_fd;
}

int write_cli_sock(int cli_sock, struct Response *res)
{

	size_t l = strlen(res->header_str);
	size_t buff_l = res->body.size + l + 1;
	char *buff = NULL;
	if( buff_l >= STD_HD_L){
		errno = 0;
		buff = calloc(buff_l,sizeof(char));
		if(!buff){
			if(errno == ENOMEM)
				fprintf(stderr,"(%s): not enough memory.\n",prog);	
			else 
				fprintf(stderr,"(%s): calloc() failed %s:%d.\n",prog,__FILE__,__LINE__);	

			return -1;
		}

		strncpy(buff,res->header_str,strlen(res->header_str));
		if(res->body.d_cont){
			strncat(buff,res->body.d_cont,res->body.size);
		}else{
		
			if(res->body.size > 0)
				strncat(buff,res->body.content,res->body.size);
		}
	} else {
		if(res->body.size > 0)
			strncat(res->header_str,res->body.content,res->body.size);
	}


	if(!buff){
		errno = 0;
		if(write(cli_sock,res->header_str,strlen(res->header_str)) == -1){
			if(errno == EAGAIN || errno == EWOULDBLOCK){
				if(modify_monitor_event(cli_sock,EPOLLOUT | EPOLLET) == -1) return -1;
				return errno;
			}

			fprintf(stderr,"(%s): cannot write to socket.\n",prog);
			return -1;
		}
	}else{
		errno = 0;
		if(write(cli_sock,buff,strlen(buff)) == -1){
			if(errno == EAGAIN || errno == EWOULDBLOCK){	
				if(modify_monitor_event(cli_sock,EPOLLOUT | EPOLLET) == -1) return -1;
				return errno;
			}

			free(buff);
			fprintf(stderr,"(%s): cannot write to socket.\n",prog);
			return -1;
		}
		
		free(buff);
	}
	return 0;
}

int read_cli_sock(int cli_sock,struct Request *req)
{
	ssize_t bread = 0;	
	if((bread = read(cli_sock,req->req,BASE)) == -1){
		if(errno == EAGAIN || errno == EWOULDBLOCK) {
			int e = errno;
			if((add_socket_to_monitor(cli_sock,EPOLLIN | EPOLLET)) == -1) return -1;
			return e;
		}

		fprintf(stderr,"(%s): cannot read data from socket",prog);
		return -1;
	}
	req->size = bread;
	if(handle_request(req) == BAD_REQ){
		if(req->method == -1) return BAD_REQ;
		if(req->size < (ssize_t)BASE) return BAD_REQ;
		
		if(req->size == (ssize_t)BASE){
			if(set_up_request(bread,req) == -1) return -1;

			ssize_t move = req->size;
			if((bread = read(cli_sock,req->d_req +  move,req->size)) == -1){
				if(errno == EAGAIN || errno == EWOULDBLOCK) {
					int e = errno;
					if((add_socket_to_monitor(cli_sock,EPOLLIN | EPOLLET)) == -1) return -1;
					return e;
				}
				fprintf(stderr,"(%s): cannot read data from socket",prog);
				return -1;
			}
		}
	}

	return 0;
}

int wait_for_connections(int sock_fd,int *cli_sock, struct Request *req)
{
	struct sockaddr cli_info;
	socklen_t len = sizeof(cli_info);
	errno = 0;

	if((*cli_sock = accept4(sock_fd,&cli_info,&len,SOCK_NONBLOCK)) == -1){
		if(errno == EAGAIN || errno == EWOULDBLOCK) {
			if((add_socket_to_monitor(*cli_sock,EPOLLIN | EPOLLET)) == -1) return -1;
			return errno;
		}
		return -1;
	}
		

	int e = 0;
	if(( e = read_cli_sock(*cli_sock,req)) == -1){
		fprintf(stderr,"(%s): cannot read data from socket",prog);
		return -1;
	}
	
	if( e == EAGAIN || e == EWOULDBLOCK || e == BAD_REQ) return e;

	return 0;	
}

void stop_listening(int sock_fd)
{
	close(sock_fd);
}

int get(char *URL)
{
	/*process the url*/
	struct Url url = {0};
	if(parse_URL(URL,&url) == -1) return -1;	


	/*get addr info*/
	int rsl = 0;
	struct addrinfo hints = {0};
	struct addrinfo *result;

	hints.ai_family = AF_UNSPEC; /* allow IPv4 and IPv6*/
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

       	if((rsl = getaddrinfo(url.host,url.protocol, &hints,&result)) != 0){
		fprintf(stderr, "(%s): getaddrinfo: %s\n",prog, gai_strerror(rsl));
		return -1;
	}
	
	int  sock_fd = -1;
	struct addrinfo *rp;
	for( rp = result; rp != NULL; rp = rp->ai_next){
		if((sock_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) == -1) continue;
		if(connect(sock_fd,rp->ai_addr,rp->ai_addrlen) != -1) break;
		close(sock_fd);
	}

	freeaddrinfo(result);

	if(!rp) {
		fprintf(stderr,"(%s): could not connect to '%s'.\n",prog,URL);
		return -1;
	}
	
	/*send GET request*/
	char req[1024] = {0};
	if(snprintf(req,1024,"%s %s %s\r\n"\
				"Host: %s\r\n"\
				"User-Agent: %s\r\n"\
				"Accept: %s\r\n"\
				"Priority: %s\r\n"\
				"Connection: %s\r\n\r\n","GET", url.resource, "HTTP/1.1",
						url.host,
						prog,
						"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
						"u=0, i",
						"keep-alive") == -1){
		
		fprintf(stderr,"(%s): cannot form GET request.",prog);
		close(sock_fd);
		return -1;
	}
	
	if(write(sock_fd,req,1024) == -1){
		fprintf(stderr,"(%s): cannot send request to '%s'.\n",prog,URL);
		close(sock_fd);
		return -1;
	}

	ssize_t bread = 0;
	char buff[1024] = {0};
	if((bread = read(sock_fd,buff,1024)) == -1){
		fprintf(stderr,"(%s): cannot read from '%s'.\n",prog,URL);
		close(sock_fd);
		return -1;
	}

	fprintf(stderr,"\n%s\n",buff);
	close(sock_fd);
	return 0;
}

static int parse_URL(char *URL, struct Url *url)
{
	if(!URL) return -1;

	char *d = strstr(URL,"//");
	if(!d) return -1;

	strncpy(url->protocol,URL,d - URL -1);
	d += 2;
	int start_host = d - URL;
	char *d_s = strstr(d,"/"); 
	if(!d_s){
		/*in the url we have only the host*/
		strncpy(url->host,&URL[start_host],strlen(&URL[start_host]));
		url->resource[0] = '/';
		return 0;
	}	
	int end_host = d_s - URL;
	strncpy(url->host,&URL[start_host],end_host - start_host);
	strncpy(url->resource,++d_s,strlen(&URL[end_host+1]));
	return 0;
}
