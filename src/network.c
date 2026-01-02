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
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "network.h"       
#include "monitor.h"       

char cache_id[] = "wser";
SSL_CTX *ctx = NULL;

#define USE_HTTPS 0
static char prog[] = "wser";
static int parse_URL(char *URL, struct Url *url);
#define LISTEN_BACKLOG 50
#define MAX_BUF_SIZE 2048

int init_SSL(SSL_CTX **ctx){
	long opts;

	*ctx = SSL_CTX_new(TLS_server_method());
	if(!(*ctx)) {
		fprintf(stderr,"failed to create SSL context");
		return -1;
	}


	if(!SSL_CTX_set_min_proto_version(*ctx,TLS1_2_VERSION)) {
		fprintf(stderr,"failed to set minimum TLS version\n");
		SSL_CTX_free(*ctx);
		return -1;
	}

	/*
	 * setting the option for the SSL context
	 *
	 * for documentation on what this option are please see
	 * openSSL documentaion at 
	 * https://docs.openssl.org/master/man7/ossl-guide-tls-server-block/
	 * or 
	 * https://github.com/openssl/openssl/blob/master/demos/guide/tls-server-block.c 
	 **/

	opts = SSL_OP_IGNORE_UNEXPECTED_EOF;
	opts |= SSL_OP_NO_RENEGOTIATION;
	opts |= SSL_OP_CIPHER_SERVER_PREFERENCE;

	/*apply the selction options */
	SSL_CTX_set_options(*ctx, opts);

	if(SSL_CTX_use_certificate_chain_file(*ctx,"/path/to/your/fullchain.pem") <= 0 ) {
		fprintf(stderr,"error use certificate.\n");
		return -1;
	}

	if(SSL_CTX_use_PrivateKey_file(*ctx, "path/to/yours/privkey.pem",SSL_FILETYPE_PEM) <= 0) {
		fprintf(stderr,"error use privatekey ");
		return -1;
	}

	SSL_CTX_set_session_id_context(*ctx,(void*)cache_id,sizeof(cache_id));
	SSL_CTX_set_session_cache_mode(*ctx,SSL_SESS_CACHE_SERVER);
	SSL_CTX_sess_set_cache_size(*ctx, 1024);
	SSL_CTX_set_timeout(*ctx,3600);
	SSL_CTX_set_verify(*ctx,SSL_VERIFY_NONE, NULL);

	return 0;
}


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
		if(write(cli_sock,buff,buff_l) == -1){
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

void clean_connecion_data(struct Connection_data *cd)
{
	int i;
	for(i = 0; i < MAX_CON_DAT_ARR; i++){
		if(cd[i].ssl) SSL_free(cd[i].ssl);
		cd[i].retry_read = NULL;
		cd[i].retry_handshake = NULL;
	}

}
int read_cli_sock_SSL(int cli_sock,struct Request *req,struct Connection_data *cd)
{
	int i;
	for(i = 0; i < MAX_CON_DAT_ARR;i++){
		if(cd[i].fd == cli_sock) break;
	}

	if(i >= MAX_CON_DAT_ARR){
		return -1;
	}	
	
	if(cd[i].retry_handshake){
		/*retry handshake*/
		int r = 0;
		if((r = cd[i].retry_handshake(cd[i].ssl)) <= 0){ 
			int err = SSL_get_error(cd[i].ssl,r);
			if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE){
				return HANDSHAKE;	
			}else{
				SSL_free(cd[i].ssl);
				remove_socket_from_monitor(cli_sock);
				return -1;
			}
		}
		int result;
		size_t bread = 0;
		if((result = SSL_read_ex(cd[i].ssl,req->req,BASE,&bread)) == 0) {
			int err = SSL_get_error(cd[i].ssl,result);
			if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
				cd[i].retry_read = SSL_read_ex;
				return SSL_READ_E; 
			}else {
				SSL_free(cd[i].ssl);
				remove_socket_from_monitor(cli_sock);
				return -1;
			}
		}
		/*clear the connection data*/
		SSL_free(cd[i].ssl);
		cd[i].fd = -1;
		cd[i].ssl = NULL;
		cd[i].retry_handshake = NULL;
		cd[i].retry_read = NULL;
		return 0;
	}

	if(cd[i].retry_read){ 
		int result;
		size_t bread = 0;
		if((result = cd[i].retry_read(cd[i].ssl,req->req,BASE,&bread)) == 0){
			int err = SSL_get_error(cd[i].ssl,result);
			if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
				cd[i].retry_read = SSL_read_ex;
				return SSL_READ_E; 
			}else{
				SSL_free(cd[i].ssl);
				remove_socket_from_monitor(cli_sock);
				return -1;
			}
		}

		if(bread == BASE){
			/*TODO: read the socket again*/
		}
		/*clear the connection data*/
		SSL_free(cd[i].ssl);
		cd[i].fd = -1;
		cd[i].ssl = NULL;
		cd[i].retry_handshake = NULL;
		cd[i].retry_read = NULL;
		return 0;
	}
	return 0;
}

int read_cli_sock(int cli_sock,struct Request *req)
{
	ssize_t bread = 0;	
	errno = 0;

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
#if USE_HTTPS
	struct TLS_plain_text plain_text = {0};
	if(get_TLS_plain_text(&plain_text,(uint8_t*)req->req) == -1){
		return BAD_REQ;
	}
#else
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

#endif
	return 0;
}

int wait_for_connections_SSL(int sock_fd,int *cli_sock, struct Request *req,struct Connection_data *cd, SSL **ssl, SSL_CTX **ctx)
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
	if((*ssl = SSL_new(*ctx)) == NULL) {
		fprintf(stderr,"error creating SSL handle for new connection.\n");
		return SSL_HD_F;
	}

	if(!SSL_set_fd(*ssl,*cli_sock)) {
		fprintf(stderr,"error setting socket to SSL context.\n");
		SSL_free(*ssl);
		return SSL_SET_E;		
	}		

	/*try handshake with the client*/	
	int hs_res = 0;
	if((hs_res = SSL_accept(*ssl)) <= 0) {
		int err = SSL_get_error(*ssl,hs_res);
		if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
			/* 
			 * socket is not ready
			 * so we add the file descriptor to the epoll system
			 * and return;
			 * */
			if((add_socket_to_monitor(*cli_sock,EPOLLIN | EPOLLET)) == -1) {
				SSL_free(*ssl);
				return -1;
			}

			cd->fd = *cli_sock;
			cd->ssl = *ssl;
			cd->retry_handshake = SSL_accept;
			return HANDSHAKE;		
		}else {
			SSL_free(*ssl);
			remove_socket_from_monitor(*cli_sock);
			stop_listening(*cli_sock);
			return -1;
		}
	}

	size_t bread = 0;
	int result = 0;
	/*TODO: use SSL_peek_ex() instead?*/
	if((result = SSL_read_ex(*ssl,req->req,BASE,&bread)) == 0) {
		int err = SSL_get_error(*ssl,result);
		if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
			/* 
			 * socket is not ready add the file descriptor to the epoll system
			 * */
			if((add_socket_to_monitor(*cli_sock,EPOLLIN | EPOLLET)) == -1) {
				SSL_free(*ssl);
				return -1;
			}

			cd->fd = *cli_sock;
			cd->ssl = *ssl;
			cd->retry_read= SSL_read_ex;
			return SSL_READ_E; 
		}else {
			SSL_free(*ssl);
			remove_socket_from_monitor(*cli_sock);
			stop_listening(*cli_sock);
			return -1;
		}
	}

	if(bread == BASE){
		/*
		 * TODO: read again the socket,
		 * req is bigger than BASE = (1024 bytes)*/
	}
	/* DEL THIS*/
	int e = 0;
	if(( e = read_cli_sock(*cli_sock,req)) == -1){
		fprintf(stderr,"(%s): cannot read data from socket",prog);
		return -1;
	}

	if( e == EAGAIN || e == EWOULDBLOCK || e == BAD_REQ) return e;
	/**/

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
	char buff[MAX_BUF_SIZE] = {0};
	if((bread = read(sock_fd,buff,MAX_BUF_SIZE)) == -1){
		fprintf(stderr,"(%s): cannot read from '%s'.\n",prog,URL);
		close(sock_fd);
		return -1;
	}

	int index = find_headers_end(buff, (size_t)bread);

	/* === PROCESS THE RESPONSE HEADER
	 *
	 * TODO: if transfer encoding then look for the number and keep reading the data 
	 * === DO NOT PRINT THE HEADER ===
	 * */

	fprintf(stderr,"\n%s\n",&buff[index]);
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
