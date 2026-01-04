#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netdb.h>
#include <errno.h>
#include <ifaddrs.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <fcntl.h>
#include "network.h"       
#include "response.h"       
#include "monitor.h"       

char cache_id[] = "wser";
SSL_CTX *ctx = NULL;

#define USE_HTTPS 0
static char prog[] = "wser";
static int parse_URL(char *URL, struct Url *url);
#define LISTEN_BACKLOG 50
#define MAX_BUF_SIZE 2048

struct Connection_data cds[MAX_CON_DAT_ARR] = {0};

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
	if(SSL_CTX_use_certificate_chain_file(*ctx,"/etc/letsencrypt/live/lorenzopiombini.com/fullchain.pem") <= 0 ) {
		fprintf(stderr,"error use certificate.\n");
		return -1;
	}

	if(SSL_CTX_use_PrivateKey_file(*ctx, "/etc/letsencrypt/live/lorenzopiombini.com/privkey.pem",SSL_FILETYPE_PEM) <= 0) {
		fprintf(stderr,"error use privatekey ");
		return -1;
	}

	SSL_CTX_set_session_id_context(*ctx,(void*)cache_id,sizeof(cache_id));
	SSL_CTX_set_session_cache_mode(*ctx,SSL_SESS_CACHE_SERVER);
	SSL_CTX_sess_set_cache_size(*ctx, 1024);
	SSL_CTX_set_timeout(*ctx,3600);
	SSL_CTX_set_verify(*ctx,SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_cipher_list(ctx,"ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!MD5:!RC4:!3DES");
	SSL_CTX_set_ciphersuites(*ctx,"TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256");
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

int listen_UNIX_socket(int opt) 
{
	
	struct sockaddr_un address_socket_family;
	memset(&address_socket_family,0,sizeof(struct sockaddr_un));

	int sock_un = socket(AF_UNIX,SOCK_SEQPACKET,0);
	if(sock_un == -1) return -1;
	
	/*bind to a file_path*/
	address_socket_family.sun_family = AF_UNIX;
	strncpy(address_socket_family.sun_path,INT_PROC_SOCK_SSL,strlen(INT_PROC_SOCK_SSL)+1);	

	if(opt == SOCK_NONBLOCK){
		if(fcntl(sock_un,F_SETFD,O_NONBLOCK) == -1){
			return -1;
		}
	}
	unlink(INT_PROC_SOCK_SSL);
	int result = bind(sock_un,(const struct sockaddr *) &address_socket_family,sizeof(address_socket_family));
	if(result == -1) return -1;

	/*listen socket*/
	if(listen(sock_un,20) == -1) return -1;
	

	return sock_un;

}

int write_cli_SSL(int cli_sock, struct Response *res, struct Connection_data *cd)
{
	int i;
	for(i = 0; i < MAX_CON_DAT_ARR; i++){
		if(cd[i].fd == cli_sock) break;
	}

	if(i >= MAX_CON_DAT_ARR) return -1;

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
		size_t bwritten;
		int r = 0;
		if((r = SSL_write_ex(cd[i].ssl,res->header_str,strlen(res->header_str),&bwritten)) == 0){
			int err = SSL_get_error(cd[i].ssl,r);
			if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
				if(modify_monitor_event(cli_sock,EPOLLOUT | EPOLLET) == -1){
					SSL_free(cd[i].ssl);
					remove_socket_from_monitor(cli_sock);
					return -1;
				}
				cd[i].retry_write = SSL_write_ex;
				memcpy(&cd[i].res,res,sizeof(struct Response));
				return SSL_WRITE_E;
			}else{
				SSL_free(cd[i].ssl);
				remove_socket_from_monitor(cli_sock);
				cd[i].fd = -1;
				return -1;
			}
			fprintf(stderr,"(%s): cannot write to socket.\n",prog);
			return -1;
		}
	}else{
		size_t bwritten;
		int r = 0;
		if((r = SSL_write_ex(cd[i].ssl,buff,strlen(buff),&bwritten)) == 0){
			int err = SSL_get_error(cd[i].ssl,r);
			if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
				if(modify_monitor_event(cli_sock,EPOLLOUT | EPOLLET) == -1) {
					SSL_free(cd[i].ssl);
					remove_socket_from_monitor(cli_sock);
					return -1;
				}

				cd[i].retry_handshake = NULL;
				cd[i].retry_read = NULL;
				cd[i].retry_write = SSL_write_ex;
				cd[i].buf = buff;
				return SSL_WRITE_E;
			}

			free(buff);
			fprintf(stderr,"(%s): cannot write to socket.\n",prog);
			return -1;
		}else{
			SSL_free(cd[i].ssl);
			remove_socket_from_monitor(cli_sock);
			cd[i].fd = -1;
			free(buff);
			return -1;
		}

		free(buff);
	}
	return 0;
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


void clean_connecion_data(struct Connection_data *cd, int sock)
{
	if(sock != -1){
				
		int i;
		for(i = 0; i < MAX_CON_DAT_ARR; i++){
			if(cd[i].fd != sock) continue;

			cd[i].fd = -1;
			if(cd[i].ssl) SSL_free(cd[i].ssl);
			cd[i].retry_read = NULL;
			cd[i].retry_handshake = NULL;
			cd[i].retry_write = NULL;
			clear_response(&cd[i].res);
			if(cd[i].buf) free(cd[i].buf);
			return ;
		}

		return;
	}
	int i;
	for(i = 0; i < MAX_CON_DAT_ARR; i++){
		cd[i].fd = -1;
		if(cd[i].ssl) SSL_free(cd[i].ssl);
		cd[i].retry_read = NULL;
		cd[i].retry_handshake = NULL;
		cd[i].retry_write = NULL;
		clear_response(&cd[i].res);
		if(cd[i].buf) free(cd[i].buf);
	}

}
int read_cli_sock_SSL(int cli_sock,struct Request *req,struct Connection_data *cd)
{
	int i;
	for(i = 0; i < MAX_CON_DAT_ARR;i++){
		if(cd[i].fd == cli_sock) break;
	}

	if(i >= MAX_CON_DAT_ARR){
		return NO_CON_DATA;
	}	
	
	if(cd[i].retry_handshake){
		/*retry handshake*/
		int r = 0;
		if((r = cd[i].retry_handshake(cd[i].ssl)) <= 0){ 
			int err = SSL_get_error(cd[i].ssl,r);
			if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE){
				return HANDSHAKE;	
			}else{
				fprintf(stderr,"the error happens when retrying handshake\n");
				ERR_print_errors_fp(stderr);
				SSL_free(cd[i].ssl);
				remove_socket_from_monitor(cli_sock);
				cd[i].fd = -1;
				cd[i].ssl = NULL;
				cd[i].retry_handshake = NULL;
				cd[i].retry_read = NULL;
				return -1;
			}
		}
		cd[i].retry_handshake = NULL;
		int result;
		size_t bread = 0;
		if((result = SSL_read_ex(cd[i].ssl,req->req,BASE,&bread)) == 0) {
			int err = SSL_get_error(cd[i].ssl,result);
			if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
				cd[i].retry_read = SSL_read_ex;
				return SSL_READ_E; 
			}else if (bread == BASE){
				fprintf(stderr,"the issue is not enogh space in the buffer\n");
				ERR_print_errors_fp(stderr);
				SSL_free(cd[i].ssl);
				remove_socket_from_monitor(cli_sock);
				cd[i].fd = -1;
				cd[i].ssl = NULL;
				cd[i].retry_handshake = NULL;
				cd[i].retry_read = NULL;
				return -1;
			}else{
				fprintf(stderr,"the error happens when reading SSL after handshake\n");
				ERR_print_errors_fp(stderr);
				SSL_free(cd[i].ssl);
				remove_socket_from_monitor(cli_sock);
				cd[i].fd = -1;
				cd[i].ssl = NULL;
				cd[i].retry_handshake = NULL;
				cd[i].retry_read = NULL;
				return -1;
			}
		}
		/*clear the connection data*/
		return 0;
	}

	if(cd[i].retry_read){ 
		int result;
		size_t bread = 0;
		if((result = cd[i].retry_read(cd[i].ssl,req->req,BASE,&bread)) == 0){
			int err = SSL_get_error(cd[i].ssl,result);
			if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
				return SSL_READ_E; 
			}else{
				fprintf(stderr,"the error happens when retrying read\n");
				ERR_print_errors_fp(stderr);
				SSL_free(cd[i].ssl);
				remove_socket_from_monitor(cli_sock);
				cd[i].fd = -1;
				cd[i].ssl = NULL;
				cd[i].retry_handshake = NULL;
				cd[i].retry_read = NULL;
				return -1;
			}
		}

		cd[i].retry_read = NULL;
		if(bread == BASE){
			fprintf(stderr,"buffer is not big enough\n");
			/*TODO: read the socket again*/
		}
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

int wait_for_connections_SSL(int sock_fd,int *cli_sock)
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
