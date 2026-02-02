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
#include <assert.h>
#include "network.h"       
#include "response.h"       
#include "request.h"       
#include "monitor.h"       

char cache_id[] = "wser";
SSL_CTX *ctx = NULL;
SSL *ssl_client = NULL;

#define USE_HTTPS 0
static char prog[] = "wser";
static int SSL_client_setup(SSL_CTX **ctx);
static int handle_client_IO(SSL *ssl, int ret);
static int wait_for_activity(SSL *ssl, int w_r);
static long read_hex_for_transfer_encoding(char *hex, int *h_end);
static void clean_CRNL(char *str);
static void clean_garbage(char *str);
static void debugf(char *fmt);
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
	if(SSL_CTX_use_certificate_chain_file(*ctx,"/path/to/your/certificate") <= 0 ) {
		fprintf(stderr,"error use certificate.\n");
		return -1;
	}

	if(SSL_CTX_use_PrivateKey_file(*ctx, "path/to/your/private.key",SSL_FILETYPE_PEM) <= 0) {
		fprintf(stderr,"error use privatekey ");
		return -1;
	}

	SSL_CTX_set_session_id_context(*ctx,(void*)cache_id,sizeof(cache_id));
	SSL_CTX_set_session_cache_mode(*ctx,SSL_SESS_CACHE_SERVER);
	SSL_CTX_sess_set_cache_size(*ctx, 1024);
	SSL_CTX_set_timeout(*ctx,3600);
	SSL_CTX_set_verify(*ctx,SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_cipher_list(*ctx,"ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!MD5:!RC4:!3DES");
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

int connect_UNIX_socket(int opt, char *sock_path)
{
       struct sockaddr_un address_socket_family;
       memset(&address_socket_family,0,sizeof(struct sockaddr_un));
   
       int sock_un = socket(AF_UNIX,SOCK_SEQPACKET,0);
       if(sock_un == -1) return -1;
       
       /*bind to a file_path*/
       address_socket_family.sun_family = AF_UNIX;
	   strncpy(address_socket_family.sun_path,sock_path,strlen(sock_path)+1);  

	   if(opt == SOCK_NONBLOCK){
		   if(fcntl(sock_un,F_SETFD,O_NONBLOCK) == -1){
			   return -1;
		   }
	   }

	   errno = 0;
	   int result = connect(sock_un,(const struct sockaddr*) &address_socket_family,sizeof(address_socket_family));
	   if(result == -1) {
		   if(errno == ECONNREFUSED){
			   fprintf(stderr," !!!!! you need a bigger que for UNIX_SOCK !!!!!!\n");
		   }
		   return -1;
	   }

	   return sock_un;

}

int listen_UNIX_socket(int opt, char *sock_path) 
{
	struct sockaddr_un address_socket_family;
	memset(&address_socket_family,0,sizeof(struct sockaddr_un));

	int sock_un = socket(AF_UNIX,SOCK_SEQPACKET,0);
	if(sock_un == -1) return -1;
	
	/*bind to a file_path*/
	address_socket_family.sun_family = AF_UNIX;
	strncpy(address_socket_family.sun_path,sock_path,strlen(sock_path)+1);	

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

	assert(i < MAX_CON_DAT_ARR);

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
					/*SSL_free(cd[i].ssl);*/
					/*remove_socket_from_monitor(cli_sock);*/
					return -1;
				}
				cd[i].retry_write = SSL_write_ex;
				memcpy(&cd[i].res,res,sizeof(struct Response));
				return SSL_WRITE_E;
			}else{
				//remove_socket_from_monitor(cli_sock);
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
				//	SSL_free(cd[i].ssl);
				//	remove_socket_from_monitor(cli_sock);
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
		}
		//remove_socket_from_monitor(cli_sock);
		cd[i].fd = -1;
		free(buff);
	}
	/*Write was succesful we can shutdown the TLS section*/
		
	int r = 0;
	while((r = SSL_shutdown(cd[i].ssl) != 1)){
		if((r = handle_client_IO(cd[i].ssl,r)) == 1)
			continue;
		else if(r == 2 || r == 0)
			break;

		return -1;
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
		ssize_t sign_bread = 0;
		if(handle_request(req) == BAD_REQ){
			if(req->method == -1) return BAD_REQ;
			if(req->size < (ssize_t)BASE) return BAD_REQ;

			if(req->size == (ssize_t)BASE){
				if(set_up_request(bread,req) == -1) return -1;

				ssize_t move = req->size;
				if((sign_bread = read(cli_sock,req->d_req +  move,req->size)) == -1){
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

void SSL_client_close(){
	SSL_CTX_free(ctx);
	SSL_free(ssl_client);
}
int SSL_client_config(){
	if(SSL_client_setup(&ctx) != 0){
		if(ctx)
			SSL_CTX_free(ctx);

		return -1;
	}
	if((ssl_client = SSL_new(ctx)) == NULL){
		SSL_CTX_free(ctx);
		return -1;
	}
	return 0;
}

int perform_http_request(char *URL, char *req, char **body)
{
	/*process the url*/
	struct Url url = {0};
	if(parse_URL(URL,&url) == -1) return -1;	

	int secure = 0;
	if(!ssl_client){
		if(strncmp(url.protocol,"https",5) == 0)
			secure = 1;
	} else{
		secure = 1;
	}

	if(secure){
		if(!ssl_client){
			if(SSL_client_setup(&ctx) != 0){
				if(ctx)
					SSL_CTX_free(ctx);

				return -1;
			}
			if((ssl_client = SSL_new(ctx)) == NULL){
				SSL_CTX_free(ctx);
				return -1;
			}
		}else{
			SSL_clear(ssl_client);
		}
	}

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

	if(fcntl(sock_fd,F_SETFD,O_NONBLOCK) == -1){
		close(sock_fd);
		return -1;
	}

	if(!rp) {
		fprintf(stderr,"(%s): could not connect to '%s'.\n",prog,URL);
		return -1;
	}

	if(ssl_client){
		if(!SSL_set_fd(ssl_client,sock_fd)){
			close(sock_fd);
			return -1;
		}

		if(!SSL_set_tlsext_host_name(ssl_client,url.host)){
			close(sock_fd);
			return -1;
		}

		if(!SSL_set1_host(ssl_client,url.host)){
			close(sock_fd);
			return -1;
		}

		int ret = 0;
		while((ret = SSL_connect(ssl_client)) != 1){
			int r = handle_client_IO(ssl_client,ret); 
			if(r == 1)
				continue;
			else if( r == 0)
				break;

			close(sock_fd);
			return -1;
		}
	}

	size_t bread = 0;
	char buff[MAX_BUF_SIZE] = {0};
	char *pbuf = &buff[0];
	char *all_data_from_the_response = NULL;
	if(ssl_client){
		size_t bwritten = 0;
		while(!SSL_write_ex(ssl_client,req,strlen(req),&bwritten)){
			if(handle_client_IO(ssl_client,0) == 1)
				continue;

			close(sock_fd);
			return -1;
		}

		size_t first_alloc = 0;
		int h_end = 0;
		int index = 0;
		int eof = 0;
		int tf = 0;
		size_t sz = 0;
		size_t byte_to_read = MAX_BUF_SIZE-1;
		while((!eof && !SSL_read_ex(ssl_client,&pbuf[index],byte_to_read,&bread)) || (bread <= byte_to_read) || tf){
			if(!tf){
				/*check for transfer encoding */
				if(pbuf[0] == '{'){
					if(strstr(pbuf,"\"message\":")){
						break;
					}
				}
				if(strstr(pbuf,"Transfer-Encoding")){
					tf = 1;
					h_end = find_headers_end(pbuf, strlen(pbuf));
					if(h_end == bread && bread < byte_to_read){
						index = h_end;
						byte_to_read -= index;
						tf = 0;
						continue;
					}
					sz = read_hex_for_transfer_encoding(&pbuf[h_end], &h_end); 
					/*allocate memory for the chunk*/
					size_t r = 0;
					if(( r = strlen(&pbuf[h_end])) > sz)
						sz += r;

					pbuf = calloc(sz,sizeof(char));	
					if(!pbuf){
						close(sock_fd);
						return -1;
					}

					index = r;
					byte_to_read = sz - r - 1;
					assert(byte_to_read < sz);
					assert(byte_to_read > 0);
					strncpy(pbuf,&buff[h_end],r);
					first_alloc = sz;
					assert((sz - strlen(pbuf)) > byte_to_read);
					continue;
				}
				if(bread == byte_to_read){
					if(pbuf == &buff[0]){
						index = strlen(buff);	
						pbuf = calloc(MAX_BUF_SIZE*2,sizeof(char));  
						if(!pbuf){
							close(sock_fd);
							return -1;
						}
						first_alloc = (MAX_BUF_SIZE * 2);
						memcpy(pbuf,buff,strlen(buff));
						byte_to_read = MAX_BUF_SIZE-1;
						sz = first_alloc;
						assert((sz - strlen(pbuf)) > byte_to_read);
						continue;
					}

					char *new = realloc(pbuf,first_alloc += MAX_BUF_SIZE);
					if(!new){
						close(sock_fd);
						return -1;
					}
					pbuf = new;
					continue;
				}

				long ix = 0;
				if((ix = find_headers_end(pbuf,strlen(pbuf))) == -1 || ix == (long)strlen(pbuf)){
					/*response header is not complete */
						index = strlen(pbuf);
						if((size_t)index >= byte_to_read){
							if(first_alloc){
								byte_to_read =  first_alloc - index - 1;
								assert(byte_to_read < sz);
								assert(byte_to_read > 0);
								assert((sz - strlen(pbuf)) > byte_to_read);
							}
						}else{
							byte_to_read -= index;
							assert(byte_to_read < sz);
							assert(byte_to_read > 0);
							assert((sz - strlen(pbuf)) > byte_to_read);
						}
						continue;
				}

			}else{
			//	debugf(pbuf);
				if(!strstr(pbuf,"\r\n0\r\n")){
					char *CRNL = strstr(pbuf,"\r\n");
					if(CRNL){
						/*make sure you have the all size data*/
						*CRNL = ' ';
						if(!strstr(CRNL,"\r\n")){
								*CRNL = '\r';
								index = strlen(pbuf);		
								byte_to_read = sz - index -1;
								assert(byte_to_read < sz);
								assert(byte_to_read > 0);
								if(byte_to_read == 0){
									char *f = strstr(CRNL,"\r\n");
									*f = '\0';
									long sn = strtol(pbuf,NULL,16);
									char *new = realloc(pbuf,sz+sn);
									if(!new){
										close(sock_fd);
										return -1;
									}
									pbuf = new;
									sz += sn;
									index = strlen(pbuf);		
									byte_to_read = sz - index -1;
									assert(byte_to_read < sz);
									assert(byte_to_read > 0);
									assert((sz - strlen(pbuf)) > byte_to_read);
									continue;
								}

								if((size_t)index > sz){
									/*realloc*/
								}
								continue;
						}
						/*we have all the chunked size info*/
						*CRNL = '\r';
						CRNL += 2;
						int hinx =(int) (CRNL - pbuf);
						long sz_to_realloc = read_hex_for_transfer_encoding(CRNL,&hinx);		
						assert(sz_to_realloc > 0);
						char *new = realloc(pbuf,sz += sz_to_realloc);
						if(!new){
							close(sock_fd);
							break;
						}
						pbuf  = new;
						memset(&pbuf[strlen(pbuf)],0,sz- strlen(pbuf));
						index = strlen(pbuf); 
						byte_to_read = sz_to_realloc-1;
						assert(byte_to_read < sz);
						assert(byte_to_read > 0);
						assert((sz - strlen(pbuf)) > byte_to_read);
						clean_CRNL(pbuf);
						continue;
					}
					index = strlen(pbuf);		
					byte_to_read = sz - index -1;
					if(byte_to_read == 0 && first_alloc > 0){
						/*realloc*/
						char *new = realloc(pbuf,sz += MAX_BUF_SIZE);
						if(!new){
							close(sock_fd);
							break;
						}
						pbuf = new;
						memset(&pbuf[strlen(pbuf)],0,sz - strlen(pbuf));
						byte_to_read = sz - strlen(pbuf) - 1;		
						assert(byte_to_read < sz);
						assert(byte_to_read > 0);
						assert((sz - strlen(pbuf)) > byte_to_read);
					}
					continue;
				}
				/*here you have all the body*/
				tf = 0;
				h_end = find_headers_end(buff, strlen(buff));
				read_hex_for_transfer_encoding(&buff[h_end],&h_end);
				long l = strlen(&buff[h_end]) + strlen(pbuf) +1;
				if(!body){
					all_data_from_the_response = calloc(l,sizeof(char));
					if(!all_data_from_the_response){
						close(sock_fd);
						return -1;
					}
				}else{
					*body = calloc(l,sizeof(char));
					if(!body){
						close(sock_fd);
						return -1;
					}
				}

				clean_CRNL(pbuf);
				/*clear the response properly*/
				clean_garbage(pbuf);
				size_t first_fragment = strlen(&buff[h_end]);
				strncpy( body ? *body : all_data_from_the_response,&buff[h_end],first_fragment);
				strncpy(body ? &(*body)[first_fragment] : &all_data_from_the_response[first_fragment],pbuf,strlen(pbuf));
				free(pbuf);
				clean_CRNL(body ? *body : all_data_from_the_response);
				break;
			}


			int r = 0;
			if((r = handle_client_IO(ssl_client,0)) == 1){
				continue;
			}else if(r == 0 || r == 2){
				eof = 1;
				break;
			}
		}

		if(all_data_from_the_response){
			fwrite(all_data_from_the_response,1,strlen(all_data_from_the_response),stdout);
			free(all_data_from_the_response);
		}else if(body){
			if(*body == NULL){
				*body = calloc(strlen(buff)+1,sizeof(char));	
				if(!(*body)){
					close(sock_fd);
					return -1;
				}
				int inx = find_headers_end(buff,strlen(buff));
				if(inx == -1){
					strncpy(*body,buff,strlen(buff));
				}else{
					strncpy(*body,&buff[inx],strlen(&buff[inx]));
				}
			}
		}else{
			fwrite(buff,1,strlen(buff),stdout);
		}

		int ret = 0;
		while((ret = SSL_shutdown(ssl_client)) != 1){
			if(ret < 0 && handle_client_IO(ssl_client,ret) == 1)
				continue;

			close(sock_fd);
			return -1;
		}

	}else{
		if(write(sock_fd,req,strlen(req)) == -1){
			fprintf(stderr,"(%s): cannot send request to '%s'.\n",prog,URL);
			close(sock_fd);
			return -1;
		}
		if((bread = read(sock_fd,buff,MAX_BUF_SIZE)) == -1){
			fprintf(stderr,"(%s): cannot read from '%s'.\n",prog,URL);
			close(sock_fd);
			return -1;
		}
	}

	close(sock_fd);
	int index = find_headers_end(buff, (size_t)bread);
	
	if(body && !(*body)){
		*body = calloc(strlen(&buff[index])+1,sizeof(char));		
		if(!(*body)){

		}
		strncpy(*body,&buff[index],strlen(&buff[index]));
	}else{
		fprintf(stderr,"\n%s\n",&buff[index]);
	}
	return 0;
}

int parse_URL(char *URL, struct Url *url)
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
	strncpy(url->resource,d_s,strlen(&URL[end_host]));
	return 0;
}

static int SSL_client_setup(SSL_CTX **ctx)
{

	*ctx = SSL_CTX_new(TLS_client_method());
	if(!(*ctx))
		return -1;

	SSL_CTX_set_verify(*ctx,SSL_VERIFY_PEER,NULL);

	if(!SSL_CTX_set_default_verify_paths(*ctx))
		return -1;

	if(!SSL_CTX_set_min_proto_version(*ctx,TLS1_2_VERSION))
		return -1;
	return 0;
}

static int handle_client_IO(SSL *ssl, int ret)
{
	int err = SSL_get_error(ssl,ret);
	ERR_print_errors_fp(stderr);
	switch(err){
		case SSL_ERROR_NONE:
			return 2;
		case SSL_ERROR_ZERO_RETURN:
		case SSL_ERROR_SYSCALL:
			return 0;
		case SSL_ERROR_WANT_READ:
			if(wait_for_activity(ssl,0) == -1)
				return -1;
			return 1;
		case SSL_ERROR_WANT_WRITE:
			if(wait_for_activity(ssl,1) == -1)
				return -1;
			return 1;
		case SSL_ERROR_SSL:
			return -1;
		default:
			return -1;
	}
	return -1;
}

static int wait_for_activity(SSL *ssl, int w_r)
{
	int fd = SSL_get_fd(ssl);
	if(start_monitor(fd) == -1)
		return -1;

	modify_monitor_event(fd,w_r ? EPOLLOUT : EPOLLIN);
	int n = monitor_events();
	return n;
}

static long read_hex_for_transfer_encoding(char *hex, int *h_end)
{
	char *t = strstr(hex,"\r\n");
	int t_pos = (int)(t - hex);
	*t = '\0';
	t--;
	while(*t != '\0' && *t != '\r' && *t != '\n'){ 
		t--; 
	}
	
	*h_end += strlen(++t) + 2;        
	long n = strtol(t,NULL,16);
	hex[t_pos] = '\r';
	return  n;
}

static void clean_CRNL(char *str)
{
	char *n = NULL;
	int c = 0;
	while((n = strstr(str,"\r\n"))){
		if(c == 2) return;
		*n = ' ';
		n++;
		*n = ' ';	
		c++;
	}
}
static void clean_garbage(char *str)
{
	char *space = NULL;
	while(( space = strstr(str, "  "))){
		int start = space - str;
		space += 2;
		while(*space != ' ') space++;
		

		int end = ++space - str;
		if((end - start) > 8)
			return;
		
		size_t s = strlen(&str[end+1]);
		char cpy[s+1];
		memset(cpy,0,s+1);
		strncpy(cpy,&str[end+1],s);
		strncpy(&str[start],cpy,s);
		str[start + s]= '\0';
		int trailing = strlen(&str[start+s+1]);
		if(trailing > 0)
			memset(&str[start + s],0,trailing);
	}
}

int req_builder(int method, char *urlstr, char *format_str, char *req, int length)
{ 
	struct Url url = {0};
	if(parse_URL(urlstr,&url) == -1)
		return -1;

	switch(method){
		case GET:
			if(snprintf(req,1024,format_str,"GET", 
						url.resource, 
						"HTTP/1.1",
						url.host,
						"wser") == -1){
				fprintf(stderr,"(%s): cannot form GET request.",prog);
				return -1;
			}
			break;
		case POST:
			if(snprintf(req,1024,format_str,"POST", 
						url.resource, "HTTP/1.1",
						url.host,
						"wser",
						length) == -1){

				fprintf(stderr,"(%s): cannot form GET request.",prog);
				return -1;
			}
			break;
		default:
	}
	return 0;
}


static void debugf(char *fmt)
{
	char *start = fmt;
	for(;*fmt;fmt++){
		if(*fmt =='\r'){
			printf("\\r");
			continue;
		}
		if(*fmt == '\n'){
			printf("\\n");
			continue;
		}

		printf("%c",*fmt);
	}
	fmt = start;
	printf("\n====================\n");
}
