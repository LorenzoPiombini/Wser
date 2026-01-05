#include <poll.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include "load.h"
#include "ssl_process.h"
#include "network.h"
#include "request.h"
#include "response.h"
#include "monitor.h"

static char prog[] = "ssl process";
static int handle_ssl_steps(struct Connection_data *cd, 
							int cli_sock,
							struct Request *req,
							SSL **ssl,
							SSL_CTX **ctx);


int SSL_work_process(int data_sock)
{
	if(init_SSL(&ctx) == -1){
		fprintf(stderr,"(%s): cannot start SSL context.\n",prog);
		kill(getppid(),SIGINT);
		exit(1);
		return -1;
	}

	if(start_monitor(data_sock) == -1) {
		fprintf(stderr,"(%s): monitor event startup failed.\n",prog);
		kill(getppid(),SIGINT);
		exit(1);
	}


	/*setting up to receiving file descriptor from another process*/
	int            data, cli_sock;
	struct iovec   iov;
	struct msghdr  msgh;

	/* Allocate a char buffer for the ancillary data. See the comments
	   in sendfd() */
	union {
		char   buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} controlMsg;
	struct cmsghdr *cmsgp;

	/* The 'msg_name' field can be used to obtain the address of the
	   sending socket. However, we do not need this information. */

	msgh.msg_name = NULL;
	msgh.msg_namelen = 0;

	/* Specify buffer for receiving real data */

	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	iov.iov_base = &data;       /* Real data is an 'int' */
	iov.iov_len = sizeof(int);

	/* Set 'msghdr' fields that describe ancillary data */

	msgh.msg_control = controlMsg.buf;
	msgh.msg_controllen = sizeof(controlMsg.buf);

	SSL *ssl_cli = NULL;
	for(;;){
		if((nfds = monitor_events()) == -1) break;	
		if(nfds == EINTR) continue;
		for(int i = 0; i < nfds; i++){
			if(events[i].data.fd == data_sock){
				int sock = -1;
				errno = 0;
				if((sock = accept(data_sock,NULL,NULL)) == -1)
				/* Receive real plus ancillary data; real data is ignored */

				if(errno == EAGAIN || errno == EWOULDBLOCK) continue;

				errno = 0;
				if(recvmsg(data_sock, &msgh, 0) == -1){
					if(errno == EAGAIN || errno == EWOULDBLOCK) continue;
					continue;
				}

				if (cmsgp == NULL
						|| cmsgp->cmsg_len != CMSG_LEN(sizeof(int))
						|| cmsgp->cmsg_level != SOL_SOCKET
						|| cmsgp->cmsg_type != SCM_RIGHTS) continue;


				memcpy(&cli_sock, CMSG_DATA(cmsgp), sizeof(int));

				struct Request req = {0};
				int r = handle_ssl_steps(cds,cli_sock,&req,&ssl_cli,&ctx);

				if(r == -1) continue;
				if(r == 0){
					/*process request*/
					switch(req.method){
						case GET:
							{
								struct Response res = {0};
								struct Content cont = {0};
								/* Load content */	
								if(load_resource(req.resource,&cont) == -1){
									/*send not found response*/
									if(generate_response(&res,404,NULL,&req) == -1) break;

									int w = 0;
									if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) break;
									if( w == SSL_WRITE_E) {
										clear_response(&res);
										clear_request(&req);
										clear_content(&cont);
										continue;
									}
									clear_response(&res);
									clear_request(&req);
									clear_content(&cont);
									continue;
								}

								/*send 200 response*/
								if(generate_response(&res,OK,&cont,&req) == -1) {
									clear_content(&cont);
									clear_response(&res);
									clear_request(&req);
									continue;
								}

								clear_content(&cont);
								int w = 0;
								if((w = write_cli_SSL(cli_sock,&res,cds)) == -1){
									clear_request(&req);
									clear_response(&res);
									break;
								}
								if(w == SSL_WRITE_E){
									clear_request(&req);
									clear_response(&res);
									continue;
								}
								clear_request(&req);
								clear_response(&res);
								continue;
				}
				case BAD_REQ:
				{
					struct Response res = {0};
					/*send a bed request response*/
					if(generate_response(&res,400,NULL,&req) == -1) {
						clear_response(&res);
						clear_request(&req);
						break;
					}

					int w = 0;
					if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) {
						clear_response(&res);
						clear_request(&req);
						break;
					}
					if(w == SSL_WRITE_E){
						clear_response(&res);
						clear_request(&req);
						continue;
					}
					clear_response(&res);
					clear_request(&req);
					continue;
				}
				case SSL_SET_E:
				/*TODO*/
				default:
				continue;
			}


				}
			}else{
				struct Request req = {0};
				int r = handle_ssl_steps(cds,events[i].data.fd,&req,&ssl_cli,&ctx);

				if(r == -1){
					clear_request(&req);
					continue;
				}

				switch(r){
					case SSL_READ_E:
					case HANDSHAKE:
						{		
							r = handle_ssl_steps(cds,cli_sock,&req,&ssl_cli,&ctx);
							if( r == 0){
								/*falls to case 0*/
							}else{
								break;
							}
						}
					case 0:
						{
							/*process request*/
							switch(req.method){
								case GET:
									{
										struct Response res = {0};
										struct Content cont = {0};
										/* Load content */	
										if(load_resource(req.resource,&cont) == -1){
											/*send not found response*/
											if(generate_response(&res,404,NULL,&req) == -1){
												clear_response(&res);
												clear_request(&req);
												clear_content(&cont);
												remove_socket_from_monitor(events[i].data.fd);
												break;
											}

											int w = 0;
											if((w = write_cli_SSL(cli_sock,&res,cds)) == -1){
												clear_response(&res);
												clear_request(&req);
												clear_content(&cont);
												break;
											}

											if( w == SSL_WRITE_E){
												clear_response(&res);
												clear_request(&req);
												clear_content(&cont);
												continue;
											}

											clear_response(&res);
											clear_request(&req);
											clear_content(&cont);
											remove_socket_from_monitor(events[i].data.fd);
											continue;
										}

										/*send 200 response*/
										if(generate_response(&res,OK,&cont,&req) == -1) {
											clear_content(&cont);
											clear_response(&res);
											clear_request(&req);
											remove_socket_from_monitor(events[i].data.fd);
											continue;
										}

										clear_content(&cont);
										int w = 0;
										if((w = write_cli_SSL(cli_sock,&res,cds)) == -1){
											clear_request(&req);
											clear_response(&res);
											break;
										}

										if(w == SSL_WRITE_E){
											clear_request(&req);
											clear_response(&res);
											continue;
										}
										clear_request(&req);
										clear_response(&res);
										remove_socket_from_monitor(events[i].data.fd);
										continue;
									}
								default:
							}
							break;
						}
					case BAD_REQ:
						{
							struct Response res = {0};
							/*send a bed request response*/
							if(generate_response(&res,400,NULL,&req) == -1){
								clear_response(&res);
								clear_request(&req);
								remove_socket_from_monitor(events[i].data.fd);
								break;
							}

							int w = 0;
							if((w = write_cli_SSL(cli_sock,&res,cds)) == -1){
								clear_response(&res);
								clear_request(&req);
								break;
							}
							if(w == SSL_WRITE_E){
								clear_response(&res);
								clear_request(&req);
								continue;
							}
							clear_response(&res);
							clear_request(&req);
							remove_socket_from_monitor(events[i].data.fd);
							continue;
						}
					case WRITE_OK:
						remove_socket_from_monitor(events[i].data.fd);
						break;
					case SSL_SET_E:
					default:
						continue;
				}
			}
		}
	}
	SSL_CTX_free(ctx);
	clean_connecion_data(cds,-1);
	return 0;
}

static int handle_ssl_steps(struct Connection_data *cd, 
		int cli_sock,
		struct Request *req,
		SSL **ssl,
		SSL_CTX **ctx)
{
	int i;
	for(i = 0; i < MAX_CON_DAT_ARR; i++){
		if(cd[i].fd == cli_sock) break;
	}

	if(i >= MAX_CON_DAT_ARR && cli_sock != -1){
		if((*ssl = SSL_new(*ctx)) == NULL) {
			fprintf(stderr,"error creating SSL handle for new connection.\n");
			return SSL_HD_F;
		}

		if(!SSL_set_fd(*ssl,cli_sock)) {
			fprintf(stderr,"error setting socket to SSL context.\n");
			SSL_free(*ssl);
			return SSL_SET_E;		
		}		


		/*try handshake with the client*/	
		int hs_res = 0;
		if((hs_res = SSL_accept(*ssl)) <= 0) {
			int err = SSL_get_error(*ssl,hs_res);
			if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {

				int i;
				for(i = 0; i < MAX_CON_DAT_ARR;i++){
					if(cd[i].fd == 0 || cd[i].fd == -1){
						cd[i].fd = cli_sock;
						cd[i].ssl = *ssl;
						cd[i].retry_handshake = SSL_accept;
						if(add_socket_to_monitor(cli_sock,EPOLLIN | EPOLLOUT) == -1){
							/*TODO*/
						}
						break;
					}
				}
				if(i >= MAX_CON_DAT_ARR){
					fprintf(stdout,"yuo have to make MAX_CON_DAT_ARR bigger");
					return -1;
				}
				return HANDSHAKE;		
			}else {
				fprintf(stderr,"the error happens when trying handshake first time\n");
				ERR_print_errors_fp(stderr);
				SSL_free(*ssl);
				return -1;
			}
		}

		size_t bread = 0;
		int result = 0;
		if((result = SSL_peek_ex(*ssl,req->req,BASE,&bread)) == 0) {
			int err = SSL_get_error(*ssl,result);
			if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
				int i;
				for(i = 0; i < MAX_CON_DAT_ARR;i++){
					if(cd[i].fd == 0 || cd[i].fd == -1){
						cd[i].fd = cli_sock;
						cd[i].ssl = *ssl;
						cd[i].retry_read = SSL_read_ex;
						if(add_socket_to_monitor(cli_sock,EPOLLIN | EPOLLOUT) == -1){
							/*TODO*/
						}
						break;
					}
				}
				if(i >= MAX_CON_DAT_ARR){
					fprintf(stdout,"yuo have to make MAX_CON_DAT_ARR bigger");
					return -1;
				}
				return SSL_READ_E; 
			}else {
				SSL_free(*ssl);
				return -1;
			}
		}

		if(bread == BASE){
			/*
			 * TODO: read again the socket,
			 * req is bigger than BASE = (1024 bytes)*/
		}

		return 0;
	}else{
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
			if((result = SSL_peek_ex(cd[i].ssl,req->req,BASE,&bread)) == 0) {
				int err = SSL_get_error(cd[i].ssl,result);
				if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
					cd[i].retry_read = SSL_peek_ex;
					return SSL_READ_E; 
				}else if (bread == BASE){
					fprintf(stderr,"the issue is not enogh space in the buffer\n");
					ERR_print_errors_fp(stderr);
					SSL_free(cd[i].ssl);
					cd[i].fd = -1;
					cd[i].ssl = NULL;
					cd[i].retry_handshake = NULL;
					cd[i].retry_read = NULL;
					return -1;
				}else{
					fprintf(stderr,"the error happens when reading SSL after handshake\n");
					ERR_print_errors_fp(stderr);
					SSL_free(cd[i].ssl);
					cd[i].fd = -1;
					cd[i].ssl = NULL;
					cd[i].retry_handshake = NULL;
					cd[i].retry_read = NULL;
					return -1;
				}
			}

			req->size = bread;
			if(handle_request(req) == BAD_REQ){
				if(req->method == -1) return BAD_REQ;
				if(req->size < (ssize_t)BASE) return BAD_REQ;

				if(req->size == (ssize_t)BASE){
					if(set_up_request(bread,req) == -1) return -1;

					ssize_t move = req->size;
#if 0
					if((bread = read(cli_sock,req->d_req +  move,req->size)) == -1){
						if(errno == EAGAIN || errno == EWOULDBLOCK) {
							int e = errno;
							/*TODO: add fd to poll*/
							return e;
						}
						fprintf(stderr,"(%s): cannot read data from socket",prog);
						return -1;
					}
#endif
				}
			}
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
					cd[i].fd = -1;
					cd[i].ssl = NULL;
					cd[i].retry_handshake = NULL;
					cd[i].retry_read = NULL;
					return -1;
				}
			}

			req->size = bread;
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
#if 0
					if((bread = read(cli_sock,req->d_req +  move,req->size)) == -1){
						if(errno == EAGAIN || errno == EWOULDBLOCK) {
							int e = errno;
							/*TODO: add fd to poll*/
							return e;
						}
						fprintf(stderr,"(%s): cannot read data from socket",prog);
						return -1;
					}
#endif
				}
			}
			return 0;
		}

		if(cd[i].retry_write){
			int result;
			size_t bwritten = 0;
			if((result = cd[i].retry_write(cd[i].ssl,
							cd[i].buf != NULL ? cd[i].buf : cd[i].res.header_str,
							cd[i].buf != NULL ? strlen(cd[i].buf) : strlen(cd[i].res.header_str),
							&bwritten)) == 0){
				int err = SSL_get_error(cd[i].ssl,result);
				if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
					return SSL_WRITE_E;
				}else{

					ERR_print_errors_fp(stderr);
					clean_connecion_data(cds,cd[i].fd);
					return -1;
				}
			}
			clean_connecion_data(cds,cd[i].fd);
			return WRITE_OK;
		}
	}
	return 0;

}

