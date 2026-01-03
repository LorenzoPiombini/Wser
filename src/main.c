#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h> 
#include <openssl/ssl.h> 
#include "network.h" 
#include "load.h"
#include "request.h"
#include "monitor.h"
#include "default.h"
#include "handlesig.h"
#include "response.h"
#include "ssl_process.h"



char prog[] = "wser";

#define USE_FORK 1

int main(int argc, char **argv)
{	
	int secure = 0;
	if(argc > 2) goto client; 

	if(argc > 1 && *argv[1] == 's') secure = 1;

	if(check_default_setting() == -1){
		fprintf(stderr,"(%s): cannot start the server, configuration issue.",prog);
		return -1;
	} 

	/*start listening on port 80*/
	int con = -1;
	uint16_t port = secure ? 443 : 80;
	if((con = listen_port_80(&port)) == -1){
		fprintf(stderr,"(%s): cannot listen to port 80.\n",prog);
		return -1;
	}

	hdl_sock  = con;
	if(handle_sig() == -1) return -1;

	fprintf(stdout,"(%s): listening on port %d...\n",prog,port);

	if(start_monitor(con) == -1) {
		fprintf(stderr,"(%s): monitor event startup failed.\n",prog);
		stop_listening(con);
		return -1;
	}

	
	if(secure){
		if(init_SSL(&ctx) == -1){
			fprintf(stderr,"(%s): cannot start SSL to port 80.\n",prog);
			stop_monitor();
			stop_listening(con);
			return -1;
		}
	}

	int cli_sock = -1;
	SSL *ssl_cli = NULL;

	struct Response res;
	memset(&res,0,sizeof(struct Response));

	for(;;){
		if((nfds = monitor_events()) == -1) break;	
		if(nfds == EINTR) continue;
		for(int i = 0; i < nfds; i++){

			struct Request req;
			memset(&req,0,sizeof(struct Request));
			req.method = -1;
			if(events[i].data.fd == con){
				int r = 0;
				if(secure){
					if((r = wait_for_connections_SSL(con,&cli_sock)) == -1) break;
					/*start SSL handle processs*/
					pid_t ssl_handle_child = fork();
					if(ssl_handle_child == -1){

					}else if (ssl_handle_child == 0){
						/*child*/
						SSL_work_process(cds,cli_sock,&req,&ssl_cli,&ctx);
						SSL_CTX_free(ctx);
						clean_connecion_data(cds);
						exit(0);
					}

					/*parent*/
					continue;
				}else{
					if((r = wait_for_connections(con,&cli_sock,&req)) == -1) break;
				}

				if(r == EAGAIN || 
						r == EWOULDBLOCK 	|| 
						r == HANDSHAKE 		|| 
						r == SSL_READ_E) continue;
					
#if USE_FORK
				pid_t child = fork();
				if(child == -1){

				}
#else

				pid_t child = 0;
#endif
	
				if(child == 0){
					/* send response */
					if(r == BAD_REQ) {
						/*send a bed request response*/
						if(generate_response(&res,400,NULL,&req) == -1) break;

						int w = 0;
						if(secure){
							if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) break;
						}else{
							if(( w = write_cli_sock(cli_sock,&res)) == -1) break;
						}
						if(w == EAGAIN || w == EWOULDBLOCK || w == SSL_WRITE_E){
#if USE_FORK
							uint8_t ws = 0;
							if(secure){
								while((w = write_cli_SSL(cli_sock,&res,cds)) == -1){
									if(w == EAGAIN || w == EWOULDBLOCK || w == SSL_WRITE_E) continue;

									ws = 1;
									break;
								}

							}else{
								while((w = write_cli_sock(cli_sock,&res) != -1)){
									if(w == EAGAIN || w == EWOULDBLOCK) continue;

									ws = 1;
									break;
								}

							}
							if(ws){
								//clear_response(&res);
								stop_listening(cli_sock);
								if(secure) SSL_CTX_free(ctx);
								clean_connecion_data(cds);
								exit(0);
							}
							//clear_response(&res);
							stop_listening(cli_sock);
							if(secure) SSL_CTX_free(ctx);
							clean_connecion_data(cds);
							exit(1);

#else
							continue;
#endif
						}

#if USE_FORK
						clear_request(&req);
						clear_response(&res);
						stop_listening(cli_sock);
						if(secure) SSL_CTX_free(ctx);
						clean_connecion_data(cds);
						exit(0);
#else
						remove_socket_from_monitor(cli_sock);
						clear_request(&req);
						clear_response(&res);
						clean_connecion_data(cds);
						continue;
#endif
					}

					struct Content cont;
					memset(&cont,0,sizeof(struct Content));
					switch(req.method){
						case GET:
							/* Load content */	
							if(load_resource(req.resource,&cont) == -1){
								/*send not found response*/
								if(generate_response(&res,404,NULL,&req) == -1) break;

								int w = 0;
								if(secure){
									if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) break;
								}else{
									if(( w = write_cli_sock(cli_sock,&res)) == -1) break;
								}
								if(w == EAGAIN || w == EWOULDBLOCK || w == SSL_WRITE_E){
#if USE_FORK
									uint8_t ws = 0;
									if(secure){
										while((w = write_cli_SSL(cli_sock,&res,cds)) == -1){
											if(w == EAGAIN || w == EWOULDBLOCK || w == SSL_WRITE_E) continue;

											ws = 1;
											break;
										}

									}else{
										while((w = write_cli_sock(cli_sock,&res) != -1)){
											if(w == EAGAIN || w == EWOULDBLOCK) continue;

											ws = 1;
											break;
										}

									}

									if(ws){
										stop_listening(cli_sock);
										clear_request(&req);
										clear_content(&cont);
										if(secure) SSL_CTX_free(ctx);
										clean_connecion_data(cds);
										exit(0);
									}

									clear_request(&req);
									clear_content(&cont);
									stop_listening(cli_sock);
									if(secure) SSL_CTX_free(ctx);
									clean_connecion_data(cds);
									exit(1);
								}

									clear_request(&req);
									clear_content(&cont);
									stop_listening(cli_sock);
									if(secure) SSL_CTX_free(ctx);
									clean_connecion_data(cds);
									exit(1);
#else
									clear_request(&req);
									clear_content(&cont);
									remove_socket_from_monitor(cli_sock);
									clean_connecion_data(cds);
									continue;
#endif
#if USE_FORK
								stop_listening(cli_sock);
								clear_request(&req);
								clear_content(&cont);
								if(secure) SSL_CTX_free(ctx);
								clean_connecion_data(cds);
								exit(0);

#else 
								clear_request(&req);
								clear_content(&cont);
								remove_socket_from_monitor(cli_sock);
								clean_connecion_data(cds);
								continue;
#endif
							}

							/*send 200 response*/
							if(generate_response(&res,OK,&cont,&req) == -1) {
								clear_content(&cont);
#if USE_FORK
								SSL_CTX_free(ctx);
								if(secure) SSL_CTX_free(ctx);
								clean_connecion_data(cds);
								exit(1);
#endif
							}

							clear_content(&cont);
							int w = 0;
							if(secure){
								if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) break;
							}else{
								if(( w = write_cli_sock(cli_sock,&res)) == -1) break;
							}
							if(w == EAGAIN || w == EWOULDBLOCK || w == SSL_WRITE_E){
#if USE_FORK
								uint8_t ws = 0;
								if(secure){
									while((w = write_cli_SSL(cli_sock,&res,cds)) == -1){
										if(w == EAGAIN || w == EWOULDBLOCK || w == SSL_WRITE_E) continue;

										ws = 1;
										break;
									}

								}else{
									while((w = write_cli_sock(cli_sock,&res) != -1)){
										if(w == EAGAIN || w == EWOULDBLOCK) continue;

										ws = 1;
										break;
									}

								}
								if(ws){
									stop_listening(cli_sock);
									clear_request(&req);
									clear_response(&res);
									if(secure) SSL_CTX_free(ctx);
									clean_connecion_data(cds);
									exit(0);
								}
								clear_request(&req);
								clear_response(&res);
								stop_listening(cli_sock);
								if(secure) SSL_CTX_free(ctx);
								clean_connecion_data(cds);
								exit(1);
#else
								clear_request(&req);
								remove_socket_from_monitor(cli_sock);
								clean_connecion_data(cds);
								continue;
#endif

							}

							if(req.d_req)
								fprintf(stdout,"%s\n",req.d_req);
							else
								fprintf(stdout,"%s\n",req.req);

							clear_request(&req);
							clear_response(&res);
#if USE_FORK 

							stop_listening(cli_sock);
							if(secure) SSL_CTX_free(ctx);
							clean_connecion_data(cds);
							exit(0);
#else
							remove_socket_from_monitor(cli_sock);
							clean_connecion_data(cds);
							break;
#endif
						case OPTIONS:
							{
								size_t s = strlen(req.origin);
								if(s != strlen(ORIGIN_DEF)) goto bad_request;

								if(strncmp(req.origin,ORIGIN_DEF,strlen(ORIGIN_DEF)) != 0){

bad_request:
									/*send a bed request response*/
									if(generate_response(&res,400,NULL,&req) == -1) break;

									int w = 0;
									if(secure){
										if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) break;
									}else{
										if(( w = write_cli_sock(cli_sock,&res)) == -1) break;
									}
									if(w == EAGAIN || w == EWOULDBLOCK || w == SSL_WRITE_E){
#if USE_FORK
										uint8_t ws = 0;
										if(secure){
											while((w = write_cli_SSL(cli_sock,&res,cds)) == -1){
												if(w == EAGAIN || w == EWOULDBLOCK || w == SSL_WRITE_E) continue;

												ws = 1;
												break;
											}

										}else{
											while((w = write_cli_sock(cli_sock,&res) != -1)){
												if(w == EAGAIN || w == EWOULDBLOCK) continue;

												ws = 1;
												break;
											}

										}
										if(ws){
											stop_listening(cli_sock);
											clear_request(&req);
											if(secure) SSL_CTX_free(ctx);
											clean_connecion_data(cds);
											exit(0);
										}

										stop_listening(cli_sock);
										clear_request(&req);
										if(secure) SSL_CTX_free(ctx);
										clean_connecion_data(cds);
										exit(1);
#else
										remove_socket_from_monitor(cli_sock);
										clear_request(&req);
										continue;
#endif
								}


								clear_request(&req);
								clear_response(&res);
#if USE_FORK
								stop_listening(cli_sock);
								if(secure) SSL_CTX_free(ctx);
								clean_connecion_data(cds);
								exit(0);
#else 
								remove_socket_from_monitor(cli_sock);
								clean_connecion_data(cds);
								continue;
#endif

							}

							/*send a response to the options request*/
							if(generate_response(&res,200,NULL,&req) == -1) break;

							clear_request(&req);
							int w = 0;
							if(secure){
								if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) break;
							}else{
								if(( w = write_cli_sock(cli_sock,&res)) == -1) break;
							}
							if(w == EAGAIN || w == EWOULDBLOCK || w == SSL_WRITE_E){
#if USE_FORK
								uint8_t ws = 0;
								if(secure){
									while((w = write_cli_SSL(cli_sock,&res,cds)) == -1){
										if(w == EAGAIN || w == EWOULDBLOCK || w == SSL_WRITE_E) continue;

										ws = 1;
										break;
									}

									}else{
										while((w = write_cli_sock(cli_sock,&res) != -1)){
											if(w == EAGAIN || w == EWOULDBLOCK) continue;

											ws = 1;
											break;
										}

									}
								if(ws){
									stop_listening(cli_sock);
									clear_response(&res);
									if(secure) SSL_CTX_free(ctx);
									clean_connecion_data(cds);
									exit(0);
								}
#else
								remove_socket_from_monitor(cli_sock);
								clean_connecion_data(cds);
								continue;
#endif
							}

							clear_response(&res);
							clean_connecion_data(cds);

#if USE_FORK
							stop_listening(cli_sock);
							if(secure) SSL_CTX_free(ctx);
							clean_connecion_data(cds);
							exit(0);
#else
							remove_socket_from_monitor(cli_sock);
							clean_connecion_data(cds);
							continue;
#endif
						}
					case DELETE:
					case POST:
					case PUT:
					default:
					{
							if(generate_response(&res,400,NULL,&req) == -1) break;

							clear_request(&req);
							int w = 0;
							if(secure){
								if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) break;
							}else{
								if(( w = write_cli_sock(cli_sock,&res)) == -1) break;
							}
							if(w == EAGAIN || w == EWOULDBLOCK || w == SSL_WRITE_E){
#if USE_FORK
								uint8_t ws = 0;
								if(secure){
									while((w = write_cli_SSL(cli_sock,&res,cds)) == -1){
										if(w == EAGAIN || w == EWOULDBLOCK || w == SSL_WRITE_E) continue;

										ws = 1;
										break;
									}

								}else{
									while((w = write_cli_sock(cli_sock,&res) != -1)){
										if(w == EAGAIN || w == EWOULDBLOCK) continue;

										ws = 1;
										break;
									}

								}

								if(ws){
									stop_listening(cli_sock);
									clear_request(&req);
									if(secure) SSL_CTX_free(ctx);
									clean_connecion_data(cds);
									exit(0);
								}
								stop_listening(cli_sock);
								clear_request(&req);
								if(secure) SSL_CTX_free(ctx);
								clean_connecion_data(cds);
								exit(1);
#else
								remove_socket_from_monitor(cli_sock);
								clear_request(&req);
								continue;
#endif
							}

							clear_response(&res);

#if USE_FORK
							stop_listening(cli_sock);
							if(secure) SSL_CTX_free(ctx);
							clean_connecion_data(cds);
							exit(0);
#else 
							remove_socket_from_monitor(cli_sock);
							break;
#endif
					}
					}
				}
				/* parent */
				remove_socket_from_monitor(cli_sock);
				stop_listening(cli_sock);
				clear_request(&req);
				clean_connecion_data(cds);
				continue;

			}else{ /*SECOND BRANCH*/

				int r = 0;
				printf("sock nr %d\n",events[i].data.fd);
				if(events[i].events == EPOLLIN) {

					if(secure){
						if((r = read_cli_sock_SSL(events[i].data.fd,&req,cds)) == -1) break;
					}else{
						if((r = read_cli_sock(events[i].data.fd,&req)) == -1) break;
					}

					if(r == EAGAIN || r == EWOULDBLOCK || r == HANDSHAKE || 
							r == SSL_READ_E || r == NO_CON_DATA) continue;

#if USE_FORK 
					pid_t child = fork();
					if(child == -1){
						continue;
					}
#else
					pid_t child =0;

#endif
					if(child == 0){
						printf("in the child!\n");
						printf("%s\n",req.req);
						if(r == BAD_REQ) {
							/*send a bed request response*/
#if USE_FORK
							if(secure) SSL_CTX_free(ctx);
							clean_connecion_data(cds);
							exit(1);
#else
							continue;
#endif
						}

						struct Content cont;
						memset(&cont,0,sizeof(struct Content));
						switch(req.method){
						case GET:
							/* Load content */	
							if(load_resource(req.resource,&cont) == -1){
								printf("sending 404.\n");
								/*send not found response*/

								if(generate_response(&res,404,NULL,&req) == -1) break;


								clear_content(&cont);
								clear_request(&req);
								printf("header is \n%s\n",res.header_str);
								int w = 0;
								if(secure){
									if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) break;
								}else{
									if(( w = write_cli_sock(cli_sock,&res)) == -1) break;
								}
								if(w == EAGAIN || w == EWOULDBLOCK || w == SSL_WRITE_E){
#if USE_FORK
									uint8_t ws = 0;
									if(secure){
										while((w = write_cli_SSL(cli_sock,&res,cds)) == -1){
											if(w == EAGAIN || w == EWOULDBLOCK || w == SSL_WRITE_E) continue;

											ws = 1;
											break;
										}

									}else{
										while((w = write_cli_sock(cli_sock,&res) != -1)){
											if(w == EAGAIN || w == EWOULDBLOCK) continue;

											ws = 1;
											break;
										}

									}
									clear_request(&req);
									if(ws){
										if(secure) SSL_CTX_free(ctx);
										clean_connecion_data(cds);
										exit(0);
									}
									if(secure) SSL_CTX_free(ctx);
									clean_connecion_data(cds);
									exit(1);
#else
									clear_request(&req);
									continue;	
#endif
								}
							}
							/* send response */
							if(generate_response(&res,OK,&cont,&req) == -1){
								/*server error 500*/
#if USE_FORK 
								if(secure) SSL_CTX_free(ctx);
								clean_connecion_data(cds);
								exit(0);
#else 
								continue;
#endif
							}

							clear_content(&cont);
							printf("2nd branch: response header is\n%s\n",res.header_str);
							printf("writing to client.\n");
							int w = 0;
							if(secure){
								if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) break;
							}else{
								if(( w = write_cli_sock(cli_sock,&res)) == -1) break;
							}
							if(w == EAGAIN || w == EWOULDBLOCK || w == SSL_WRITE_E){
#if USE_FORK
								uint8_t ws = 0;
								if(secure){
									while((w = write_cli_SSL(cli_sock,&res,cds)) == -1){
										if(w == EAGAIN || w == EWOULDBLOCK || w == SSL_WRITE_E) continue;

										ws = 1;
										break;
									}

								}else{
									while((w = write_cli_sock(cli_sock,&res) != -1)){
										if(w == EAGAIN || w == EWOULDBLOCK) continue;

										ws = 1;
										break;
									}

								}

								if(ws){
									stop_listening(events[i].data.fd);
									clear_response(&res);		
									if(secure) SSL_CTX_free(ctx);
									clean_connecion_data(cds);
									exit(0);
								}

								stop_listening(events[i].data.fd);
								clear_response(&res);		
								if(secure) SSL_CTX_free(ctx);
								clean_connecion_data(cds);
								exit(1);
#else 
								continue;
#endif
							}

							if(req.d_req)
								fprintf(stdout,"%s\n",req.d_req);
							else
								fprintf(stdout,"%s\n",req.req);


							clear_request(&req);
							clear_response(&res);		

#if USE_FORK
							stop_listening(events[i].data.fd);
							if(secure) SSL_CTX_free(ctx);
							exit(0);
#else
							remove_socket_from_monitor(events[i].data.fd);
							continue;
#endif
						default:
							/*send a bad request response*/
#if USE_FORK
							if(secure) SSL_CTX_free(ctx);
							clean_connecion_data(cds);
							exit(0);
#else
							continue;
#endif
						}
					}
					/*parent*/
					remove_socket_from_monitor(events[i].data.fd);
					clean_connecion_data(cds);
					continue;
				}else if(events[i].events == EPOLLOUT) {
					int w = 0;
					if(secure){
						if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) break;
					}else{
						if(( w = write_cli_sock(cli_sock,&res)) == -1) break;
					}
					if(w == EAGAIN || w == EWOULDBLOCK || w == SSL_WRITE_E){
#if USE_FORK
						uint8_t ws = 0;
						if(secure){
							while((w = write_cli_SSL(cli_sock,&res,cds)) == -1){
								if(w == EAGAIN || w == EWOULDBLOCK || w == SSL_WRITE_E) continue;

								ws = 1;
								break;
							}

						}else{
							while((w = write_cli_sock(cli_sock,&res) != -1)){
								if(w == EAGAIN || w == EWOULDBLOCK) continue;

								ws = 1;
								break;
							}

						}

						if(ws){
							clear_response(&res);
							stop_listening(events[i].data.fd);
							if(secure) SSL_CTX_free(ctx);
							clean_connecion_data(cds);
							exit(0);
						}

						stop_listening(events[i].data.fd);
						clear_request(&req);
						if(secure) SSL_CTX_free(ctx);
						clean_connecion_data(cds);
						exit(1);
#else
						clear_request(&req);
						continue;
#endif
					}

					clear_response(&res);
#if USE_FORK
					stop_listening(events[i].data.fd);
					if(secure) SSL_CTX_free(ctx);
					clean_connecion_data(cds);
					exit(0);
#else
					break;
#endif
				}
			}
		}
	}

	stop_monitor();
	stop_listening(con);
	if(secure) SSL_CTX_free(ctx);
	clean_connecion_data(cds);
	return 0;

client:

	int option = 0;
	while((option = getopt(argc,argv,"g:")) != -1){
		switch(option){
			case 'g':
				get(optarg);
				break;
			default:
				break;
		}
	}

	return 0;
}
