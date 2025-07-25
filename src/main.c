#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h> 
#include "network.h" 
#include "load.h"
#include "request.h"
#include "monitor.h"
#include "default.h"
#include "handlesig.h"
#include "response.h"


char prog[] = "wser";

int main(int argc, char **argv)
{	
	if(argc > 1) goto client; 
	if(check_default_setting() == -1){
		fprintf(stderr,"(%s): cannot start the server, configuration issue.",prog);
		return -1;
	} 

	/*start listening on port 80*/
	int con = -1;
	uint16_t port = 80;
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

	int cli_sock = -1;

	struct Response res = {0};
	for(;;){
		if((nfds = monitor_events()) == -1) break;	
		if(nfds == EINTR) continue;
		for(int i = 0; i < nfds; i++){

			struct Request req = {0};
			req.method = -1;
			if(events[i].data.fd == con){
				int r = 0;
				if((r = wait_for_connections(con,&cli_sock,&req)) == -1) break;

				if(r == EAGAIN || r == EWOULDBLOCK) continue;
					
				/* send response */
				if(r == BAD_REQ) {
					/*send a bed request response*/
					if(generate_response(&res,400,NULL,&req) == -1) break;
					
					int w = 0;
					if(( w = write_cli_sock(events[i].data.fd,&res)) == -1) break;
					if(w == EAGAIN || w == EWOULDBLOCK) {
						clear_request(&req);
						continue;
					}

					clear_request(&req);
					clear_response(&res);

					if(remove_socket_from_monitor(events[i].data.fd) == -1) break;
					continue;
				}
				
				struct Content cont= {0};
				switch(req.method){
				case GET:
					/* Load content */	
					if(load_resource(req.resource,&cont) == -1){
						/*send not found response*/
						if(generate_response(&res,404,NULL,&req) == -1) break;

						int w = 0;
						if(( w = write_cli_sock(cli_sock,&res)) == -1) break;
						if(w == EAGAIN || w == EWOULDBLOCK) {
							clear_request(&req);
							clear_content(&cont);
							continue;
						}

						stop_listening(cli_sock);

						clear_request(&req);
						clear_response(&res);
						continue;
					}
					break;
				case OPTIONS:
				{
					size_t s = strlen(req.origin);
					if(s != strlen(ORIGIN_DEF)) goto bad_request;

					if(strncmp(req.origin,ORIGIN_DEF,strlen(ORIGIN_DEF)) != 0){
						
						bad_request:
						/*send a bed request response*/
						if(generate_response(&res,400,NULL,&req) == -1) break;

						int w = 0;
						if(( w = write_cli_sock(events[i].data.fd,&res)) == -1) break;
						if(w == EAGAIN || w == EWOULDBLOCK) {
							clear_request(&req);
							continue;
						}

						clear_request(&req);
						clear_response(&res);

						if(remove_socket_from_monitor(events[i].data.fd) == -1) break;
						continue;
					}
					/*send a response to the options request*/
					if(generate_response(&res,200,NULL,&req) == -1) break;

					int w = 0;
					if(( w = write_cli_sock(events[i].data.fd,&res)) == -1) break;
					if(w == EAGAIN || w == EWOULDBLOCK) {
						clear_request(&req);
						continue;
					}

					clear_request(&req);
					clear_response(&res);

					if(remove_socket_from_monitor(events[i].data.fd) == -1) break;
					continue;
				}
				case DELETE:
					if(generate_response(&res,400,NULL,&req) == -1) break;

					int w = 0;
					if(( w = write_cli_sock(events[i].data.fd,&res)) == -1) break;
					if(w == EAGAIN || w == EWOULDBLOCK) {
						clear_request(&req);
						continue;
					}

					clear_request(&req);
					clear_response(&res);

					if(remove_socket_from_monitor(events[i].data.fd) == -1) break;
					continue;
				case PUT:
				case POST:
				default:
					/*send a bed request response*/
					break;
				}


				/* send response*/
				if(generate_response(&res,OK,&cont,&req) == -1) {

				}

				clear_content(&cont);
				int w = 0;
				if(( w = write_cli_sock(cli_sock,&res)) == -1) break;

				if(w == EAGAIN || w == EWOULDBLOCK) {
					clear_request(&req);
					continue;
				}


				if(req.d_req)
					fprintf(stdout,"%s\n",req.d_req);
				else
					fprintf(stdout,"%s\n",req.req);

				stop_listening(cli_sock);
				clear_request(&req);
				clear_response(&res);
			}else{
				
				int r = 0;
				printf("sock nr %d\n",events[i].data.fd);
				if(events[i].events == EPOLLIN) {

					if((r = read_cli_sock(events[i].data.fd,&req)) == -1) break;
					if(r == EAGAIN || r == EWOULDBLOCK) continue;

					if(r == BAD_REQ) {
						/*send a bed request response*/
					}

					struct Content cont= {0};
					switch(req.method){
					case GET:
						/* Load content */	
						if(load_resource(req.resource,&cont) == -1){
							printf("sending 404.\n");
							/*send not found response*/

							if(generate_response(&res,404,NULL,&req) == -1) break;

							
							printf("header is \n%s\n",res.header_str);
							int w = 0;
							if(( w = write_cli_sock(events[i].data.fd,&res)) == -1) break;
							if(w == EAGAIN || w == EWOULDBLOCK) {
								clear_request(&req);
								clear_content(&cont);
								continue;
							}

							clear_request(&req);
							clear_response(&res);
							
							if(remove_socket_from_monitor(events[i].data.fd) == -1) break;
							continue;
						}
						break;
					default:
						/*send a bed request response*/
						break;
					}

					/* send response */
					if(generate_response(&res,OK,&cont,&req) == -1){


					}

					printf("response header is\n%s\n",res.header_str);
					clear_content(&cont);
					int w = 0;
					printf("writing to client.\n");
					if(( w = write_cli_sock(events[i].data.fd,&res)) == -1) break;


					printf("after writing to client.\n");
					if(w == EAGAIN || w == EWOULDBLOCK) continue;

					if(remove_socket_from_monitor(events[i].data.fd) == -1) break;

					if(req.d_req)
						fprintf(stdout,"%s\n",req.d_req);
					else
						fprintf(stdout,"%s\n",req.req);

					clear_response(&res);
					clear_request(&req);
				}else if(events[i].events == EPOLLOUT) {
					int w = 0;
					if(( w = write_cli_sock(events[i].data.fd,&res)) == -1) break;

					if(w == EAGAIN || w == EWOULDBLOCK) {
						clear_request(&req);
						continue;
					}
					
					if(remove_socket_from_monitor(events[i].data.fd) == -1) break;
					clear_request(&req);
					clear_response(&res);
				}
			}
		}
	}

	stop_listening(con);
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
