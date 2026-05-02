#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include "load.h"
#include "handlesig.h"
#include "ssl_process.h"
#include "network.h"
#include "request.h"
#include "response.h"
#include "monitor.h"

struct p_info{
	pid_t p;
	time_t t;
	int exited;
};

struct p_info proc_list[100] = {0};

#define TIME_OUT 300 /*5 minutes*/
#define EIGHTkib_limit 8192

static char prog[] = "wser";

#if OWN_DB

#include "work_process.h" /* database handler*/
#include "end_points.h"
#include "lua_start.h"
#include "ctype.h"

static int process_request(struct Request *req, int cli_sock, int work_proc_data_sock);
static int load_resource_db(struct Request *req, struct Content *cont,int data_sock);
static char *convert_json(char* body);
#else
static int process_request(struct Request *req, int cli_sock);
#endif

static int check_URL_encoding(char *p);
static int handle_ssl_steps(struct Connection_data *cd, 
							int cli_sock,
							struct Request *req,
							SSL **ssl,
							SSL_CTX **ctx);


int SSL_work_process(int data_sock)
{

#ifdef OWN_DB
	int work_proc_data_sock = -1;

	pid_t work_proc_pid = fork();

	if(work_proc_pid == -1){
		/*Parent*/
		fprintf(stderr,"(%s): architecture cannot be implemented.\n",prog);
		return -1;
	}

	if(work_proc_pid == 0){
		/*CHILD*/
		/* start DB handle process */	
		if((work_proc_data_sock = listen_UNIX_socket(-1,INT_PROC_SOCK_DB)) == -1) {
			fprintf(stderr,"cannot start Data base.\n");
			kill(getppid(),SIGINT);
		 	exit(-1);
		}

		
		db_sock = work_proc_data_sock;
		if(handle_sig_db_process() == -1)
			exit(1);

		work_process(work_proc_data_sock);
		return -1;
	}
	
	/*parent*/
	db_proc = work_proc_pid;

#endif /* OWN_DB -make flag*/

	if(start_monitor(data_sock) == -1){
		fprintf(stderr,"(%s): cannot start SSL context.\n",prog);
		kill(getppid(),SIGINT);
		exit(-1);
	}

	if(init_SSL(&ctx) == -1){
		fprintf(stderr,"(%s): cannot start SSL context.\n",prog);
		stop_monitor();
		kill(getppid(),SIGINT);
		exit(-1);
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
		
		if((nfds = monitor_events()) == -1) goto teardown;
		if(nfds == EINTR){
			continue; /*change with goto teardwn in prod*/
		}

		int i;
		for(i = 0; i < nfds; i++){
			/* Receive ancillary data; real data is ignored */
			int sock = -1;
			if(events[i].data.fd == data_sock){
				if((sock = accept(data_sock,NULL,NULL)) == -1)
					continue;

				errno = 0;
				if(recvmsg(sock, &msgh, 0) == -1){
					if(add_socket_to_monitor(sock, EPOLLIN) == -1) 
						continue;

					if(errno == EAGAIN || errno == EWOULDBLOCK)
						continue;

					stop_listening(sock);
					continue;
				}
			}else{
				if(recvmsg(sock, &msgh, 0) == -1){
					if(errno == EAGAIN || errno == EWOULDBLOCK)
						continue;

					stop_listening(sock);
					continue;
				}
			}

			cmsgp = CMSG_FIRSTHDR(&msgh);
			if (cmsgp == NULL
					|| cmsgp->cmsg_len != CMSG_LEN(sizeof(int))
					|| cmsgp->cmsg_level != SOL_SOCKET
					|| cmsgp->cmsg_type != SCM_RIGHTS) continue;


			memcpy(&cli_sock, CMSG_DATA(cmsgp), sizeof(int));

			pid_t child = fork();
			if(child == 0){
				/*clear ssl que error*/
				ERR_clear_error(); 
				/*free resources that the child does not need*/
				stop_listening(sock);
				stop_listening(data_sock);
#if OWN_DB
				int db_sock = connect_UNIX_socket(-1,INT_PROC_SOCK_DB);
#endif

				if(start_monitor(cli_sock) == -1) {
					fprintf(stderr,"(%s): monitor event startup failed.\n",prog);
					goto teardown;
				}

				struct Request req = {0};
				int r = handle_ssl_steps(cds,cli_sock,&req,&ssl_cli,&ctx);

				if(r == -1)
					goto teardown;
			
				if(r == 0 || r == 2){
#ifdef OWN_DB
					if(process_request(&req,cli_sock, db_sock) == 1){
#else 
					if(process_request(&req,cli_sock) == 1){
#endif
						clear_request(&req);
						goto loop;
					}
					clear_request(&req);
					goto teardown;
				}

loop:
				int nfds =-1,i;
				for(;;){
					if((nfds = monitor_events()) == -1) goto teardown;
					if(nfds == EINTR){
						continue; /*change with goto teardwn in prod*/
					}
	
					for(i = 0; i < nfds; i++){
						int r = handle_ssl_steps(cds,events[i].data.fd,&req,&ssl_cli,&ctx);

						if(r == -1){
							/*shutdown*/
							goto teardown;
						}

						switch(r){
						case SSL_READ_E:
						case SSL_WRITE_E:
						case HANDSHAKE:
						{		
							r = handle_ssl_steps(cds,events[i].data.fd,&req,&ssl_cli,&ctx);
							if(r == 0 || r == 2){
#ifdef OWN_DB
								if(process_request(&req,events[i].data.fd,db_sock)== 1){
#else 
								if(process_request(&req,events[i].data.fd) == 1){
#endif
									clear_request(&req);
									continue;
								}
								clear_request(&req);
								goto teardown;
							}
							break;
						}
						case 2:
						case 0:
						{
							/*process request*/
#ifdef OWN_DB
							if(process_request(&req,events[i].data.fd,db_sock) == 1){
#else 
							if(process_request(&req,events[i].data.fd) == 1){
#endif
								clear_request(&req);
								continue;
							}
							goto teardown;
						}
						case CLEAN_TEARDOWN:
							goto teardown;
						case SSL_CLOSE:
						case SSL_SET_E:
						case SSL_HD_F:
						default:
						remove_socket_from_monitor(cli_sock);
						stop_monitor();
						clear_request(&req);
						clean_connecion_data(cds,events[i].data.fd);
						SSL_CTX_free(ctx);
						close(db_sock);
						ctx = NULL;
						exit(1);
						}
					}
				}
teardown:
			remove_socket_from_monitor(cli_sock);
			clean_connecion_data(cds,events[i].data.fd);
			SSL_CTX_free(ctx);
			ctx = NULL;
			stop_monitor();
			close(db_sock);
			exit(0);
		}else if(child == -1){
			/*PARENT*/
			stop_listening(cli_sock);
			stop_listening(sock);
			/*wait on the children*/
			continue;
		}else{
			/*PARENT*/
			stop_listening(cli_sock);
			stop_listening(sock);

			int i;
			for(i = 0; i < 100;i++){
				if(proc_list[i].p == 0 || proc_list[i].p == -1){
					proc_list[i].p = child;
					proc_list[i].t = time(NULL);
					break;
				}
			}
						
			assert(i < 100);
			/*wait on the children*/
			for(i = 0; i < 100;i++){
				if(proc_list[i].p == 0 || proc_list[i].p == -1)
					continue;

				errno = 0;
				if(kill(proc_list[i].p,0) == -1 && errno == ESRCH){
					proc_list[i].p = -1;
					proc_list[i].t = 0;
					continue;
				}

				if(proc_list[i].t > 0 && ((time(NULL) - proc_list[i].t ) > (time_t) TIME_OUT)){
					if(kill(proc_list[i].p,SIGKILL) == 0){
						proc_list[i].p = -1;
						proc_list[i].t = 0;
						continue;
					}
				}
			}
		}
		}
	}
	SSL_CTX_free(ctx);
	ctx = NULL;
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
			*ssl = NULL;
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
						if(modify_monitor_event(cli_sock,EPOLLIN | EPOLLOUT) == -1){
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
				int i;
				for(i = 0; i < MAX_CON_DAT_ARR;i++){
					if(cd[i].fd == 0 || cd[i].fd == -1){
						cd[i].fd = cli_sock;
						cd[i].ssl = *ssl;
						cd[i].retry_handshake = NULL;
						cd[i].retry_read = NULL;
						cd[i].retry_write = NULL;
						cd[i].close_notify = SSL_shutdown;
						if(modify_monitor_event(cli_sock,EPOLLIN | EPOLLOUT) == -1){
							/*TODO*/
						}
						break;
					}
				}
				return -1;
			}
		}

		size_t bread = 0;
		int result = 0;
		ssize_t byte_to_read = BASE;
		char buf[EIGHTkib_limit] = {0};
		char *pbuf = &buf[0];

		while((result = SSL_peek_ex(*ssl,pbuf,byte_to_read,&bread)) == 0 || bread == BASE) {
			int err = SSL_get_error(*ssl,result);
			if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
				int i;
				for(i = 0; i < MAX_CON_DAT_ARR;i++){
					if(cd[i].fd == 0 || cd[i].fd == -1){
						cd[i].fd = cli_sock;
						cd[i].ssl = *ssl;
						cd[i].retry_read = SSL_peek_ex;
						if(modify_monitor_event(cli_sock,EPOLLIN | EPOLLOUT) == -1){
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
			}else if(err == SSL_ERROR_NONE){
				if(byte_to_read < EIGHTkib_limit){
					memset(buf,0,byte_to_read);
					byte_to_read += 1024;
					continue;
				}

				/*TODO: here we need to allocate memory*/		
			}else {
				int i;
				for(i = 0; i < MAX_CON_DAT_ARR;i++){
					if(cd[i].fd == 0 || cd[i].fd == -1){
						cd[i].fd = cli_sock;
						cd[i].ssl = *ssl;
						cd[i].retry_handshake = NULL;
						cd[i].retry_read = NULL;
						cd[i].retry_write = NULL;
						cd[i].close_notify = SSL_shutdown;
						if(modify_monitor_event(cli_sock,EPOLLIN | EPOLLOUT) == -1){
							/*TODO*/
						}
						break;
					}
				}
				return SSL_CLOSE;
			}
		}

		for(i = 0; i < MAX_CON_DAT_ARR;i++){
			if(cd[i].fd == 0 || cd[i].fd == -1){
				cd[i].fd = cli_sock;
				cd[i].ssl = *ssl;
				cd[i].retry_read = SSL_peek_ex;
				if(modify_monitor_event(cli_sock,EPOLLIN | EPOLLOUT) == -1){
					/*TODO*/
				}
				break;
			}
		}
		/* copy the buffer to the request struct*/
		req->size = bread;
		if(bread >= BASE){
			/*allocate*/
			if(set_up_request(bread,req) == -1) return -1;
		}else{
			strncpy(req->req,pbuf,bread);
		}

		if(handle_request(req) == BAD_REQ){
			if(req->method == -1) return BAD_REQ;
			if(req->size < (ssize_t)BASE) return BAD_REQ;
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
					int i;
					for(i = 0; i < MAX_CON_DAT_ARR;i++){
						if(cd[i].fd == 0 || cd[i].fd == -1){
							cd[i].fd = cli_sock;
							cd[i].ssl = *ssl;
							cd[i].retry_handshake = NULL;
							cd[i].retry_read = NULL;
							cd[i].retry_write = NULL;
							cd[i].close_notify = SSL_shutdown;
							if(modify_monitor_event(cli_sock,EPOLLIN | EPOLLOUT) == -1){
								/*TODO*/
							}
							break;
						}
					}
					return SSL_CLOSE;
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
					return -1;
				}else{
					fprintf(stderr,"the error happens when reading SSL after handshake\n");
					ERR_print_errors_fp(stderr);
					int i;
					for(i = 0; i < MAX_CON_DAT_ARR;i++){
						if(cd[i].fd == 0 || cd[i].fd == -1){
							cd[i].fd = cli_sock;
							cd[i].ssl = *ssl;
							cd[i].retry_handshake = NULL;
							cd[i].retry_read = NULL;
							cd[i].retry_write = NULL;
							cd[i].close_notify = SSL_shutdown;
							if(modify_monitor_event(cli_sock,EPOLLIN | EPOLLOUT) == -1){
								/*TODO*/
							}
							break;
						}
					}
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
					return -1;
					/*
					fprintf(stderr,"the error happens when retrying read\n");
					ERR_print_errors_fp(stderr);
					return -1;
					*/
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
			cd[i].retry_read = NULL;
			return 2;
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
					int i;
					for(i = 0; i < MAX_CON_DAT_ARR;i++){
						if(cd[i].fd == 0 || cd[i].fd == -1){
							cd[i].fd = cli_sock;
							cd[i].ssl = *ssl;
							cd[i].retry_handshake = NULL;
							cd[i].retry_read = NULL;
							cd[i].retry_write = NULL;
							cd[i].close_notify = SSL_shutdown;
							if(modify_monitor_event(cli_sock,EPOLLIN | EPOLLOUT) == -1){
								/*TODO*/
							}
							break;
						}
					}
					return SSL_CLOSE;
				}
			}
			return WRITE_OK;
		}
		
		if(cd[i].close_notify){
			if(SSL_shutdown(cd[i].ssl) != 1)
				return SSL_CLOSE;
			else 
				return CLEAN_TEARDOWN;
		}
	}
	return 0;

}

#if OWN_DB
static int process_request(struct Request *req, int cli_sock, int work_proc_data_sock)
#else
static int process_request(struct Request *req, int cli_sock)
#endif
{
	switch(req->method){
	case GET:
	{
		struct Response res = {0};
		struct Content cont = {0};
		/* Load content */	
		/*check if the req->resource is an end point for the db or a website page*/
#if OWN_DB
		if(!strstr(req->resource,".html")
			&& !strstr(req->resource,".css")
			&& !strstr(req->resource,".js")){
		if(load_resource_db(req,&cont,work_proc_data_sock) == -1){
#endif
			if(load_resource(req->resource,&cont) == -1){
				/*send not found response*/
				if(generate_response(&res,404,&cont,req) == -1) break;

				int w = 0;
				if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) break;
				if(w == SSL_WRITE_E){
					clear_response(&res);
					clear_content(&cont);
					return 1;
				}
				clear_response(&res);
				clear_content(&cont);
				return 0;
			}

			/*send 200 response*/
			if(generate_response(&res,OK,&cont,req) == -1) {
				clear_content(&cont);
				clear_response(&res);
				return 0;
			}

			clear_content(&cont);
			int w = 0;
			if((w = write_cli_SSL(cli_sock,&res,cds)) == -1){
				clear_response(&res);
				return 0;
			}

			if(w == SSL_WRITE_E){
				clear_response(&res);
				return 1;
			}
			clear_response(&res);
			return 0;
#if OWN_DB
		}
		/*send 200 response*/
		if(generate_response(&res,201,&cont,req) == -1) {
			clear_content(&cont);
			clear_response(&res);
			return 0;
		}

		clear_content(&cont);
		int w = 0;
		if((w = write_cli_SSL(cli_sock,&res,cds)) == -1){
			clear_response(&res);
			return 0;
		}

		if(w == SSL_WRITE_E){
			clear_response(&res);
			return 1;
		}
		clear_response(&res);
		return 0;

		} else{

			if(load_resource(req->resource,&cont) == -1){
				/*send not found response*/
				if(generate_response(&res,404,&cont,req) == -1) break;

				int w = 0;
				if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) break;
				if(w == SSL_WRITE_E){
					clear_response(&res);
					clear_content(&cont);
					return 1;
				}
				clear_response(&res);
				clear_content(&cont);
				return 0;
			}

			/*send 200 response*/
			if(generate_response(&res,OK,&cont,req) == -1) {
				clear_content(&cont);
				clear_response(&res);
				return 0;
			}

			clear_content(&cont);
			int w = 0;
			if((w = write_cli_SSL(cli_sock,&res,cds)) == -1){
				clear_response(&res);
				return 0;
			}

			if(w == SSL_WRITE_E){
				clear_response(&res);
				return 1;
			}
			clear_response(&res);
			return 0;
		}
		return 0;
#endif
	}
	case OPTIONS:
	{
		struct Response res = {0};
		size_t s = strlen(req->origin);
		if(s != strlen(ORIGIN_DEF) 
				|| strncmp(req->origin,ORIGIN_DEF,strlen(ORIGIN_DEF)) != 0) {
			/*send bad request*/
			/*send a bed request response*/
			if(generate_response(&res,400,NULL,req) == -1) {
				clear_response(&res);
				return -1;
			}

			int w = 0;
			if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) {
				clear_response(&res);
				return -1;
			}

			if(w == SSL_WRITE_E){
				clear_response(&res);
				return 1;
			}
			clear_response(&res);
			return 0;
		}

		/*send a response to the options request*/
		if(generate_response(&res,200,NULL,req) == -1) break;

		clear_request(req);
		int w = 0;

		if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) {
			clear_response(&res);
			return -1;
		}

		if(w == SSL_WRITE_E){
			clear_response(&res);
			return 1;
		}

		clear_response(&res);
		return 0;
	}
	case BAD_REQ:
	{
		struct Response res = {0};
		/*send a bed request response*/
		if(generate_response(&res,400,NULL,req) == -1) {
			clear_response(&res);
			return -1;
		}

		int w = 0;
		if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) {
			clear_response(&res);
			return -1;
		}

		if(w == SSL_WRITE_E){
			clear_response(&res);
			return 1;
		}
		clear_response(&res);
		return 0;
	}
	case POST:
	{
#if OWN_DB
		struct Response res = {0};
		struct Content cont = {0};

		if(load_resource_db(req,&cont,work_proc_data_sock) == -1){
			if(generate_response(&res,404,&cont,req) == -1) break;

			int w = 0;
			if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) break;
			if(w == SSL_WRITE_E){
				clear_response(&res);
				clear_content(&cont);
				return 1;
			}
			clear_response(&res);
			clear_content(&cont);
			return 0;
		}

		/*send 200 response*/
		if(generate_response(&res,OK,&cont,req) == -1) {
			clear_content(&cont);
			clear_response(&res);
			return 0;
		}

		clear_content(&cont);
		int w = 0;
		if((w = write_cli_SSL(cli_sock,&res,cds)) == -1){
			clear_response(&res);
			return 0;
		}

		if(w == SSL_WRITE_E){
			clear_response(&res);
			return 1;
		}
		clear_response(&res);
		return 0;
#endif

	}
	case PUT:
	case DELETE:
	default:
	return 0;
	}
	return -1;
}

/*this will change depends on the bussines*/
#if OWN_DB
static int load_resource_db(struct Request *req, struct Content *cont,int data_sock)
{
	int resource = map_end_point(req->resource); 
	if(resource == -1) return -1;

	switch(req->method){
	case POST:
	{
		switch(resource){
		case NEW_CUST:
		{
			/*convert json in db_string*/
			char *db = 0x0;
			if(req->req_body.d_cont)
				db = convert_json(req->req_body.d_cont);
			else
				db = convert_json(req->req_body.content);

			assert(db != NULL);
			if(db[0] == '\0') return -1;

			/*2 stands for  1 '\0', and 1 for the operation*/
			size_t size_buffer = strlen(db) + 2;
			char *buffer = (char *) malloc(size_buffer);

			buffer[0] = resource + '0';
			strncpy(&buffer[1],db,size_buffer-1);

			/*send data to the worker process*/
			if(write(data_sock,buffer,strlen(buffer)) == -1){ 
				free(buffer);
				return -1;
			}

			/*TODO: refactor the socket comunication so that you read once with 
			 * the size of the next message then you allocate a buffer accordangly so 
			 * you can be eficient*/
			char read_buffer[MAX_CONT_SZ];
			if(read(data_sock,read_buffer,MAX_CONT_SZ) == -1){
				free(buffer);
				return -1;
			}

			if(read_buffer[0] == '\0'){
				free(buffer);
				return -1;
			}

			if(snprintf(cont->cnt_st,1024,"%s",read_buffer) == -1){
				/*log error*/
				free(buffer);
				return -1;
			}
			cont->size = strlen(cont->cnt_st);
			free(buffer);
			return 0;
		}
		case NEW_SORD:
		case UPDATE_SORD:
		{

			/*save the sales order in the db */
			char *db = NULL;
			if(req->req_body.d_cont)
				db = convert_json(req->req_body.d_cont);
			else
				db = convert_json(req->req_body.content);

			assert(db != NULL);

			if(db[0] == '\0') return -1;

			/*process the string and separate the two file sintax*/

			char *lines_start = strstr(db,"sales_orders_lines");
			if(!lines_start) return -1;


			size_t lines_len = strlen((lines_start + strlen("sales_orders_lines:")));
			char orders_line[lines_len+1];
			memset(orders_line,0,lines_len+1);
			strncpy(orders_line,lines_start + strlen("sales_orders_lines:"),lines_len);

			char orders_head[((lines_start - db) - strlen("sales_orders_head:")) + 1];
			memset(orders_head,0,((lines_start - db) -strlen("sales_orders_head:")) +1);
			strncpy(orders_head,&db[strlen("sales_orders_head:")],((lines_start - db)-strlen("sales_orders_head:")));


			size_t size_buffer = 0;
			char *buffer = NULL;
			if(resource == NEW_SORD){
			/* 3 is 
			 *  1 for '^'
			 *  1 for instruction byte
			 *  1 for '\0';
			 * */
				size_buffer = sizeof(orders_head) + sizeof(orders_line)+3;
				buffer = (char*)malloc(size_buffer);
				if(!buffer) return -1;

				memset(buffer,0,size_buffer);

				/*parse data to buffer*/
				buffer[0] = resource + '0';
				strncpy(&buffer[1],orders_head,strlen(orders_head));
				strncpy(&buffer[1+strlen(orders_head)],"^",2);
				strncpy(&buffer[1+strlen(orders_head)+1],orders_line,strlen(orders_line));
			}else{
				/*parse a buffer for the update operation*/
				char *p = req->resource;
				p += strlen(UPDATE_ORDERS) + 1;

			/* 4 is 
			 *  2 for '^'
			 *  1 for instruction byte
			 *  1 for '\0';
			 * */
				
				size_buffer = sizeof(orders_head) + sizeof(orders_line)+ strlen(p) +4;
				buffer = (char*)malloc(size_buffer);
				if(!buffer) return -1;

				memset(buffer,0,size_buffer);

				buffer[0] = resource + '0';
				strncpy(&buffer[1],p,strlen(p));
				int position = 1+strlen(p);
				strncpy(&buffer[position],"^",2);
				position += 1;
				strncpy(&buffer[position],orders_head,strlen(orders_head));
				position += strlen(orders_head);
				strncpy(&buffer[position],"^",2);
				position += 1;
				strncpy(&buffer[position],orders_line,strlen(orders_line));
			}

			/*send data to the worker process*/
			if(write(data_sock,buffer,strlen(buffer)) == -1){
				free(buffer);
				return -1;
			}

			char read_buffer[MAX_CONT_SZ];
			if(read(data_sock,read_buffer,MAX_CONT_SZ) == -1){ 
				free(buffer);
				return -1;
			}

			if(read_buffer[0] == '\0') {
				free(buffer);
				return -1;
			}

			if(snprintf(cont->cnt_st,1024,"%s",read_buffer) == -1){
				/*log error*/
				free(buffer);
				return -1;
			}
			cont->size = strlen(cont->cnt_st);
			free(buffer);
			return 0;
		}
		case S_ORD:
		{
			break;
		}
		default:
		break;
		}
		break;
	}
	case GET:
	{
		switch(resource){
		case CUSTOMER_GET:
		{

			/*get the Key from the request*/
			char *p = req->resource;
			p += strlen(CUSTOMERS) + 1;

			/*
			 * check for URL encoding 
			 * if the %20 is found, the function will 
			 * change the string in place
			 * */
			check_URL_encoding(p);

			size_t key_size = strlen(p);
			char buffer[key_size+2];
			memset(buffer,0,key_size+2);

			buffer[0] = resource + '0';
			strncpy(&buffer[1],p,key_size);

			if(write(data_sock,buffer,sizeof(buffer)) == -1){
				return -1;
			}

			char *read_buffer = (char*)malloc(EIGHTkib_limit*4);
			if(!read_buffer) return -1;

			/*read data from worker proc*/

			memset(read_buffer,0,EIGHTkib_limit * 4);
			ssize_t bread = 0;
			if((bread = read(data_sock,read_buffer,(EIGHTkib_limit * 4)-1)) == -1){ 
				free(read_buffer);
				return -1;
			}

			if(bread == ((EIGHTkib_limit * 4) - 1)){
				free(read_buffer);
				fprintf(stderr,"code refactor neened %s:%d\n",__FILE__,__LINE__-1);
				return -1;
			}

			if(read_buffer[0] == '\0'){
				free(read_buffer);
				return -1;
			}

			size_t mem_size = strlen(read_buffer) + 1;
			cont->cnt_dy = (char*) malloc(mem_size);
			if(!cont->cnt_dy) {
				free(read_buffer);
				return -1;
			}

			cont->size = mem_size - 1;
			if(snprintf(cont->cnt_dy,mem_size,"%s",read_buffer) == -1) {
				free(read_buffer);
				return -1;
			}
			free(read_buffer);
			return 0;
		}
		case CUSTOMER_GET_ALL:
		case S_ORD:
		{		
			/*send data to the worker process*/
			char buffer[2];
			memset(buffer,0,2);
			if(resource == S_ORD)
				buffer[0] = S_ORD + '0';
			else
				buffer[0] = CUSTOMER_GET_ALL + '0';

			if(write(data_sock,buffer,sizeof(buffer)) == -1){
				return -1;
			}

			char *read_buffer = (char*)malloc(EIGHTkib_limit * 4);
			if(!read_buffer) return -1;

			/*read data from worker proc*/

			memset(read_buffer,0,EIGHTkib_limit * 4);
			ssize_t bread = 0;
			if((bread = read(data_sock,read_buffer,(EIGHTkib_limit * 4)-1)) == -1){
				free(read_buffer);
				return -1;
			}
			

			if(bread == ((EIGHTkib_limit * 4) - 1)){
				free(read_buffer);
				fprintf(stderr,"code refactor neened %s:%d\n",__FILE__,__LINE__-1);
				return -1;
			}

			if(read_buffer[0] == '\0'){ 
				free(read_buffer);
				return -1;
			}

			size_t mem_size = strlen(read_buffer) + 1;
			cont->cnt_dy = (char*) malloc(mem_size);
			if(!cont->cnt_dy) {
				free(read_buffer);
				return -1;
			}

			cont->size = mem_size - 1;
			if(snprintf(cont->cnt_dy,strlen(read_buffer)+1,"%s",read_buffer) == -1) {
				free(cont->cnt_dy);
				free(read_buffer);
				cont->cnt_dy = NULL;
				return -1;
			}

			free(read_buffer);
			return 0;
		}
		case S_ORD_GET:
		{
			char *p = req->resource;
			p += strlen(SALES_ORDERS) + 1;

			size_t key_size = strlen(p);
			char buffer[key_size+2];
			memset(buffer,0,key_size+2);

			buffer[0] = resource + '0';
			strncpy(&buffer[1],p,key_size);

			if(write(data_sock,buffer,strlen(buffer)) == -1) return -1;

			char *read_buffer = (char*) malloc(EIGHTkib_limit);
			if(!read_buffer) return -1;

			ssize_t bread = 0;
			if((bread = read(data_sock,read_buffer,EIGHTkib_limit) == -1)) {
				free(read_buffer);
				return -1;
			}

			if(bread == EIGHTkib_limit){
				/*code refactor*/					
				free(read_buffer);
				fprintf(stderr,"code refactor needed %s:%d\n",__FILE__,__LINE__-4);
				return -1;
			}

			strncpy(cont->cnt_st,read_buffer,strlen(read_buffer));		
			cont->size = strlen(read_buffer);
			free(read_buffer);
			return 0;
		}
		default:
		break;
		}
		break;
		}
		default:
		break;	
	}
	return 0;
}	

static char *convert_json(char* body)
{
	static char db_entry[1024] = {0};
	memset(db_entry,0,1024);
	int array = 0;
	int n_array = 0;
	int n_obj_arr = 0;
	int n_obj = 0;
	int string = 0;
	int i = 0;
	for(char *p = &body[1]; *p != '\0'; p++){
		if(*p == ']'){
			if(n_array) 
				n_array = 0;
			else
				array = 0;

			continue;
		}

		if(*p == ',' && !string) {
			db_entry[i] = ':';
			i++;
			continue;
		}

		if(*p == '}'){
			if(n_obj_arr){
				n_obj_arr = 0;
				db_entry[i] = ']';
				i++;
				/* 
				 * the following if statment check if we have more
				 * than one object in the array
				 * and format the db_entry accordingly
				 * */
				if(*(p + 1) == ','){
					db_entry[i] = ',';
					i++;
					p++;
				}
			}else if (n_obj){
				n_obj = 0;
			}
			continue;
		}

		if(*p == '{'){
			if(array){
				n_obj_arr = 1;
				/*file as a field syntax*/
				db_entry[i] = '[';
				i++;
				db_entry[i] = 'w';
				i++;
				db_entry[i] = '|';
				i++;
			}else{	
				n_obj = 1;
			}
		}

		if(*p == '['){
			if(array)
				n_array = 1;
			else
				array = 1;
			continue;
		}

		if(*p == ':' && string == 0){
			db_entry[i] = *p;
			i++;
			continue;
		}

		if(*p == ' ' && !string) continue;
		if(*p == '"') {
			if(string)
				string = 0;
			else
				string = 1;
			continue;
		}

		if(string){
			db_entry[i] = *p;
			i++;
			continue;
		}	

		if(isdigit(*p)){
			db_entry[i] = *p;
			i++;
			continue;
		}
	}

	return &db_entry[0];
}
#endif
static int check_URL_encoding(char *p)
{
	int sz = (int)strlen(p);
	char clean[sz];
	memset(clean,0,sz);
	int copied = 0;

	char *s = p;
	char *space = NULL;
	while((space = strstr(s,"%20"))){
		*space++ = ' ';
		int where = space - s; 	
		strncpy(&clean[copied],s,where);
		copied += where;
		space += 2;
		s = space;
	}
	
	strncpy(&clean[copied],s,strlen(s));
	strncpy(p,clean,strlen(clean));
	p[strlen(clean)] = '\0';
	return 0;
}


