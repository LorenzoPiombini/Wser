#include <poll.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "ssl_process.h"
#include "network.h"
#include "request.h"
#include "response.h"

/*USE POLL for this process*/
static int handle_ssl_steps(struct Connection_data *cd, 
							int cli_sock,
							struct Request *req,
							SSL **ssl,
							SSL_CTX **ctx);

int SSL_work_process(struct Connection_data *cd,int cli_sock,struct Request *req,SSL **ssl,SSL_CTX **ctx)
{

	int b_out = 0;
	for(;;){
		int r = handle_ssl_steps(cd,cli_sock,req,ssl,ctx);
			
		if(r == -1) return 0;

		switch(r){
		case SSL_READ_E:
		case HANDSHAKE:
		{		
			r = handle_ssl_steps(cd,cli_sock,req,ssl,ctx);
			if( r == 0){
				
			}else{
				break;
			}
		}
		case 0:
		{
			/*process request*/
			switch(req->method){
			case GET:
			{
				struct Response res = {0};
				struct Content cont = {0};
				/* Load content */	
				if(load_resource(req->resource,&cont) == -1){
					/*send not found response*/
					if(generate_response(&res,404,NULL,req) == -1) break;

					int w = 0;
					if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) break;
					if( w == SSL_WRITE_E){
						uint8_t ws = 0;
						while((w = write_cli_SSL(cli_sock,&res,cds)) == -1){
							if( w == SSL_WRITE_E) continue;
						}

						clear_response(&res);
						clear_request(req);
						clear_content(&cont);
						return 0;
					}
					clear_response(&res);
					clear_request(req);
					clear_content(&cont);
					return 0;
				}

				/*send 200 response*/
				if(generate_response(&res,OK,&cont,req) == -1) {
					clear_content(&cont);
					clear_response(&res);
					clear_request(req);
					return 0;
				}

				clear_content(&cont);
				int w = 0;
				if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) break;
				if(w == SSL_WRITE_E){
					uint8_t ws = 0;
					while((w = write_cli_SSL(cli_sock,&res,cds)) == -1){
						if(w == SSL_WRITE_E) continue;

					}
					clear_request(req);
					clear_response(&res);
					return 0;
				}
				clear_request(req);
				clear_response(&res);
				return 0;
			}
			default:
			}
			break;
		}
		case BAD_REQ:
		{
			struct Response res = {0};
			/*send a bed request response*/
			if(generate_response(&res,400,NULL,req) == -1) break;
			int w = 0;
			if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) break;
			if(w == SSL_WRITE_E){
				while((w = write_cli_SSL(cli_sock,&res,cds)) == -1){
					if( w == SSL_WRITE_E) continue;
				}
			}
			clear_response(&res);
			return 0;
		}
		case SSL_SET_E:
		default:
		return 0;
		}

		if(b_out){
			break;
		}
	}
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
	}
	return 0;

}

