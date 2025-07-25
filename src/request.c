#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "request.h"

static char prog[] = "wser";
static int get_headers_block(struct Request *req);
static int parse_header(char *head, struct Request *req);
static int get_method(char *method);
static int map_content_type(struct Request *req);

int handle_request(struct Request *req)
{
	int h_end = 0;
	if((h_end = get_headers_block(req)) == -1) return BAD_REQ;	

	char head[h_end+1];
	memset(head,0,h_end+1);
	if(req->d_req)
		strncpy(head,req->d_req,h_end);
	else
		strncpy(head,req->req,h_end);

	if(parse_header(head, req) == -1) return BAD_REQ;

	map_content_type(req);
	return 0;
}


int set_up_request(ssize_t bytes,struct Request *req)
{	
	ssize_t n_size = bytes * 2;
	req->d_req = calloc(n_size,sizeof(char));
	if(!req->d_req){
		fprintf(stderr,"(%s): cannot allocate memory for request.\n",prog);
		return -1;
	}
	strncpy(req->d_req,req->req,req->size);	
	memset(req->req,0,BASE);
	req->size= n_size;
	return 0;
}

void clear_request(struct Request *req)
{
	if(req->d_req) free(req->d_req);
	memset(req->req,0,BASE);
}


static int parse_header(char *head, struct Request *req)
{
	char *crlf = NULL;
	int start = 0;
	while((crlf = strstr(&head[start],"\r"))){
		if (start > 0){
			int end = crlf - head;
			size_t s = end - start;
			char t[s+1];
			memset(t,0,s+1);
			strncpy(t,&head[start],s);

			char *b = NULL;
			if((b = strstr(t,"Host:"))){	
				b += strlen("Host: ");
				strncpy(req->host,b,strlen(b));
				*crlf = ' ';
				start = end + 2;
				continue;
			}
			
			if((b = strstr(t,"Transfer-Encoding:"))){
				b += strlen("Transfer-Encoding: ");
				strncpy(req->transfer_encoding,b,strlen(b));
				*crlf = ' ';
				start = end + 2;
				continue;
			}

			if((b = strstr(t,"Access-Control-Request-Method:"))){
				b += strlen("Access-Control-Request-Method: ");
				strncpy(req->access_control_request_method,b,strlen(b));
				*crlf = ' ';
				start = end + 2;
				continue;
			}

			if((b = strstr(t,"Origin:"))){
				b += strlen("Origin: ");
				strncpy(req->origin,b,strlen(b));
				*crlf = ' ';
				start = end + 2;
				continue;
			}
			*crlf = ' ';
			start = end + 2;
			continue;
		}	

		int end = crlf - head;		
		char t[end+1];
		memset(t,0,end+1);
		strncpy(t,head,end);
		char *tok = strtok(t," ");
		if ((req->method = get_method(tok)) == -1 ) return BAD_REQ;

		tok = strtok(NULL, " ");
		size_t tok_l = strlen(tok);
		if(strlen(tok) > STD_LT_RESOURCE){
			/* handle this case*/
		}else{
			strncpy(req->resource,tok,tok_l);
		}
		tok = strtok(NULL," ");
		tok_l = strlen(tok);
		if (strncmp(tok,DEFAULT,tok_l) == 0){
			if(strstr(head,"Host:") == NULL) return BAD_REQ;
		}	
		*crlf = ' ';
		start = end + 2;
	}
	return 0;
}

int find_headers_end(char *buffer, size_t size)
{
	char *start = buffer;
	int c = 0;
	while(*buffer != '\r' && ((size_t)(buffer - start) < size)) {
		buffer++;
		if(*buffer != '\r') continue; 

		while(*buffer == '\r' || *buffer == '\n'){
			if((size_t)(buffer - start) == size) break;
			c++;
			buffer++;
		}

		if( c == 4) break;
		c = 0;
	}

	if(c < 4) return -1;
	if(c == 4) return (int)(buffer - start);

	return -1;
}

static int get_headers_block(struct Request *req)
{
	if(req->d_req) return find_headers_end(req->d_req, req->size);
	
	return find_headers_end(req->req, req->size);
}


static int get_method(char *method)
{
	size_t method_l = strlen(method);
	if(strlen("GET") == method_l)
		if(strncmp("GET",method,method_l) == 0) return GET;
	
	if(strlen("HEAD") == method_l)
		if(strncmp("HEAD",method,method_l) == 0) return HEAD;

	if(strlen("POST") == method_l)
		if(strncmp("POST",method,method_l) == 0) return POST;

	if(strlen("PUT") == method_l)
		if(strncmp("PUT",method,method_l) == 0) return PUT;

	if(strlen("DELETE") == method_l)
		if(strncmp("DELETE",method,method_l) == 0) return DELETE;
	
	if(strlen("CONNECT") == method_l)
		if(strncmp("CONNECT",method,method_l) == 0) return CONNECT;

	if(strlen("OPTIONS") == method_l)
		if(strncmp("OPTIONS",method,method_l) == 0) return OPTIONS;
		
	if(strlen("TRACE") == method_l)
		if(strncmp("TRACE",method,method_l) == 0) return TRACE;

	return -1;
}

static int map_content_type(struct Request *req)
{
	if(strstr(req->resource,".html")) {
		strncpy(req->cont_type,"text/html",MIN_HEAD_FIELD);
		return 0;
	} 

	if(strncmp(req->resource,"/", 2) == 0) {
		strncpy(req->cont_type,"text/html",MIN_HEAD_FIELD);
		return 0;
	} 

	if(strstr(req->resource,".css")) {
		strncpy(req->cont_type,"text/css",MIN_HEAD_FIELD);
		return 0;
	} 
	if(strstr(req->resource,".js")) {
		strncpy(req->cont_type,"text/javascript",MIN_HEAD_FIELD);
		return 0;
	} 
	if(strstr(req->resource,".jpeg")) {
		strncpy(req->cont_type,"image/jpeg",MIN_HEAD_FIELD);
		return 0;
	} 

	if(strstr(req->resource,".png")) {
		strncpy(req->cont_type,"image/png",MIN_HEAD_FIELD);
		return 0;
	} 

	if(strstr(req->resource,".json")) {
		strncpy(req->cont_type,"application/json",MIN_HEAD_FIELD);
		return 0;
	} 
	
	strncpy(req->cont_type,"text/plain",MIN_HEAD_FIELD);
	return 0;
}
