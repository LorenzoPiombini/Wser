#ifndef _REQUEST_H_
#define _REQUEST_H_

#define MIN_HEAD_FIELD 50
#define BASE 1024
#define BAD_REQ 400
#define OK 200 
#define STD_LT_RESOURCE 550
#define DEFAULT "HTTP/1.1"
#define HTTP2 "HTTP/2"
#define ORIGIN_DEF "http://artech:8080"

enum method{
	GET,
	HEAD,
	PUT,
	POST,
	DELETE,
	CONNECT,
	OPTIONS,
	TRACE
};

struct Request{
	char req[BASE];
	char *d_req;
	ssize_t size;
	int method;
	char host[MIN_HEAD_FIELD];
	char resource[STD_LT_RESOURCE];
	char cont_type[MIN_HEAD_FIELD];
	char transfer_encoding[MIN_HEAD_FIELD];
	/*fields from OPTIONS method request (LIKE CORS browser preflight)*/
	char access_control_request_headers[MIN_HEAD_FIELD];
	char access_control_request_method[MIN_HEAD_FIELD]; 
	char origin[MIN_HEAD_FIELD];
};

int handle_request(struct Request *req);
int set_up_request(ssize_t len,struct Request *req);
int find_headers_end(char *buffer, size_t size);
void clear_request(struct Request *req);
#endif
