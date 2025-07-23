#ifndef _RESPONSE_H_
#define _RESPONSE_H_


#include <stdint.h>
#include "request.h"
#include "load.h"
#define STD_PTC "HTTP/1.1"
#define STD_LEN_PTC 9
#define STD_LEN_HTTP2 7 
#define STD_BDY_CNT 8192
#define STD_HD_L 1024
#define BAD_REQ_MES "{\"error\": \"Bad request\",\"message\": \"Request body could not be read properly.\"}"

struct Header{
	uint16_t status;
	char protocol_vs[STD_LEN_PTC];
	char reason_phrase[MIN_HEAD_FIELD];
	char date[MIN_HEAD_FIELD];
	uint32_t content_lenght;
	char connection[MIN_HEAD_FIELD];
	char transfer_encoding[MIN_HEAD_FIELD];
};

struct Body {
	char content[STD_BDY_CNT];	
	char *d_cont;
	size_t size;
};

struct Response{
	struct Header headers;
	char header_str[STD_HD_L];
	struct Body body;
};

int generate_response(struct Response *res, int status, struct Content *cont, struct Request *req);
void clear_response(struct Response *res);
#endif
