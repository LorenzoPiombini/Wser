#ifndef _SSL_PROCESS_H_
#define _SSL_PROCESS_H_ 1


#include "network.h"
#include "request.h"

int SSL_work_process(struct Connection_data *cd,int cli_sock,struct Request *req,SSL **ssl,SSL_CTX **ctx);
#endif 
