#ifndef __LOAD_H_
#define __LOAD_H_

#include "request.h"
#include <stdint.h>
#define MAX_CONT_SZ 5000
struct Content{
	char cnt_st[MAX_CONT_SZ];
	char *cnt_dy;
	size_t size;
};

#define SET_ACME(n)	((uint32_t)(n) | 0x08000000)
#define SET_GZIP(n)	((uint32_t)(n) | 0x00000001)
#define IS_GZIP(n) 	(((uint32_t)(n) & 1U) == 1U) 
#define IS_ACME(n) 	(((uint32_t)(n) & 0x08000000U) == 0x08000000U) 

#define GZ_HEADER 700U
int load_resource(char *rpath, struct Content *cont, uint32_t option);
void clear_content(struct Content *cont);

#ifdef OWN_DB
int load_resource_db(struct Request *req, struct Content *cont,int data_sock);
#endif

#if EZ_GUI
#include "tpt_endpoint.h"
int load_resource_EZ(struct Request *req, struct Content *cont,int data_sock);
#endif

#endif
