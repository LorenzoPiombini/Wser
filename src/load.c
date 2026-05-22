#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "load.h"
#include "request.h"
#include "default.h"

static char prog[] = "wser";
static char *map_rpath(char *rpath);
static int check_URL_encoding(char *p);

#ifdef OWN_DB

#include "work_process.h" /* database handler*/
#include "end_points.h"
#include "lua_start.h"
#include "ctype.h"
#include <assert.h>
static char *convert_json(char* body);
const int EIGHTkib_limit = 1024 * 8;
#endif

int load_resource(char *rpath, struct Content *cont)
{
	char *file_path = map_rpath(rpath);
	if(!file_path) {
		/*debug print*/
		fprintf(stderr,"map_rpath failed for some reason\nrpath is %s\n",rpath);
		return -1;
	}

	FILE *fp = fopen(file_path,"rb");
	if(!fp){
#ifdef OWN_DB
		/*
		 * TODO: if ir is not a file could be a DB endpoint
		 * 	so, in this case we need to implement a mapping function
		 * 	that maps the endpoints correctly, so we can write/read the info
		 * 	requested by the application, from the db.
		 *
		 *
		 * */
#endif
		strncpy(cont->cnt_st,NOT_FOUND,strlen(NOT_FOUND)+1);
		cont->size = strlen(NOT_FOUND) + 1;
		fprintf(stderr,"(%s): cannot open '%s'.\n",prog,rpath);
		return -1;
	}
	
	if(fseek(fp,0,SEEK_END) == -1){
		fclose(fp);
		return -1;	
	}

	long size = 0;
	if((size = ftell(fp)) == -1){
		fclose(fp);
		return -1;
	}

	rewind(fp);
	char buf[size+1];
	memset(buf,0,size+1);
	if(fread(buf,(size_t)size,1,fp) != 1){
		fprintf(stderr,"(%s): cannot read from '%s'.\n",prog,rpath);
		fclose(fp);
		return -1;
	}

	fclose(fp);	
	if((size + 1) > MAX_CONT_SZ){
		errno = 0;
		cont->cnt_dy = calloc(size+1,sizeof(char));
		if(!cont->cnt_dy){
			if(errno == ENOMEM) 
				fprintf(stderr,"(%s): not enough memory to allocate dynamic buffer for '%s'.\n",prog,rpath);
			else
				fprintf(stderr,"(%s): cannot allocate dynamic buffer for '%s'.\n",prog,rpath);

			return -1;
		}
		strncpy(cont->cnt_dy,buf,size);
		cont->size = (size_t)size;
		return 0;
	}

	cont->size = (size_t)size;
	strncpy(cont->cnt_st,buf,size);
	return 0;
}


static char *map_rpath(char *rpath)
{
	if(*rpath == '\0') return NULL;

	char dir[DEF_DIR_L+1] = {0};
	if(getuid() != 0)
		strncpy(dir,"www",DEF_DIR_L+1);
	else 
		strncpy(dir,DEF_DIR,DEF_DIR_L+1);
		
	static char path[1024] = {0};
	size_t l = strlen(rpath);
	size_t l_map = 1;
	if (l_map == l){
		if(strncmp("/",rpath,l_map) == 0){
			size_t inx_l = strlen("/index.html");	
			l += DEF_DIR_L + inx_l + 1;
			strncpy(path,dir,DEF_DIR_L);
			strncat(path,"/index.html",inx_l);

			return path;
		} 
		return NULL;
	}
	l += DEF_DIR_L + 1;
	strncpy(path,dir,DEF_DIR_L);
	strncat(path,rpath,l - DEF_DIR_L -1);
	return path;
}

void clear_content(struct Content *cont){
	if(cont->cnt_dy) free(cont->cnt_dy);

	memset(cont->cnt_st,0,MAX_CONT_SZ);
	cont->size = 0;
}	

/*
 * this will change depends on the bussines
 * that you want to manage.
 *  
 *  this is just a sales order system
 * */
#ifdef OWN_DB
int load_resource_db(struct Request *req, struct Content *cont,int data_sock)
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

			/*1 is the space  for '\0'*/
			size_t db_len = strlen(db);
			size_t size_buffer = db_len + sizeof(uint16_t)+ 1;
			uint16_t *buffer = malloc(size_buffer);
			if(!buffer){
				fprintf(stderr,"(%s): malloc() failed, %s:%d.\n",prog,__FILE__,__LINE__);
				return -1;
			}

			memset(buffer,0,size_buffer);

			*buffer = (uint16_t)resource;
			buffer += 1;
			strncpy((char*)buffer,db,db_len);

			uint16_t *b = (uint16_t*)buffer - 1;
			/*send data to the worker process*/
			if(write(data_sock,b,size_buffer - 1) == -1){ 
				free(b);
				return -1;
			}

			/*TODO: refactor the socket comunication so that you read once with 
			 * the size of the next message then you allocate a buffer accordangly so 
			 * you can be eficient
			 * 
			 *  NOTE: I do not think we need a refactor here as per 05/22/26
			 *
			 *
			 * */
			char read_buffer[MAX_CONT_SZ];
			if(read(data_sock,read_buffer,MAX_CONT_SZ) == -1){
				free(b);
				return -1;
			}

			if(read_buffer[0] == '\0'){
				free(b);
				return -1;
			}

			if(snprintf(cont->cnt_st,1024,"%s",read_buffer) == -1){
				/*log error*/
				free(b);
				return -1;
			}
			cont->size = strlen(cont->cnt_st);
			free(b);
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
			uint16_t *buffer = NULL;
			if(resource == NEW_SORD){
			/* 3 is 
			 *  1 for '^'
			 *  1 for '\0';
			 * */
				size_buffer = sizeof(orders_head) + sizeof(orders_line)+ sizeof(uint16_t) +2;
				buffer = malloc(size_buffer);
				if(!buffer){
					fprintf(stderr,"(%s): malloc() failed, %s:%d.\n",prog,__FILE__,__LINE__-2);
					return -1;
				}

				memset(buffer,0,size_buffer);

				/*parse data to buffer*/
				*buffer = (uint16_t)resource;
				buffer += 1;
				char *p = (char*)buffer;
				strncpy(p,orders_head,strlen(orders_head));
				strncpy(&p[strlen(orders_head)],"^",2);
				strncpy(&p[strlen(orders_head)+1],orders_line,strlen(orders_line));
			}else{
				/*parse a buffer for the update operation*/
				char *p = req->resource;
				p += strlen(UPDATE_ORDERS) + 1;

			/* 3 is 
			 *   - 2 for '^'
			 *   - 1 for '\0';
			 * */
				
				size_buffer = sizeof(orders_head) + sizeof(orders_line)+ strlen(p)+ sizeof(uint16_t) +3;
				buffer = malloc(size_buffer);
				if(!buffer) return -1;

				memset(buffer,0,size_buffer);

				*buffer = (uint16_t)resource;
				
				buffer += 1;
				char *b = (char*)buffer;

				strncpy(b,p,strlen(p));
				int position = strlen(p);
				strncpy(&b[position],"^",2);
				position += 1;
				strncpy(&b[position],orders_head,strlen(orders_head));
				position += strlen(orders_head);
				strncpy(&b[position],"^",2);
				position += 1;
				strncpy(&b[position],orders_line,strlen(orders_line));
			}

			uint16_t *b = (uint16_t*)buffer - 1;
			/*send data to the worker process*/
			if(write(data_sock,b,size_buffer) == -1){
				free(b);
				return -1;
			}

			char read_buffer[MAX_CONT_SZ];
			if(read(data_sock,read_buffer,MAX_CONT_SZ) == -1){ 
				free(b);
				return -1;
			}

			if(read_buffer[0] == '\0') {
				free(b);
				return -1;
			}

			if(snprintf(cont->cnt_st,1024,"%s",read_buffer) == -1){
				/*log error*/
				free(b);
				return -1;
			}
			cont->size = strlen(cont->cnt_st);
			free(b);
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
		case S_ORD_GET:
		case ITEM_GET:
		case S_ORD_CUSTOMER_GET:
		case CUSTOMER_GET:
		{

			/*get the Key from the request*/
			char *p = NULL;
			switch(resource){
			case S_ORD_GET:
			{
				p = req->resource;
				p += strlen(SALES_ORDERS) + 1;
				break;
			}
			case ITEM_GET:
			{
				p = req->resource;
				p += strlen(ITEMS) + 1;
				break;
			}
			case CUSTOMER_GET:
			{
				p = req->resource;
				p += strlen(CUSTOMERS) + 1;
				break;
			}
			case S_ORD_CUSTOMER_GET:
			{
				p = req->resource;
				p += strlen(SALES_NEW_ORDER_CUSTOMERS) + 1;
				break;
			}
			default:
				return -1;
			}
			/*
			 * check for URL encoding 
			 * if the %20 is found, the function will 
			 * change the string in place
			 * */
			check_URL_encoding(p);

			size_t key_size = strlen(p) +sizeof(uint16_t)+2;
			char buffer[key_size];
			memset(buffer,0,key_size);

			uint16_t *b = (uint16_t*)&buffer[0];
			*b = (uint16_t) resource;
			strncpy(&buffer[2],p,key_size - 2);

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
		case RPT:
		{
			char *p = req->resource; 
			p += strlen(REPORTS) + 1;

			int size = (int)(strlen(p) + sizeof(uint16_t));
			char buffer[size+1];
			memset(buffer,0,size+1);

			uint16_t *b = (uint16_t*)&buffer[0];
			*b = (uint16_t) resource;

			strncpy(&buffer[2],p,size - sizeof(uint16_t));

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
		case ITEM_GET_ALL:
		case CUSTOMER_GET_ALL:
		case S_ORD:
		{		
			/*send data to the worker process*/
			char buffer[3];
			memset(buffer,0,3);
			uint16_t *b = (uint16_t*)&buffer[0];
			switch(resource){
			case S_ORD:
				*b = (uint16_t)S_ORD;
				break;
			case CUSTOMER_GET_ALL:
				*b = (uint16_t)CUSTOMER_GET_ALL;
				break;
			case ITEM_GET_ALL:
				*b = (uint16_t)ITEM_GET_ALL;
				break;
			default:
				return -1;
			}

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
/*
 * This translate the JSON object from the UI in 
 * the string to add data to the Database
 * */
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
	
	if(!copied)
		return 0;

	strncpy(&clean[copied],s,strlen(s));
	strncpy(p,clean,strlen(clean));
	p[strlen(clean)] = '\0';
	return 0;
}




