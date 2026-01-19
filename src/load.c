#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "load.h"
#include "default.h"

static char prog[] = "wser";
static char *map_rpath(char *rpath);

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
