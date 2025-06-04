#ifndef __LOAD_H_
#define __LOAD_H_

#define MAX_CONT_SZ 5000
struct Content{
	char cnt_st[MAX_CONT_SZ];
	char *cnt_dy;
	size_t size;
};

int load_resource(char *rpath, struct Content *cont);
void clear_content(struct Content *cont);

#endif
