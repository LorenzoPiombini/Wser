#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "limits.h"
#include "default.h"


char dir[PATH_MAX] = {0};
static char prog[] = "wser";
static int no_su_setting();

int check_default_setting()
{
	/* check if the default directory exist*/
	
	if(getuid() != 0){
		if(no_su_setting() == -1) return -1;
	}else{
		if(chdir(DEF_DIR) == -1) return -1;	
	}


	struct stat st;
	if(stat(DEF_DIR,&st) == -1){
		if(errno == EACCES){ 
			if(no_su_setting() == -1) return -1;

		} else if (errno == ENOENT){
			errno = 0;
			if(setuid(0) == -1){
				if(errno == EPERM){
					/*get the user home path and check/create the defautl folder there*/
					if(no_su_setting() == -1) return -1;
					return 0;
				}
				return -1;
			}

			/*create the folder*/
			if(mkdir(DEF_DIR,S_IFDIR | S_IRWXU) == -1){
				fprintf(stderr,"(%s:)cannot setup default folder.\n",prog);
				return -1;
			}
			
			FILE *fp = fopen(INDEX_FILE,"w");
			if(!fp){
		   		fprintf(stderr,"(%s): cannot create sample home page",prog);	
				return -1;
			}
			fputs(INDEX_CNT,fp);
			fclose(fp);
			return 0;
		}
	}
	
	if(S_ISDIR(st.st_mode))return 0;

	return -1;
}

static int no_su_setting()
{
	/*get the user home path and check/create the defautl folder there*/
	errno = 0;
	if(!getcwd(dir,PATH_MAX)){
		if(errno == ENAMETOOLONG){
			fprintf(stderr,"(%s): cannot setup default config",prog);
			return -1;
		}
		return -1;
	}
	uid_t uid = getuid();
	setuid(uid);
	struct passwd *pw = getpwuid(uid);
	size_t dir_len = strlen(dir);
	if(dir_len == strlen(pw->pw_dir)){
		if(strncmp(dir,pw->pw_dir,dir_len) != 0){
			/*go to home dir*/	
			if(chdir(pw->pw_dir) == -1){
				fprintf(stderr,"(%s): cannot change directory.\n",prog);
				return -1;
			}
		}
	} else {

		/*go to home dir*/	
		if(chdir(pw->pw_dir) == -1){
			fprintf(stderr,"(%s): cannot change directory.\n",prog);
			return -1;
		}

	}
	errno= 0;
	struct stat st;
	if(stat(DEF_DIR_no_su,&st) == -1){
		if(errno == ENOENT){
			/* make dir*/
			if(mkdir(DEF_DIR_no_su,S_IFDIR | S_IRWXU) == -1){
				if(chdir(dir) == -1){
					fprintf(stderr,"(%s): cannot change directory.\n",prog);
					return -1;
				}
				return -1;
			}
			FILE *fp = fopen(INDEX_FILE_no_su,"w");
			if(!fp){
				fprintf(stderr,"(%s): cannot create sample home page",prog);	
				if(chdir(dir) == -1){
					fprintf(stderr,"(%s): cannot change directory.\n",prog);
					return -1;
				}
				return -1;
			}
			fputs(INDEX_CNT,fp);
			fclose(fp);
			return 0;
		}
	}

	if(S_ISDIR(st.st_mode)) return 0;
	return -1;
}
