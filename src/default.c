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
static int su_setting();
static int create_wser_config();
static int go_to_user_home_dir();
static int load_wser_config(FILE **config_file);

int check_default_setting()
{
	/* check if the default directory exist*/
	
	if(getuid() != 0){
		if(no_su_setting() == -1) return -1;
	}else{
        if(su_setting() == -1) return -1;
    }
    return 0;
}

static int su_setting()
{
    /*this is root */
        if(go_to_user_home_dir() == -1) return -1;

        FILE *cf = NULL;
		if(load_wser_config(&cf) == -1){
            if(chdir(dir) == -1){
                fprintf(stderr,"(%s): cannot change directory.\n",prog);
                return -1;
            }
            return -1;
        }

		if(chdir(DEF_DIR) == -1) {
			/*make the directory*/
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
            if(chdir(DEF_DIR) == -1) return -1;
			return 0;
		}
        return 0;
}

static int go_to_user_home_dir()
{
	errno = 0;
	if(!getcwd(dir,PATH_MAX)){
		if(errno == ENAMETOOLONG){
			fprintf(stderr,"(%s): cannot setup default config",prog);
			return -1;
		}
		return -1;
	}
	uid_t uid = getuid();
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

	return 0;
}

static int no_su_setting()
{
	/*get the user home path and check/create the defautl folder there*/
	if(go_to_user_home_dir() == -1) return -1;

	/* now dir contain current working directory 
		before moving to user home dir */

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
			FILE *cf = NULL;
			if(load_wser_config(&cf) == -1){
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

    /*load the conf file*/
	FILE *cf = NULL;
	if(load_wser_config(&cf) == -1){
        if(chdir(dir) == -1){
            fprintf(stderr,"(%s): cannot change directory.\n",prog);
            return -1;
        }
        return -1;
    }

	
	FILE *fp = fopen(INDEX_FILE_no_su,"r");
	if (!fp){
		fp = fopen(INDEX_FILE_no_su,"w");
		if (!fp) return 0; /*i don't think is a correct reason to fail the server*/
		fputs(INDEX_CNT,fp);
		fclose(fp);
		return 0;
	}
	fclose(fp);
	return 0;
}


static int load_wser_config(FILE **config_file)
{

	if(!(*config_file)){ 
        *config_file = fopen(".wser.conf","r");
        if(!(*config_file)) 
            if(create_wser_config(config_file) == -1) return -1;
    }

	char line[250] = {0};
	while(fgets(line,sizeof(line),*config_file)){
		size_t s = strlen(line);
		if(sizeof(line) - 1 == s
			&& line[s - 1] != '\n' ) goto failed;

		char *p = line;

		while(*p != '\0' && (*p == ' ' || *p == '\t')) p++;
		if( *p == '\n' || *p == '#' || *p == '\0') continue;
		
		if(strncmp(p,"CERT_PATH=",10) == 0
			&& certificates_path[0] == '\0'){
			int i = 0;
			p = p + strlen("CERT_PATH=");
			while(*p && (*p != '\n' && *p != '\r')) certificates_path[i++] = *p++;
			continue;
		}

		if(strncmp(p,"ACME_WEBROOT=",13) == 0
			&& acme_webroot[0] == '\0'){
			int i = 0;
			p = p + strlen("ACME_WEBROOT=");
			while(*p && (*p != '\n' && *p != '\r')) acme_webroot[i++] = *p++;
			continue;
		}

		if(strncmp(p,"SERVER_LOG_PATH=",16) == 0
			&& server_log_file[0] == '\0'){
			int i = 0;
			p = p + strlen("SERVER_LOG_PATH=");
			while(*p && (*p != '\n' && *p != '\r')) server_log_file[i++] = *p++;
			continue;
		}
	}

	fclose(*config_file);
	*config_file = NULL;
	return 0;
failed:
	printf("reading config file failed.");
	if(*config_file) fclose(*config_file);
	return -1;
}

static int create_wser_config(FILE **config_file)
{
	FILE *fp = fopen(".wser.conf","r");
	if(fp){
		/*don't change an existing file but load it */
		*config_file = fp;
		return 0;
	}

	/*create the file*/
	fp = fopen(".wser.conf","w");
	if(!fp) return -1;
	fputs(
		"#\t\tWSER configuration file\n"
		"# line starting with # are comments\n"
		"# cancel the beginning # in front of a parameter to enable it\n"
		"#\n"
		"################################################################\n\n"
		"# path where the server will look for TLS certificates\n"
		"CERT_PATH=/etc/letsencrypt/live/\n\n"
		"# path where the server will write the logs\n"
		"SERVER_LOG_PATH=.local/logs/server.log\n\n"
		"# path where .well-know will be stored. for cert renewal\n"
		"#ACME_WEBROOT=?\n\n",
		fp);	
    fclose(fp);
	fp = fopen(".wser.conf","r");
    if(!fp) return -1;

    *config_file = fp;
	return 0;
}
