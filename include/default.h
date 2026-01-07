#ifndef _DEFAULT_H_
#define _DEFAULT_H_

#include "limits.h"

extern char dir[PATH_MAX];
#define DEF_DIR_L 5
#define DEF_DIR "/www"
#define DEF_DIR_no_su "./www"
#define INDEX_FILE_no_su "www/index.html"
#define INDEX_FILE "/www/index.html"

#define INDEX_CNT "<!doctype html>\n<html>\n<head>\n<title>Wser</title>\n</head>\n\t<body>\n\t\t<h1>Wser home</h1>\n\t\t<h3>plug & play server</h3>\n\t</body>\n</html>\n" 
#define NOT_FOUND "<!doctype html>\n<html>\n<head>\n<title>Wser</title>\n</head>\n\t<body>\n\t\t<h1>NOT FOUND</h1>\n\t\t\t<h3>------</h3>\n\t\t<a href=\"/\">home</a>\n\t</body>\n</html>\n" 

int check_default_setting();
#endif
