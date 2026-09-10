#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "json.h"


static void skip_ws(const char* json,size_t len, size_t *i);
static int parse_string(const char  *json,size_t len,size_t *i);
static int parse_number(const char  *json,size_t len,size_t *i);

int json_parser(const char *json, size_t len,struct Json_token *tokens, size_t max_tokens)
{
	if(len > 0 
			&& *json != BEGIN_OBJECT 
			&& *json != H_TAB
			&& *json != SPACE
			&& *json != NEW_LINE
			&& *json != CARRIAGE_RETURN) return -1;

	int stack[JSON_MAX_DEPTH];
	int depth = 0;
	memset(stack,-1,JSON_MAX_DEPTH*sizeof(int));
	size_t i = 0;
	int tk_count = 0;

	skip_ws(json,len,&i);
	while(i < len){
		if(tk_count >= max_tokens) return JSON_TK_LIMIT;
		if(depth >= JSON_MAX_DEPTH) return JSON_DEPTH_LIMIT;

		switch(json[i]){
		case '{':
		case '[':
		{
			tokens[tk_count].type = json[i] == '{' ? OBJECT : ARRAY;
			tokens[tk_count].start = i;
			tokens[tk_count].size = 0;
			tokens[tk_count].parent = (depth > 0) ? stack[depth -1] : -1;
			stack[depth++] = tk_count;
			tk_count++;
			i++;
			if(depth > 0) tokens[stack[depth-1]].size++;
			break;
		}
		case '}':
		case ']': { if(depth == 0) return JSON_INVALID_ERR;
			depth--;
			int expect = json[i] == '}' ? OBJECT : ARRAY;
			if(tokens[stack[depth]].type != expect) return JSON_INVALID_ERR;

			tokens[stack[depth]].end = i + 1;
			i++;
			if(depth > 0) tokens[stack[depth-1]].size++;
			break;
		}
		case '"':
				  parse_string(json,len,tokens,&i);
				  break;
		case ',':
		case ':':
		default: /*number or literal*/
			i++;
			break;

		}
		skip_ws(json,len,&i);
	}


	if(depth != 0) return JSON_INVALID_ERR;
	return tk_count;
}


static void skip_ws(const char* json,size_t len, size_t *i)
{
	size_t k = *i;
	while(k < len
			&& (json[k] == SPACE 
				|| json[k] == NEW_LINE 
				|| json[k] == H_TAB
				|| json[k] == CARRIAGE_RETURN)) k++;
	*i = k;
}

static int parse_string(const char  *json,size_t len,struct Json_token *t, size_t *i)
{

	size_t k = *i + 1;
	t->start = (int)k;

	while(k < len){
		unsigned char c = (unsigned char)json[k];

		switch(c){
		case '"':
		{
			t->end = (int)k;
			t->type = STRING;
			*i = k + 1;
			return 0;
		}
		case '\\':
		{
			k++;
			if(k >= len) return JSON_INVALID_ERR;
			switch(json[k]){
			case '"':
			case '\\':
			case '/':
			case 'f':
			case 'r':
			case 't':
			case 'b':
			case 'n':
				k++;
				break;
			case 'u':
				if(k + 4 >= len) return JSON_INVALID_ERR;
				int j = 1;
				while(j<=4) if(!isxdigit(json[k + j++])) return JSON_INVALID_ERR;

				k += 5;
				break;
			default:
				return JSON_INVALID_ERR;
			}
			break;
		}
		default:
			if(c < 0x20) return JSON_INVALID_ERR;
			k++;
			break;
		}

		

	}

	return JSON_INVALID_ERR;
}
#if 0

static parse_string()
{
	for(int i = 0; i < len;i++, p++){
		switch(*p){
		case '"': 
		{
			int start = (int)(p - json);
			p++;
			while(*p != '"') p++;
			int end = (int)(p - json);
			while(*p != ':' && *p != ',') p++;
			if(*p == ':') {
				/*it is a key!*/
			}
			break;
		}
		default:
			break;
		}
	}
}
#endif
