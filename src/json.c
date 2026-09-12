#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "json.h"


static void skip_ws(const char* json,size_t len, size_t *i);
static int parse_string(const char  *json,size_t len,struct Json_token *t, size_t *i);
static int parse_number(const char  *json,size_t len,struct Json_token *t, size_t *i);
static int parse_literal(const char  *json,size_t len,struct Json_token *t, size_t *i);

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
		if(tk_count >= (int)max_tokens) return JSON_TK_LIMIT_ERR;
		if(depth >= JSON_MAX_DEPTH) return JSON_DEPTH_LIMIT_ERR;

		switch(json[i]){
		case '{':
		case '[':
		{
			tokens[tk_count].type = json[i] == '{' ? OBJECT : ARRAY;
			tokens[tk_count].start = i;
			tokens[tk_count].size = 0;
			tokens[tk_count].parent = (depth > 0) ? stack[depth -1] : -1;

			if(depth > 0) tokens[stack[depth-1]].size++;
			stack[depth++] = tk_count;
			tk_count++;
			i++;
			break;
		}
		case '}':
		case ']': 
		{ 
			if(depth == 0) return JSON_INVALID_ERR;
			depth--;
			int expect = json[i] == '}' ? OBJECT : ARRAY;
			if(tokens[stack[depth]].type != expect) return JSON_INVALID_ERR;

			tokens[stack[depth]].end = i + 1;
			if(expect == OBJECT) tokens[stack[depth]].size /= 2;
			i++;
			break;
		}
		case '"':
		{
			if(tk_count >= (int) max_tokens) return JSON_TK_LIMIT_ERR;
			tokens[tk_count].parent = (depth > 0) ? stack[depth -1] : -1;
			if(depth > 0) tokens[stack[depth-1]].size++;
			if(parse_string(json,len,&tokens[tk_count],&i) < 0) return JSON_INVALID_ERR;
			tk_count++;
			break;
		}
		case ',':
		case ':':
			i++;
			break;
		default: /*number or literal*/
			if(json[i] == 0x2D || (json[i] >= 0x30 && json[i] <= 0x39)){
				if(tk_count >= (int) max_tokens) return JSON_TK_LIMIT_ERR;
				tokens[tk_count].parent = (depth > 0) ? stack[depth -1] : -1;

				if(depth > 0) tokens[stack[depth-1]].size++;

				if(parse_number(json,len,&tokens[tk_count],&i) < 0) return JSON_INVALID_ERR;
				tk_count++;
			}else{
				if(tk_count >= (int) max_tokens) return JSON_TK_LIMIT_ERR;
				tokens[tk_count].parent = (depth > 0) ? stack[depth -1] : -1;

				if(depth > 0) tokens[stack[depth-1]].size++;

				if(parse_literal(json,len,&tokens[tk_count],&i) < 0) return JSON_INVALID_ERR;
				tk_count++;
			}
			break;
		}
		skip_ws(json,len,&i);
	}


	if(depth != 0) return JSON_INVALID_ERR;
	return tk_count;
}

int write_actual_json_tokens_to_mem(char *buf,size_t buf_size, struct Json_token *t,size_t token_size)
{
	if((sizeof *t * token_size) > buf_size) return -1;
	memcpy(buf,t,sizeof *t * token_size);	
	return 0;
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

static int parse_number(const char  *json,size_t len,struct Json_token *t, size_t *i)
{
	size_t k = *i;
	t->start = (int)k;
	if(k < len && (json[k] == '-' || json[k] == '+')) k++;
	if(k < len && json[k] == '0' &&  k+1 < len && isdigit((unsigned char)json[k+1])) return JSON_INVALID_ERR;

	if(k >= len || !isdigit((unsigned char)json[k])) return JSON_INVALID_ERR; 
	
	while(k < len && isdigit((unsigned char)json[k])) k++;

	if(k < len && json[k] == '.'){
		k++;
		if(k >= len || !isdigit((unsigned char)json[k])) return JSON_INVALID_ERR; 
		while(k < len && isdigit((unsigned char)json[k])) k++;
	}

	if(k < len && (json[k] == 'e' || json[k] == 'E')){
		k++;
		if(k < len && (json[k] == '-' || json[k] == '+')) k++;

		if(k >= len || !isdigit((unsigned char)json[k])) return JSON_INVALID_ERR; 
		while(k < len && isdigit((unsigned char)json[k])) k++;
	}

	t->type = NUMBER;
	t->end = (int)k;
	*i = k;
	return 0;
}

static int parse_literal(const char  *json,size_t len,struct Json_token *t, size_t *i)
{
	size_t k = *i;
	t->start = (int)k;

	/*false, true, null*/
	if(k + 4 <= len && strncmp(&json[k],"true",4) == 0){
		t->type = TRUE;
		k += 4;
	}else if( k + 4 <= len && strncmp(&json[k],"null",4) == 0){
		t->type = NUL;
		k += 4;
	}else if(k + 5 <= len && strncmp(&json[k],"false",5) == 0){
		t->type = FALSE;
		k += 5;
	}else{
		return JSON_INVALID_ERR;
	}

	t->end = (int)k;
	*i = k;
	return 0;
}

