#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include "json.h"


static void skip_ws(const char* json,size_t len, size_t *i);
static int parse_string(const char  *json,size_t len,struct Json_token *t, size_t *i);
static int parse_number(const char  *json,size_t len,struct Json_token *t, size_t *i);
static int parse_literal(const char  *json,size_t len,struct Json_token *t, size_t *i);

int json_parser(const char *json, size_t len,struct Json_token *tokens, size_t max_tokens)
{
	if(len > 0 
			&& *json != BEGIN_OBJECT 
			&& *json != BEGIN_ARRAY 
			&& *json != H_TAB
			&& *json != SPACE
			&& *json != NEW_LINE
			&& *json != CARRIAGE_RETURN) return -1;

	int state = -1;
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

			if(state == KEY || state == KEY_OR_CLOSING_OBJECT || state == END) return JSON_INVALID_ERR;

			tokens[tk_count].type = json[i] == '{' ? OBJECT_JS : ARRAY_JS;
			tokens[tk_count].start = i;
			tokens[tk_count].size = 0;
			tokens[tk_count].parent = (depth > 0) ? stack[depth -1] : -1;
			if(tokens[tk_count].type == OBJECT_JS) state = KEY_OR_CLOSING_OBJECT;
			if(tokens[tk_count].type == ARRAY_JS)  state = VALUE_OR_CLOSING_OBJECT;
			
			if(depth > 0) tokens[stack[depth-1]].size++;
			stack[depth++] = tk_count;
			tk_count++;
			i++;
			break;
		}
		case '}':
		case ']': 
		{ 

			if( state != KEY_OR_CLOSING_OBJECT 
					&& state != VALUE_OR_CLOSING_OBJECT 
					&& state != COMMA_OR_CLOSING_OBJ) return JSON_INVALID_ERR;
			if(depth == 0) return JSON_INVALID_ERR;
			depth--;
			int expect = json[i] == '}' ? OBJECT_JS : ARRAY_JS;
			if(expect == ARRAY_JS && state == KEY_OR_CLOSING_OBJECT) return JSON_INVALID_ERR;

			if(tokens[stack[depth]].type != expect) return JSON_INVALID_ERR;

			tokens[stack[depth]].end = i + 1;
			if(expect == OBJECT_JS) tokens[stack[depth]].size /= 2;
			int p = tokens[stack[depth]].parent;
			if(p == -1 && tokens[stack[depth]].type == OBJECT_JS) 
				state = END;
			else
				state = COMMA_OR_CLOSING_OBJ;
			i++;
			break;
		}
		case '"':
		{
			if(state == COMMA_OR_CLOSING_OBJ) return JSON_INVALID_ERR;
			if(state != KEY  
					&& state != KEY_OR_CLOSING_OBJECT
					&& state != VALUE
					&& state != VALUE_OR_CLOSING_OBJECT) return JSON_INVALID_ERR;

			if(state == KEY || state == KEY_OR_CLOSING_OBJECT) state = COLON;
			if(state == VALUE || state == VALUE_OR_CLOSING_OBJECT) state = COMMA_OR_CLOSING_OBJ;

			if(tk_count >= (int) max_tokens) return JSON_TK_LIMIT_ERR;
			tokens[tk_count].parent = (depth > 0) ? stack[depth -1] : -1;
			if(depth > 0) tokens[stack[depth-1]].size++;
			if(parse_string(json,len,&tokens[tk_count],&i) < 0) return JSON_INVALID_ERR;
			tk_count++;
			break;
		}
		case ',':
		case ':':
		{
			if(state != COLON && state != COMMA_OR_CLOSING_OBJ) return JSON_INVALID_ERR;
			if(state == COLON && json[i] != ':') return JSON_INVALID_ERR; 
			if(state == COMMA_OR_CLOSING_OBJ && json[i] != ',') return JSON_INVALID_ERR; 

			if(json[i] == ':') state = VALUE;
			if(json[i] == ','){
				int e = tokens[tokens[tk_count-1].parent].end;
				if( e == 0 && tokens[tokens[tk_count-1].parent].type == ARRAY_JS) 
					state = VALUE;
				else
					state = KEY;
			}

			size_t j = i;
			j++;
			skip_ws(json,len,&j);
			if(json[j] == ']' || json[j] == '}' || json[j] == ':') return -1;

			i++;
			break;
		}
		default: /*number or literal*/
			if(state != VALUE) return JSON_INVALID_ERR;
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
			state = COMMA_OR_CLOSING_OBJ;
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
			t->type = STRING_JS;
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

	t->type = NUMBER_JS;
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
		t->type = TRUE_JS;
		k += 4;
	}else if( k + 4 <= len && strncmp(&json[k],"null",4) == 0){
		t->type = NUL_JS;
		k += 4;
	}else if(k + 5 <= len && strncmp(&json[k],"false",5) == 0){
		t->type = FALSE_JS;
		k += 5;
	}else{
		return JSON_INVALID_ERR;
	}

	t->end = (int)k;
	*i = k;
	return 0;
}

int is_token_empty(struct Json_token *t)
{
	return 	t->type == 0 && t->start == 0 
		&& t->end == 0 && t->size == 0 && t->parent == 0;
}

int decode_json_escape(const char* src, size_t slen,char *dst,size_t dlen)
{
	
	if(dlen > slen) return -1;
	for(size_t i = 0, j = 0; i < slen; i++){
		switch(src[i]){
		case '\\':
		{
			size_t k = i + 1;
			switch(src[k]){
			case '"': 	if ((j + 1) < dlen) dst[j++] = '"';  i++;break;
			case '/': 	if ((j + 1) < dlen) dst[j++] = '/';  i++;break;
			case '\\': 	if ((j + 1) < dlen) dst[j++] = '\\'; i++;break;
			case 'b': 	if ((j + 1) < dlen) dst[j++] = '\b'; i++;break;
			case 'f': 	if ((j + 1) < dlen) dst[j++] = '\f'; i++;break;
			case 'n': 	if ((j + 1) < dlen) dst[j++] = '\n'; i++;break;
			case 'r': 	if ((j + 1) < dlen) dst[j++] = '\r'; i++;break;
			case 't': 	if ((j + 1) < dlen) dst[j++] = '\t'; i++;break;
			case 'u': 	
			{
				int r = 0;
				if ((r = encode_json_unicode((const uint8_t*)&src[k+1],&dst[j],slen - (k+1),dlen - j)) == -1) return -1;
				j += r;
				i += 5;
				break;
			}
			default:
				dst[j++] = src[k];
				break;
			}
			break;
		}
		default:
			dst[j++] = src[i];
			break;
		}
	}

	return 0;
}

int encode_json_unicode(const uint8_t *src, uint8_t *dst,size_t slen,size_t dlen)
{
	if(slen < 4) return -1;
	uint8_t bridge[7] = {0};
	bridge[0] = '0';
	bridge[1] = 'x';
	memcpy(&bridge[2],src,4);

	/*convert the unicode point from json to hex*/	
	errno = 0;
	long hex = strtol(bridge,NULL,16);
	if(errno == ERANGE || errno == EINVAL) return -1;
		
	if(hex <= 0x7F){
		if(dlen < 1) return -1;
		*dst = (uint8_t)hex;
		return 1;
	}
	
	if(hex >=0x80 && hex <= 0x7FF){
		if(dlen < 2) return -1;
		dst[0] = (uint8_t)(0xC0 | ((hex >> 6) & 0x1F));
		dst[1] = (uint8_t)(0x80 | (hex & 0x3F));
		return 2;
	}
		
	if(hex >= 0xD800 && hex <= 0xDFFF) return -1;
	if(hex >=0x800 && hex <= 0xFFFF){
		if(dlen < 3) return -1;
		dst[0] = (uint8_t)(0xE0 | ((hex >> 12) & 0x0F));
		dst[1] = (uint8_t)(0x80 | ((hex >> 6) & 0x3F));
		dst[2] = (uint8_t)(0x80 | (hex & 0x3F));
		return 3;
	}
	
	return -1;
}
