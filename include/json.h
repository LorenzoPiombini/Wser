
#ifndef _JSON_H_
#define _JSON_H_ 1

#define JSON_MAX_DEPTH 20
#define JSON_MAX_TOKENS 512
/*Mini Json parser def*/
/*json grammar*/
enum json_type{
	OBJECT_JS,
	ARRAY_JS,
	STRING_JS,
	NUMBER_JS,
	TRUE_JS,
	FALSE_JS,
	NUL_JS
};

enum sturctural_chars{
	BEGIN_ARRAY = 		(int) '[',
	END_ARRAY = 		(int) ']',
	BEGIN_OBJECT = 		(int) '{',
	END_OBJECT = 		(int) '}',
	NAME_SEPARATOR = 	(int) ':',
	VALUE_SEPARATOR = 	(int) ','
};

enum ws{
	SPACE = 			(int) ' ',
	H_TAB = 			(int) '\t',
	NEW_LINE = 			(int) '\n',
	CARRIAGE_RETURN = 	(int) '\r'
};


enum json_error{
	JSON_INVALID_ERR = -1,
	JSON_TK_LIMIT_ERR = -2,
	JSON_DEPTH_LIMIT_ERR = -3
};

struct Json_token{
	int type;
	int start;
	int end;
	int size;/*children*/
	int parent;
};


int json_parser(const char *json, size_t len,struct Json_token *tokens, size_t max_tokens);
int write_actual_json_tokens_to_mem(char *buf,size_t buf_size, struct Json_token *t,size_t token_size);
#endif
