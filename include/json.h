
#ifndef _JSON_H_
#define _JSON_H_ 1

#define JSON_MAX_DEPTH 20
/*Mini Json parser def*/
/*json grammar*/
enum json_type{
	OBJECT,
	ARRAY,
	STRING_K,
	STRING_V,
	BOOLEAN,
	NUL
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
	JSON_TK_LIMIT = -2,
	JSON_DEPTH_LIMIT = -3
};

struct Json_token{
	enum json_type type;
	int start;
	int end;
	int size;/*children*/
	int parent;
};

struct json{
	char *json_string;
	struct offsets *key_offsets;
	struct offsets *values_offsets;
};

int json_parser(const char *json, size_t len,struct Json_token *tokens, size_t max_tokens);
#endif
