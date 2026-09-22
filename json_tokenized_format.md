
# how the tokenized json data get sent to DB side

```c
/* 
 *          [SERIALIZED OBJECT] -( flat object )
 *
 * 	[size_object]	(uint16_t) 	    (aka) children of outer object
 * 	[type_of_value]	(uint8_t) 	    (aka) type of the value token(of a key:value pair)
 *	[key_size]	    (uint16_t) 	    (aka) len in bytes of the following token
 *	[key token]	    (key_size)      (aka) actual interesting data 
 *	[value_size]	(uint16_t) 	    (aka) len in bytes of the following token
 *	[value token]	(token_size)    (aka) actual interesting data 
 *
 * if it is nested:
 * 	[size_object] 		(uint16_t) 	(aka) children of outer object
 * 	[type] 		        (uint8_t) 	(aka) type of the token
 * 		@@ is the token an object ? 
 * 						[...................................]
 * 						[       SERIALIZED OBJECT           ]
 * 						[...................................]
 *		no =>(which it will always be a string token becuse it is a key with an object as a value)
 *			[token_size]	(uint16_t) 	(aka) len in bytes of the following token
 *			[token itself]	(token_size)    (aka) actual interesting data 
 * */
```
