#ifndef _TLS_H_
#define _TLS_H_ 1

#include <stdint.h>
#define PROTOCOL_VS 0x0303 /*TLS v 1.2 - legacy -*/

typedef uint16_t Protocol_version; 
typedef uint16_t Cypher_suite;
typedef 
typedef uint8_t uint24_t[3];

struct Extensions{};

struct Random{
	uint8_t bytes[32];
};



struct Client_hello{
	Protocol_version vesrsion;
	Random random;
	uint8_t legacy_session_id[32];
	Cypher_suite *suites;
	uint8_t legacy_compression_method[255];
	Extension 
};
struct Server_hello{};

#endif
