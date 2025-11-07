#ifndef _TLS_H_
#define _TLS_H_ 1

#include <stdint.h>
#define APP_LAYER_PROTO_DEFAULT "htpp/1.1"
#define PROTOCOL_VS 0x0303 /*TLS v 1.2 - legacy -*/
#define TWO_POWER_OF_14 16384
#define CIPHER_SUITES_MAX_SIZE 65534 

typedef uint16_t Protocol_version; 
typedef uint16_t Cypher_suite;
typedef uint8_t uint24[3];

struct Random{
	uint8_t bytes[32];
};

enum tls_cipher_suite{
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303
};

enum Content_type{
	INVALID = 0,
	CHANGE_CIPHER_SPEC = 20,
	ALERT = 21,
	HANDSHAKE = 22,
	APPLICATION_DATA = 23,
	MAX_SIZE_CONTENT_TYPE = 255
};

struct TLS_plain_text{
	uint8_t type;
	Protocol_version legacy_record_version;
	uint16_t length;
	uint8_t *fragment;/*I might not needed*/
};

enum Handshake_type{
	CLIENT_HELLO = 1,
	SERVER_HELLO = 2,
	NEW_SESSION_TICKET = 4,
	END_OF_EARLY_DATA = 5,
	ENCRYPTED_EXTENSIONS = 8,
	CERTIFICATE = 11,
	CERTIFICATE_REQUEST = 13,
	CERTIFICATE_VERIFY = 15,
	FINISHED = 20,
	KEY_UPDATE = 24,
	MESSAGE_HASH = 254,
	MAX_SIZE_HANSHAKE_TYPE = 255
};

struct Handshake{
	uint8_t msg_type;    /* handshake type */
	uint32_t length;     /* remaining bytes in message (read from uint24) */
	uint8_t *type;
	/* 
	 * type has to be parsed to one of the following
		ClientHello;
		ServerHello;
		EndOfEarlyData;
		EncryptedExtensions;
		CertificateRequest;
		Certificate;
		CertificateVerify;
		Finished;
		NewSessionTicket;
		KeyUpdate;
	*/
};





struct Extension{
	uint16_t extension_type;

};

struct Client_hello{
	Protocol_version version;
	struct Random random;
	uint8_t legacy_session_id[32];
	Cypher_suite *suites;
	uint8_t legacy_compression_method[255];
	struct Extension extension;
};
struct Server_hello{};

enum Extension_type{
	SERVER_NAME = 0,                             /* RFC 6066 */
	MAX_FRAGMENT_LENGTH = 1,                     /* RFC 6066 */
	STATUS_REQUEST = 5,                          /* RFC 6066 */
	SUPPORTED_GROUPS = 10,                       /* RFC 8422, 7919 */
	SIGNATURE_ALGORITHMS = 13,                  /* RFC 8446 */
	USE_SRTP = 14,                               /* RFC 5764 */
	HEARTBEAT = 15,                              /* RFC 6520 */
	APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16, /* RFC 7301 */
	SIGNED_CERTIFICATE_TIMESTAMP = 18,           /* RFC 6962 */
	CLIENT_CERTIFICATE_TYPE = 19,                /* RFC 7250 */
	SERVER_CERTIFICATE_TYPE = 20,               /* RFC 7250 */
	PADDING = 21,                                /* RFC 7685 */
	PRE_SHARED_KEY = 41,                         /* RFC 8446 */
	EARLY_DATA = 42,                             /* RFC 8446 */
	SUPPORTED_VERSIONS = 43,                     /* RFC 8446 */
	COOKIE = 44,                                 /* RFC 8446 */
	PSK_KEY_EXCHANGE_MODES = 45,                 /* RFC 8446 */
	CERTIFICATE_AUTHORITIES = 47,                /* RFC 8446 */
	OID_FILTERS = 48,                            /* RFC 8446 */
	POST_HANDSHAKE_AUTH = 49,                    /* RFC 8446 */
	SIGNATURE_ALGORITHMS_CERT = 50,              /* RFC 8446 */
	KEY_SHARE = 51,                              /* RFC 8446 */
	MAX_EXTENSION_SIZE = 65535
};
enum Named_group{/*key exchange methods*/

	/* Elliptic Curve Groups (ECDHE) */
	secp256r1 =0x0017, 
	secp384r1 =0x0018, 
	secp521r1 =0x0019,
	x25519=	0x001D, 
	x448=0x001E,

	/* Finite Field Groups (DHE) */
	ffdhe2048 =0x0100, 
	ffdhe3072 =0x0101, 
	ffdhe4096 =0x0102,
	ffdhe6144 =0x0103, 
	ffdhe8192 =0x0104,

	/* Reserved Code Points */
	ffdhe_private_use_a = 0x01FC,
	ffdhe_private_use_b = 0x01FF,
	ecdhe_private_use_a = 0xFE00,
	ecdhe_private_use_b = 0xFEFF,
	NAME_GROUP_MAX = 0xFFFF
};



/*API functions*/
int get_TLS_plain_text(struct TLS_plain_text *plain_text, const uint8_t *buffer);
int parse_handshake(struct Handshake *hs, const uint8_t *buffer);
int parse_client_hello(struct Client_hello *ch,const uint8_t *buffer);
#endif
