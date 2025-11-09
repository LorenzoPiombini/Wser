#ifndef _TLS_H_
#define _TLS_H_ 1

#include <stdint.h>
#define APP_LAYER_PROTO_DEFAULT "http/1.1"
#define PROTOCOL_VS_LEGACY 0x0303 /*TLS v 1.2 - legacy -*/
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
	/* extension_type
	 * extension_len
	 * */
	uint16_t saved_extension[1024*4];
	uint16_t bwritten;
};

struct Client_hello{
	Protocol_version version;
	struct Random random;
	uint8_t legacy_session_id_size;
	uint8_t legacy_session_id[32];
	Cypher_suite suites[3];
	uint8_t legacy_compression_method;
	struct Extension ext;
};

struct Server_hello{
	Protocol_version version;   /* it has to be TLS v1.2 */
	struct Random random;
	uint8_t legacy_session_id_echo[32]; /*it has to be == to the client hello*/
	Cypher_suite cipher; /* choose one randmly*/
	uint8_t legacy_compression_method;
	struct Extension extension;
	/*Extension extensions<6..2^16-1>*/
};

enum Certificate_status_type{
	OCSP = 1,
	MAX_SIZE_STATUS_TYPE = 255
};

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
enum Signature_type{ 
	CERTIFICATE_TIMESTAMP = 0, 
	TREE_HASH = 1,
	MAX_VALUE_SIG_TYPE = 255
};

enum psk_key_exchange_mode{ 
	PSK_KE = 0, 
	PSK_DHE_KE = 1, 
	PSK_KEY_MAX_SIZE = 255
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
	ffdhe_private_use_start = 0x01FC,
	ffdhe_private_use_end = 0x01FF,
	ecdhe_private_use_start = 0xFE00,
	ecdhe_private_use_end = 0xFEFF,
	NAME_GROUP_MAX = 0xFFFF
};

enum Signature_scheme{
          /* RSASSA-PKCS1-v1_5 algorithms */
          RSA_PKCS1_SHA256 = 0x0401,
          RSA_PKCS1_SHA384 = 0x0501,
          RSA_PKCS1_SHA512 = 0x0601,

          /* ECDSA algorithms */
          ECDSA_SECP256R1_SHA256 = 0x0403,
          ECDSA_SECP384R1_SHA384 = 0x0503,
          ECDSA_SECP521R1_SHA512 = 0x0603,

          /* RSASSA-PSS algorithms with public key OID rsaEncryption */
          RSA_PSS_RSAE_SHA256 = 0x0804,
          RSA_PSS_RSAE_SHA384 = 0x0805,
          RSA_PSS_RSAE_SHA512 = 0x0806,

          /* EdDSA algorithms */
          ED25519 = 0x0807,
          ED448 = 0x0808,

          /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
          RSA_PSS_PSS_SHA256 = 0x0809,
          RSA_PSS_PSS_SHA384 = 0x080A,
          RSA_PSS_PSS_SHA512 = 0x080B,

          /* Legacy algorithms */
          RSA_PKCS1_SHA1 = 0x0201,
          ECDSA_SHA1 = 0x0203,

          /* Reserved Code Points */
          PRIVATE_USE_START = 0xFE00,
		  PRIVATE_USE_END = 0xFFFF,
          MAX_VALUE_ALGO_SIG = 0xFFFF
};

/*API functions*/
int get_TLS_plain_text(struct TLS_plain_text *plain_text, const uint8_t *buffer);
int parse_handshake(struct Handshake *hs, const uint8_t *buffer);
int parse_client_hello(struct Client_hello *ch,const uint8_t *buffer);
int create_server_hello(struct Client_hello *ch,struct Server_hello *sh);
#endif
