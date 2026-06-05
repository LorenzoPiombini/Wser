#ifndef _NETWORK_H_
#define _NETWORK_H_

#include "request.h"
#include "response.h"
#include "stdint.h"
#include "openssl/ssl.h"
#include <stdarg.h>

#define SSL_HD_F 18
#define SSL_SET_E 19
#define HANDSHAKE 20
#define SSL_READ_E 21
#define SSL_WRITE_E 22
#define NO_CON_DATA 23
#define WRITE_OK 24
#define SSL_CLOSE 25
#define CLEAN_TEARDOWN 26
#define INT_PROC_SOCK_SSL "/tmp/TLS_SSL_operation.socket"

#if OWN_DB
	#define INT_PROC_SOCK_DB  "/tmp/db_operation.socket"
#endif /*OWN_DB -make flag-*/

/*MACRO TO MANIPULATE THE DNS HEADER */
#define SET_QR(n) 			((n) |= 0x8000)
#define SET_OPCODE(n,val) 	((n) = ((n) &= 0x8FFF) | (((val) & 0x0F) << 11))
#define SET_AA(n) 			((n) |= 0x0400)
#define SET_TC(n) 			((n) |= 0x0200)
#define SET_RD(n) 			((n) |= 0x0100)
#define SET_RA(n) 			((n) |= 0x0080)
#define SET_Z(n)  			((n) &= 0xFF0F )/*must be 0 RFC 1035*/
#define SET_RDCODE(n,val) 	((n) = ((n) &= 0xFFF0 ) | (((val) & 0x0F )))

struct DNS_header{
	uint16_t id;
	uint16_t fields; /*(RFC 1035) this contains QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |*/
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
};


struct DNS_question{
	uint8_t qname[255];
	uint16_t qtype;
	uint16_t qclass;
};

struct DNS_record_format{
	uint8_t name[255];
	uint16_t type;
	uint16_t class;
	uint16_t ttl;
	uint16_t rdlength;
	uint8_t *rdata; /*variable data*/
};

extern SSL_CTX *ctx;

#define MAX_HOST_LT 50
#define MAX_PT_LT 20
#define MAX_RESOURCE_LT 1024
#define MAX_CON_DAT_ARR 20
struct Url{
	char protocol[MAX_PT_LT];
	char host[MAX_HOST_LT];
	char resource[MAX_RESOURCE_LT];
};


struct Connection_data{
	int fd;
	SSL *ssl;
    int (*retry_read)(SSL *,void *, size_t, size_t *);
	int (*retry_handshake)(SSL *);
	int (*retry_write)(SSL *,const void *,size_t,size_t *);
	int (*close_notify)(SSL *);
	struct Response res;
	char *buf;
};

extern struct Connection_data cds[MAX_CON_DAT_ARR];

/*Client standard request format strings*/
#define F_STR_GET "%s %s %s\r\n"\
	"Host: %s\r\n"\
	"User-Agent: %s\r\n"\
	"Accept: */*\r\n\r\n"

#define CUSTOM_STR_REQUEST 	"%s %s %s\r\n"

#define USER_FIELDS 1
int init_SSL(SSL_CTX **ctx);
int wait_for_connections_SSL(int sock_fd,int *cli_sock);
int listen_port_80(uint16_t *port);
int listen_UNIX_socket(int opt, char *sock_path);
int DNS_query(char *domain, int type);
int connect_UNIX_socket(int opt, char *sock_path);
void clean_connecion_data(struct Connection_data *cd, int sock);
int read_cli_sock_SSL(int cli_sock, struct Request *req, struct Connection_data *cd);
int read_cli_sock(int cli_sock, struct Request *req);
int write_cli_sock(int cli_sock, struct Response *res);
int write_cli_SSL(int cli_sock, struct Response *res, struct Connection_data *cd);
int wait_for_connections(int sock_fd, int *cli_sock, struct Request *req);
int perform_http_request(char *URL, char *req, char **body);
void stop_listening(int sock_fd);
int parse_URL(char *URL, struct Url *url);
int req_builder(int method, char *urlstr, char *format_str, char *req, int length,int mode);
void SSL_client_close();
int  SSL_client_config();
#endif
