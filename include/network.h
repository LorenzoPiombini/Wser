#ifndef _NETWORK_H_
#define _NETWORK_H_

#include "request.h"
#include "response.h"
#include "stdint.h"
#include "openssl/ssl.h"

#define SSL_HD_F 18
#define SSL_SET_E 19
#define HANDSHAKE 20
#define SSL_READ_E 21
#define SSL_WRITE_E 22
#define NO_CON_DATA 23
#define INT_PROC_SOCK_SSL "/tmp/TLS_SSL_operation.socket"

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
};

extern struct Connection_data cds[MAX_CON_DAT_ARR];

int init_SSL(SSL_CTX **ctx);
int wait_for_connections_SSL(int sock_fd,int *cli_sock);
int listen_port_80(uint16_t *port);
int listen_UNIX_socket();
void clean_connecion_data(struct Connection_data *cd);
int read_cli_sock_SSL(int cli_sock, struct Request *req, struct Connection_data *cd);
int read_cli_sock(int cli_sock, struct Request *req);
int write_cli_sock(int cli_sock, struct Response *res);
int write_cli_SSL(int cli_sock, struct Response *res, struct Connection_data *cd);
int wait_for_connections(int sock_fd, int *cli_sock, struct Request *req);
int get(char *URL);
void stop_listening(int sock_fd);

#endif
