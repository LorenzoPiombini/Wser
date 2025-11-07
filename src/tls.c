#include <string.h>
#include <byteswap.h>
#include "tls.h"

static struct Handshake handshake = {0};

int get_TLS_plain_text(struct TLS_plain_text *plain_text, const uint8_t *buffer)
{
	int move_in_buffer = 0;
	char b = buffer[move_in_buffer];
	plain_text->type = (uint8_t)(b - '\0');			
	move_in_buffer += sizeof(uint8_t);

	memcpy(&plain_text->legacy_record_version,&buffer[move_in_buffer],sizeof(uint16_t)); 
	move_in_buffer += sizeof(uint16_t);
	plain_text->legacy_record_version = bswap_16(plain_text->legacy_record_version);

	memcpy(&plain_text->length,&buffer[move_in_buffer],sizeof(uint16_t)); 
	move_in_buffer += sizeof(uint16_t);
	plain_text->length = bswap_16(plain_text->length);

	if(plain_text->length > TWO_POWER_OF_14) return -1;

	switch(plain_text->type){
	case INVALID:
	case CHANGE_CIPHER_SPEC:
	case ALERT:
	case HANDSHAKE:
	{
		parse_handshake(&handshake,&buffer[move_in_buffer]);						
		break;
	}
	case APPLICATION_DATA:
	default:
		return -1;
	}

	return -1;
}

int parse_handshake(struct Handshake *hs, const uint8_t *buffer)
{
	int move_in_buffer = 0;
	hs->msg_type = buffer[0];	
	move_in_buffer += sizeof(hs->msg_type);
	
	uint24 l;
	memcpy(l,&buffer[move_in_buffer],sizeof(uint24));
	move_in_buffer += sizeof(uint24);
	hs->length = (uint32_t)((uint32_t)l[0] << 16) | ((uint32_t)l[1]) << 8 | (uint32_t)l[2];

	switch(hs->msg_type){
	case CLIENT_HELLO:
	{
		/*parse client hello message*/
		struct Client_hello ch = {0};
		parse_client_hello(&ch,&buffer[move_in_buffer]);
		break;
	}
	case SERVER_HELLO:
	case NEW_SESSION_TICKET:
	case END_OF_EARLY_DATA:
	case ENCRYPTED_EXTENSIONS:
	case CERTIFICATE:
	case CERTIFICATE_REQUEST:
	case CERTIFICATE_VERIFY:
	case FINISHED:
	case KEY_UPDATE:
	case MESSAGE_HASH:
	default:
	 	return -1;
	}
	
	return 0;
}

int parse_client_hello(struct Client_hello *ch,const uint8_t *buffer)
{
	
	int move_in_buffer = 0;
	memcpy(&ch->version,&buffer[move_in_buffer],sizeof(Protocol_version));
	move_in_buffer += sizeof(Protocol_version);

	ch->version = bswap_16(ch->version);
	memcpy(ch->random.bytes,&buffer[move_in_buffer],sizeof(ch->random.bytes));
	move_in_buffer += sizeof(ch->random.bytes);

	int legacy_size = (int)buffer[move_in_buffer];
	move_in_buffer += sizeof(uint8_t);

	if(legacy_size > 32) return -1;

	memcpy(ch->legacy_session_id,&buffer[move_in_buffer],legacy_size);
	move_in_buffer += legacy_size;

	uint16_t cipher_suites_size = 0;
	memcpy(&cipher_suites_size,&buffer[move_in_buffer],sizeof(uint16_t));
	move_in_buffer += sizeof(uint16_t);

	cipher_suites_size = bswap_16(cipher_suites_size);
	if(cipher_suites_size > CIPHER_SUITES_MAX_SIZE) return -1;	

	uint16_t cipher_suites[cipher_suites_size / sizeof(uint16_t)];
	memset(cipher_suites,0,cipher_suites_size/sizeof(uint16_t));

	memcpy(cipher_suites,&buffer[move_in_buffer],cipher_suites_size);
	move_in_buffer += cipher_suites_size;


	uint16_t i, found = 0;
	for(i = 0; i < cipher_suites_size / (uint16_t)sizeof(uint16_t);i++){
		cipher_suites[i] = bswap_16(cipher_suites[i]);
		switch(cipher_suites[i]){
		case TLS_AES_128_GCM_SHA256:
		case TLS_AES_256_GCM_SHA384:
		case TLS_CHACHA20_POLY1305_SHA256:
			found = 1;
			break;
		default:
			break;
		}
	}

	if(!found) return -1;

	int legacy_compression_size = buffer[move_in_buffer];
	if(legacy_compression_size != 1) return -1;

	move_in_buffer += sizeof(uint8_t);
	if(buffer[move_in_buffer] != '\0') return 0;
	
	move_in_buffer++;

	uint16_t extension_size = 0;
	memcpy(&extension_size,&buffer[move_in_buffer],sizeof(uint16_t));
	move_in_buffer += sizeof(uint16_t);
	extension_size = bswap_16(extension_size);

	/*if(extension_size < 7) return -1;*/
		
	uint8_t extension_buf[extension_size];
	memcpy(extension_buf,&buffer[move_in_buffer],extension_size);
	move_in_buffer += extension_size;
	
	uint8_t *p = &extension_buf[0];
	int bread = 0;
	uint8_t supported_vs_found = 0;
	while(bread < extension_size){
		uint16_t extension_type = 0;
		memcpy(&extension_type,p,sizeof(uint16_t));
		extension_type = bswap_16(extension_type);
		p = p + sizeof(uint16_t);
		bread += sizeof(uint16_t);

		switch(extension_type){
			case SERVER_NAME: 
			{
				uint16_t len = 0;
				memcpy(&len,p,sizeof(uint16_t));
				len = bswap_16(len);
				p += sizeof(uint16_t);
				bread += sizeof(uint16_t);
				uint8_t server_data[len];
				memcpy(server_data,p,len);
				p += len;
				bread += len;
				uint16_t server_list_len = 0;
				memcpy(&server_list_len,server_data,sizeof(uint16_t));
				server_list_len = bswap_16(server_list_len);
				int name_type = server_data[2];	
				if(name_type == 0){
					uint16_t name_size = 0;
					memcpy(&name_size,&server_data[3],sizeof(uint16_t));
					name_size = bswap_16(name_size);	
					char host_name[name_size+1];
					memset(host_name,0,name_size+1);
					strncpy(host_name,(char*)&server_data[5],name_size);
				}
				break;
			}
			case MAX_FRAGMENT_LENGTH: 
			{
				break;
			}
			case STATUS_REQUEST: 
			{
				break;
			}
			case SUPPORTED_GROUPS: 
			{
				uint16_t len = 0;
				memcpy(&len,p,sizeof(uint16_t));
				len = bswap_16(len);
				p += sizeof(uint16_t);
				bread += sizeof(uint16_t);
				uint16_t list[len/sizeof(uint16_t)];
				memcpy(list,p,len);
				p += len;
				bread += len;
				
				size_t i;
				for(i = 0; i < len/sizeof(uint16_t);i++){
					list[i] = bswap_16(list[i]);
					switch(list[i]){
					case secp256r1:
						break;
					case secp384r1:
						break;
					case secp521r1:
						break;
					case x25519:
						break;
					case x448:
						break;
					case ffdhe2048:
						break;
					case ffdhe3072:
						break;
					case ffdhe4096:
						break;
					case ffdhe6144:
						break;
					case ffdhe8192:
						break;
					case ffdhe_private_use_a:
						break;
					case ffdhe_private_use_b:
						break;
					case ecdhe_private_use_a:
						break;
					case ecdhe_private_use_b:
						break;
					default:
						break;
					}
				}
				break;
			}
			case SIGNATURE_ALGORITHMS:
			{
				break;
			}
			case USE_SRTP:
			{
				break;
			}
			case HEARTBEAT:
			{
				break;
			}
			case APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
			{
				uint16_t len = 0;
				memcpy(&len,p,sizeof(uint16_t));
				len = bswap_16(len);
				uint8_t app_proto_layer_buff[len];
				memcpy(app_proto_layer_buff,p,len);
				p += len;
				bread += len;
				int move_in_app_proto = 0;
				uint16_t proto_lis_size = 0;
				memcpy(&proto_lis_size,app_proto_layer_buff,sizeof(uint16_t));
				move_in_app_proto += sizeof(uint16_t);
				proto_lis_size = bswap_16(proto_lis_size);		
				while(move_in_app_proto < len){
					uint16_t proto_size = 0;
					memcpy(&proto_size,&app_proto_layer_buff[move_in_app_proto],sizeof(uint16_t));
					move_in_app_proto += sizeof(uint16_t);
					char prot[proto_size+1];
					prot[proto_size] = '\0';
					memcpy(prot,&app_proto_layer_buff[move_in_app_proto],proto_size);
					move_in_app_proto += proto_size;
					if(strncpy(APP_LAYER_PROTO_DEFAULT,prot,strlen(prot)) == 0) break;
				}
				break;
			}
			case SIGNED_CERTIFICATE_TIMESTAMP:
			{
				break;
			}
			case CLIENT_CERTIFICATE_TYPE:
			{
				break;
			}
			case SERVER_CERTIFICATE_TYPE:
			{
				break;
			}
			case PADDING:
			{
				break;
			}
			case PRE_SHARED_KEY:
			{
				break;
			}
			case EARLY_DATA:
			{
				break;
			}
			case SUPPORTED_VERSIONS:
			{
				supported_vs_found = 1;
				uint16_t len = 0;
				memcpy(&len,p,sizeof(uint16_t));
				p += sizeof(uint16_t);
				bread += sizeof(uint16_t);
				uint8_t list_size = 0;
				memcpy(&list_size,p,sizeof(uint8_t));
				p += 1;
				bread += 1;
				uint16_t list[list_size/sizeof(uint16_t)];
				memcpy(list,p,list_size);
				p += list_size;
				bread += list_size;
				
				size_t i;
				uint8_t f = 0;
				for(i = 0; i < list_size/sizeof(uint16_t);i++){
					if(list[i] == 0x0304) f = 1;		
				}
				if(!f) return -1;

				break;
			}
			case COOKIE:
			{
				break;
			}
			case PSK_KEY_EXCHANGE_MODES:
			{
				break;
			}
			case CERTIFICATE_AUTHORITIES:
			{
				break;
			}
			case OID_FILTERS:
			{
				break;
			}
			case POST_HANDSHAKE_AUTH:
			{
				break;
			}
			case SIGNATURE_ALGORITHMS_CERT:
			{
				break;
			}
			case KEY_SHARE:
			{
				break;
			}
			default:
			{
				uint16_t len =0;
				memcpy(&len,p,sizeof(uint16_t));
				p += sizeof(uint16_t);
				bread += sizeof(uint16_t);
				if(len == 0)continue;

				len = bswap_16(len);
				p += len;
				bread += len;
				continue; 
			}			
		}
	}
	if(!supported_vs_found) return -1;
}
