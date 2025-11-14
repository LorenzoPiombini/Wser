#include <string.h>
#include <byteswap.h>
#include <sys/random.h>
#include "tls.h"

static struct Handshake handshake = {0};

/*static func proto*/
static int is_grease(uint16_t v);
static void conditional_swap(uint64_t r[2][4],uint64_t r1[2][4],uint64_t bit);

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
		if(parse_client_hello(&ch,&buffer[move_in_buffer]) == -1){ 
			/*handshake failed */
			return -1;
		}

		/*create server hello*/
		struct Server_hello sh = {0};
		if(create_server_hello(&ch,&sh) == -1){
			/*handshake failed */
			return -1;
		}
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

int create_server_hello(struct Client_hello *ch,struct Server_hello *sh)
{
	sh->version = ch->version; 
	memcpy(sh->legacy_session_id_echo, ch->legacy_session_id,ch->legacy_session_id_size);
	uint32_t n = 0;
	if(getrandom(&n,sizeof(n),0) == -1) return -1;
	sh->cipher = ch->suites[n % 3];
	sh->cipher = bswap_16(sh->cipher);/*swap to big endian*/
	if(getrandom(sh->random.bytes,32,0) == -1) return -1;
	
	/*server hello extensions*/
	sh->ext.saved_extension[sh->ext.bwritten] = bswap_16(SUPPORTED_VERSIONS);
	sh->ext.bwritten += sizeof(uint16_t);
	sh->ext.saved_extension[sh->ext.bwritten] = bswap_16((uint16_t)1+2);
	sh->ext.bwritten += sizeof(uint16_t);
	sh->ext.saved_extension[sh->ext.bwritten] = (uint8_t) 1;
	sh->ext.bwritten++;
	sh->ext.saved_extension[sh->ext.bwritten] = (uint8_t) bswap_16((uint16_t)0x0304);
	sh->ext.bwritten += sizeof(uint16_t);

	/*reparse the client extensions*/
	uint16_t ext_type = 0;
	int bread = 0;
	do{
		uint16_t l = 0;
		memcpy(&ext_type,&ch->ext.saved_extension[bread],sizeof(uint16_t));
		bread += sizeof(uint16_t);
		if(ext_type != KEY_SHARE){
			memcpy(&l,&ch->ext.saved_extension[bread],sizeof(uint16_t));
			bread += sizeof(uint16_t) + l;
		}
		if(bread == ch->ext.bwritten) break;
	}while(ext_type != KEY_SHARE);

	/*find the named group in the key_extension*/

	switch(){
	case x25519:
	{
	/*generate and write the public_key*/

		const uint64_t p[4] = {0XFFFFFFFFFFFFFFEDULL,
								0XFFFFFFFFFFFFFFFFULL,
								0XFFFFFFFFFFFFFFFFULL,
								0X7FFFFFFFFFFFFFFFULL};
		const uint64_t a24 = 121666;
		uint8_t k[32] = {0};
		if(getrandom(k,32,0) == -1) return -1;

		/*clamp*/	
		k[0] &= 248;
		k[31] &= 127;
		k[21] |= 64;

		/*create pubblic key*/
		uint64_t R0[2][4] = {0};
		uint64_t R1[2][4] = {0};
		R1[0][0] = 9;
		R1[1][0] = 1;
		R0[0][0] = 1;

		int i, prev = 0;
		for(i = 254; i >= 0; i--){
			uint64_t bit = (k[i/8] >> (i % 8)) & 1;
			int64_t swap = bit ^ prev;
			int64_t mask = 0 - swap;
			conditional_swap(R0,R1,mask);
			R0 = point_double(R0);
			prev = bit;
		
		conditional_swap(R0,R1,0 - prev);

		break;
	}
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
	if(ch->version != PROTOCOL_VS_LEGACY) return -1;

	memcpy(ch->random.bytes,&buffer[move_in_buffer],sizeof(ch->random.bytes));
	move_in_buffer += sizeof(ch->random.bytes);

	ch->legacy_session_id_size = (int)buffer[move_in_buffer];
	move_in_buffer += sizeof(uint8_t);

	if(ch->legacy_session_id_size > 32) return -1;

	memcpy(ch->legacy_session_id,&buffer[move_in_buffer],ch->legacy_session_id_size);
	 
	move_in_buffer += ch->legacy_session_id_size;

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
			if(found < 3)
				ch->suites[found] = cipher_suites[i];
			found++;
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
				/*for TLS 1.3 we can ignore this extension*/
				uint16_t len = 0;
				memcpy(&len,p,sizeof(uint16_t));
				p += sizeof(uint16_t);
				bread += sizeof(uint16_t);
				len = bswap_16(len);
				p += len;
				bread += len;
				break;
			}
			case SUPPORTED_GROUPS: 
			{
				ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = extension_type;
				ch->ext.bwritten += sizeof(extension_type);

				uint16_t len = 0;
				memcpy(&len,p,sizeof(uint16_t));
				len = bswap_16(len);
				p += sizeof(uint16_t);
				bread += sizeof(uint16_t);
				uint16_t list[len/sizeof(uint16_t)];
				memcpy(list,p,len);
				p += len;
				bread += len;
				
				uint16_t found_group[30] = {0};
				int i, f = 0;
				for(i = 0; i < (int)(len/sizeof(uint16_t));i++){
					list[i] = bswap_16(list[i]);
					switch(list[i]){
					case secp256r1:
						if(f < 30)
							found_group[f] = list[i];
						f++;

						break;
					case secp384r1:
						if(f < 30)
							found_group[f] = list[i];
						f++;
						break;
					case secp521r1:
						if(f < 30)
							found_group[f] = list[i];
						f++;
						break;
					case x25519:
						if(f < 30)
							found_group[f] = list[i];
						f++;
						break;
					case x448:
						if(f < 30)
							found_group[f] = list[i];
						f++;
						break;
					case ffdhe2048:
						if(f < 30)
							found_group[f] = list[i];
						f++;
						break;
					case ffdhe3072:
						if(f < 30)
							found_group[f] = list[i];
						f++;
						break;
					case ffdhe4096:
						if(f < 30)
							found_group[f] = list[i];
						f++;
						break;
					case ffdhe6144:
						if(f < 30)
							found_group[f] = list[i];
						f++;
						break;
					case ffdhe8192:
						if(f < 30)
							found_group[f] = list[i];
						f++;
						break;
					case ffdhe_private_use_start:
						if(f < 30)
							found_group[f] = list[i];
						break;
					case ffdhe_private_use_end:
						if(f < 30)
							found_group[f] = list[i];
						f++;
						break;
					case ecdhe_private_use_start:
						if(f < 30)
							found_group[f] = list[i];
						f++;
						break;
					case ecdhe_private_use_end:
						if(f < 30)
							found_group[f] = list[i];
						f++;
						break;
					}
				}
				if(!f) return -1;
				uint16_t ls = f * sizeof(uint16_t);
				ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = ls;
				ch->ext.bwritten += sizeof(ls);
				memcpy(&ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)],
						found_group,f*sizeof(uint16_t));
				ch->ext.bwritten += f*sizeof(uint16_t);
				break;
			}
			case SIGNATURE_ALGORITHMS:
			{
				ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = extension_type;
				ch->ext.bwritten += sizeof(extension_type);
				uint16_t len = 0;/*signatue algo block*/
				memcpy(&len,p,sizeof(uint16_t));
				p += sizeof(uint16_t);
				bread += sizeof(uint16_t);
				len = bswap_16(len);

				uint8_t sig_algo[len];
				memcpy(sig_algo,p,len);
				p += len;
				bread += len;

				uint16_t list_size = 0;
				int move_in_sig_algo_list = 0;
				memcpy(&list_size,sig_algo,sizeof(uint16_t));
				move_in_sig_algo_list += sizeof(uint16_t);
				list_size = bswap_16(list_size);
				
				uint16_t sig_algos[list_size/sizeof(uint16_t)];
				memcpy(sig_algos,sig_algo,list_size/sizeof(uint16_t));
				uint16_t found_sig[14] = {0};
				int i,f = 0;
				for(i = 0; i < (int)(list_size/sizeof(uint16_t)); i++){
					sig_algos[i] = bswap_16(sig_algos[i]);
					switch(sig_algos[i]){
					case RSA_PKCS1_SHA256:
						if(f < 14) found_sig[i] = sig_algos[i];
						f++;
						break;
					case RSA_PKCS1_SHA384:
						if(f < 14) found_sig[i] = sig_algos[i];
						f++;
						break;
					case RSA_PKCS1_SHA512:
						if(f < 14) found_sig[i] = sig_algos[i];
						f++;
						break;
					case ECDSA_SECP256R1_SHA256:
						if(f < 14) found_sig[i] = sig_algos[i];
						f++;
						break;
					case ECDSA_SECP384R1_SHA384:
						if(f < 14) found_sig[i] = sig_algos[i];
						f++;
						break;
					case ECDSA_SECP521R1_SHA512:
						if(f < 14) found_sig[i] = sig_algos[i];
						f++;
						break;
					case RSA_PSS_RSAE_SHA256:
						if(f < 14) found_sig[i] = sig_algos[i];
						f++;
						break;
					case RSA_PSS_RSAE_SHA384:
						if(f < 14) found_sig[i] = sig_algos[i];
						f++;
						break;
					case RSA_PSS_RSAE_SHA512:
						if(f < 14) found_sig[i] = sig_algos[i];
						f++;
						break;
					case ED25519:
						if(f < 14) found_sig[i] = sig_algos[i];
						f++;
						break;
					case ED448:
						if(f < 14) found_sig[i] = sig_algos[i];
						f++;
						break;
					case RSA_PSS_PSS_SHA256:
						if(f < 14) found_sig[i] = sig_algos[i];
						f++;
						break;
					case RSA_PSS_PSS_SHA384:
						if(f < 14) found_sig[i] = sig_algos[i];
						f++;
						break;
					case RSA_PSS_PSS_SHA512:
						if(f < 14) found_sig[i] = sig_algos[i];
						f++;
						break;
					case PRIVATE_USE_START:
						if(f < 14) found_sig[i] = sig_algos[i];
						f++;
						break;
					case PRIVATE_USE_END:
						if(f < 14) found_sig[i] = sig_algos[i];
						f++;
						break;
					}
				}
				if (!f) return -1;

				uint16_t ls = f * sizeof(uint16_t);
				ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = ls;
				ch->ext.bwritten += sizeof(ls);
				memcpy(&ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)],
						found_sig,f*sizeof(uint16_t));
				ch->ext.bwritten += f *sizeof(uint16_t);
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
				p += sizeof(uint16_t);
				bread += sizeof(uint16_t);
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
				while(move_in_app_proto < proto_lis_size){
					uint16_t proto_size = 0;
					memcpy(&proto_size,&app_proto_layer_buff[move_in_app_proto],sizeof(uint8_t));
					move_in_app_proto += sizeof(uint8_t);
					char prot[proto_size+1];
					prot[proto_size] = '\0';
					memcpy(prot,&app_proto_layer_buff[move_in_app_proto],proto_size);
					move_in_app_proto += proto_size;
					if(strncmp(APP_LAYER_PROTO_DEFAULT,prot,strlen(prot)) == 0) break;
				}
				break;
			}
			case SIGNED_CERTIFICATE_TIMESTAMP:
			{
				uint16_t len = 0;
				memcpy(&len,p,sizeof(uint16_t));
				p += sizeof(uint16_t);
				bread += sizeof(uint16_t);

				if(len == 0) continue;
											
				len = bswap_16(len);
				p += len;
				bread += len;
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
				uint16_t len = 0;
				memcpy(&len,p,sizeof(uint16_t));
				p += sizeof(uint16_t);
				bread += sizeof(uint16_t);

				len = bswap_16(len);
				p += len;
				bread += len;

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
					list[i] = bswap_16(list[i]);
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
				uint16_t len = 0;
				memcpy(&len,p,sizeof(uint16_t));
				p += sizeof(uint16_t);
				bread += sizeof(uint16_t);

				if(len == 0) continue;

				len = bswap_16(len);
				uint8_t psk_list_size = p[bread];
				uint8_t psk_mode = p[bread+1];
				p += len;
				bread += len;
				switch(psk_mode){
				case PSK_KE: 
				case PSK_DHE_KE:
					break;
				default:
					return -1;
				}
				
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
				ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = extension_type;
				ch->ext.bwritten += sizeof(extension_type);

				uint16_t len = 0;
				memcpy(&len,p,sizeof(uint16_t));
				p += sizeof(uint16_t);
				bread += sizeof(uint16_t);

				if(len == 0)continue;

				len = bswap_16(len);
				uint8_t key_share_block[len];
				memcpy(key_share_block,p,len);
				p += len;
				bread += len;

				uint16_t key_shares_l = 0;
				int move_in_key_shares_block = 0;
				memcpy(&key_shares_l,key_share_block,sizeof(uint16_t));
				key_shares_l = bswap_16(key_shares_l);
				move_in_key_shares_block += sizeof(uint16_t);
				uint16_t key_size = 0;
				do{
					uint16_t named_group = 0;
					memcpy(&named_group,&key_share_block[move_in_key_shares_block],sizeof(uint16_t));
					move_in_key_shares_block += sizeof(uint16_t);
					named_group = bswap_16(named_group);
					switch(named_group){
						/*ECC*/
					case secp256r1:
					{
						ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = named_group;
						ch->ext.bwritten += sizeof(named_group);

						memcpy(&key_size,&key_share_block[move_in_key_shares_block],sizeof(uint16_t));
						move_in_key_shares_block += sizeof(uint16_t);

						key_size = bswap_16(key_size);
						if(key_size == 1){
							move_in_key_shares_block++;
							continue;
						}
						ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = key_size;
						ch->ext.bwritten += sizeof(key_size);
						memcpy(&ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)],
								&key_share_block[move_in_key_shares_block],key_size);
						/*verify the key*/

						uint8_t legacy_form = key_share_block[move_in_key_shares_block];
						if(legacy_form != 4) return -1;

						move_in_key_shares_block++;
						uint32_t x = 0, y = 0;

						memcpy(&x,&key_share_block[move_in_key_shares_block],sizeof(uint32_t));
						x = bswap_32(x);
						move_in_key_shares_block += sizeof(uint32_t);
						memcpy(&y,&key_share_block[move_in_key_shares_block],sizeof(uint32_t));
						y = bswap_32(y);
						move_in_key_shares_block += sizeof(uint32_t);

						ch->ext.bwritten += key_size;

						break;
					}
				case secp384r1:
				{
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = named_group;
					ch->ext.bwritten += sizeof(named_group);

					memcpy(&key_size,&key_share_block[move_in_key_shares_block],sizeof(uint16_t));
					move_in_key_shares_block += sizeof(uint16_t);

					key_size = bswap_16(key_size);
					if(key_size == 1){
						move_in_key_shares_block++;
						continue;
					}
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = key_size;
					ch->ext.bwritten += sizeof(key_size);
					memcpy(&ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)],
							&key_share_block[move_in_key_shares_block],key_size);
					/*verify the key*/
					uint8_t legacy_form = key_share_block[move_in_key_shares_block];
					if(legacy_form != 4) return -1;

					move_in_key_shares_block++;

					ch->ext.bwritten += key_size;

					break;
				}
				case secp521r1:
				{
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = named_group;
					ch->ext.bwritten += sizeof(named_group);

					memcpy(&key_size,&key_share_block[move_in_key_shares_block],sizeof(uint16_t));
					move_in_key_shares_block += sizeof(uint16_t);

					key_size = bswap_16(key_size);
					if(key_size == 1){
						move_in_key_shares_block++;
						continue;
					}
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = key_size;
					ch->ext.bwritten += sizeof(key_size);
					memcpy(&ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)],
							&key_share_block[move_in_key_shares_block],key_size);
					/*verify the key*/
					uint8_t legacy_form = key_share_block[move_in_key_shares_block];
					if(legacy_form != 4) return -1;

					move_in_key_shares_block++;

					uint64_t x = 0, y = 0;

					memcpy(&x,&key_share_block[move_in_key_shares_block],sizeof(uint64_t));
					x = bswap_64(x);
					move_in_key_shares_block += sizeof(uint64_t);
					memcpy(&y,&key_share_block[move_in_key_shares_block],sizeof(uint64_t));
					y = bswap_64(y);
					move_in_key_shares_block += sizeof(uint32_t);
					ch->ext.bwritten += key_size;
					break;
				}
				case x25519:
				{
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = named_group;
					ch->ext.bwritten += sizeof(named_group);

					memcpy(&key_size,&key_share_block[move_in_key_shares_block],sizeof(uint16_t));
					move_in_key_shares_block += sizeof(uint16_t);

					key_size = bswap_16(key_size);
					if(key_size == 1){
						move_in_key_shares_block++;
						continue;
					}
					/*verify the key*/
					if(key_size != 32) return -1;

					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = key_size;
					ch->ext.bwritten += sizeof(key_size);
					memcpy(&ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)],
							&key_share_block[move_in_key_shares_block],key_size);
					ch->ext.bwritten += key_size;

					break;
				}
				case x448:
				{
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = named_group;
					ch->ext.bwritten += sizeof(named_group);

					memcpy(&key_size,&key_share_block[move_in_key_shares_block],sizeof(uint16_t));
					move_in_key_shares_block += sizeof(uint16_t);

					key_size = bswap_16(key_size);
					if(key_size == 1){
						move_in_key_shares_block++;
						continue;
					}
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = key_size;
					ch->ext.bwritten += sizeof(key_size);
					memcpy(&ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)],
							&key_share_block[move_in_key_shares_block],key_size);
					/*verify the key*/
					ch->ext.bwritten += key_size;
					break;
				}
				/*FCC*/
				case ffdhe2048:
				{
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = named_group;
					ch->ext.bwritten += sizeof(named_group);


					memcpy(&key_size,&key_share_block[move_in_key_shares_block],sizeof(uint16_t));
					move_in_key_shares_block += sizeof(uint16_t);

					key_size = bswap_16(key_size);
					if(key_size == 1){
						move_in_key_shares_block++;
						continue;
					}
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = key_size;
					ch->ext.bwritten += sizeof(key_size);
					memcpy(&ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)],
							&key_share_block[move_in_key_shares_block],key_size);
					/*verify the key*/
					ch->ext.bwritten += key_size;
					break;
				}
				case ffdhe3072:
				{
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = named_group;
					ch->ext.bwritten += sizeof(named_group);


					memcpy(&key_size,&key_share_block[move_in_key_shares_block],sizeof(uint16_t));
					move_in_key_shares_block += sizeof(uint16_t);

					key_size = bswap_16(key_size);
					if(key_size == 1){
						move_in_key_shares_block++;
						continue;
					}
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = key_size;
					ch->ext.bwritten += sizeof(key_size);
					memcpy(&ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)],
							&key_share_block[move_in_key_shares_block],key_size);
					/*verify the key*/
					ch->ext.bwritten += key_size;
					break;
				}
				case ffdhe4096:
				{
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = named_group;
					ch->ext.bwritten += sizeof(named_group);

					memcpy(&key_size,&key_share_block[move_in_key_shares_block],sizeof(uint16_t));
					move_in_key_shares_block += sizeof(uint16_t);

					key_size = bswap_16(key_size);
					if(key_size == 1){
						move_in_key_shares_block++;
						continue;
					}
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = key_size;
					ch->ext.bwritten += sizeof(key_size);
					memcpy(&ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)],
							&key_share_block[move_in_key_shares_block],key_size);
					/*verify the key*/
					ch->ext.bwritten += key_size;
					break;
				}
				case ffdhe6144:
				{
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = named_group;
					ch->ext.bwritten += sizeof(named_group);

					memcpy(&key_size,&key_share_block[move_in_key_shares_block],sizeof(uint16_t));
					move_in_key_shares_block += sizeof(uint16_t);

					key_size = bswap_16(key_size);
					if(key_size == 1){
						move_in_key_shares_block++;
						continue;
					}
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = key_size;
					ch->ext.bwritten += sizeof(key_size);
					memcpy(&ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)],
							&key_share_block[move_in_key_shares_block],key_size);
					/*verify the key*/
					ch->ext.bwritten += key_size;
					break;
				}
				case ffdhe8192:
				{
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = named_group;
					ch->ext.bwritten += sizeof(named_group);

					memcpy(&key_size,&key_share_block[move_in_key_shares_block],sizeof(uint16_t));
					move_in_key_shares_block += sizeof(uint16_t);

					key_size = bswap_16(key_size);
					if(key_size == 1){
						move_in_key_shares_block++;
						continue;
					}
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = key_size;
					ch->ext.bwritten += sizeof(key_size);
					memcpy(&ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)],
							&key_share_block[move_in_key_shares_block],key_size);
					/*verify the key*/
					ch->ext.bwritten += key_size;
					break;
				}
				case ffdhe_private_use_start:
				{
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = named_group;
					ch->ext.bwritten += sizeof(named_group);

					memcpy(&key_size,&key_share_block[move_in_key_shares_block],sizeof(uint16_t));
					move_in_key_shares_block += sizeof(uint16_t);

					key_size = bswap_16(key_size);
					if(key_size == 1){
						move_in_key_shares_block++;
						continue;
					}
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = key_size;
					ch->ext.bwritten += sizeof(key_size);
					memcpy(&ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)],
							&key_share_block[move_in_key_shares_block],key_size);
					/*verify the key*/
					ch->ext.bwritten += key_size;
					break;
				}
				case ffdhe_private_use_end:
				{
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = named_group;
					ch->ext.bwritten += sizeof(named_group);

					memcpy(&key_size,&key_share_block[move_in_key_shares_block],sizeof(uint16_t));
					move_in_key_shares_block += sizeof(uint16_t);

					key_size = bswap_16(key_size);
					if(key_size == 1){
						move_in_key_shares_block++;
						continue;
					}
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = key_size;
					ch->ext.bwritten += sizeof(key_size);
					memcpy(&ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)],
							&key_share_block[move_in_key_shares_block],key_size);
					/*verify the key*/
					ch->ext.bwritten += key_size;
					break;
				}
				case ecdhe_private_use_start:
				{
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = named_group;
					ch->ext.bwritten += sizeof(named_group);

					memcpy(&key_size,&key_share_block[move_in_key_shares_block],sizeof(uint16_t));
					move_in_key_shares_block += sizeof(uint16_t);

					key_size = bswap_16(key_size);
					if(key_size == 1){
						move_in_key_shares_block++;
						continue;
					}
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = key_size;
					ch->ext.bwritten += sizeof(key_size);
					memcpy(&ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)],
							&key_share_block[move_in_key_shares_block],key_size);
					/*verify the key*/
					ch->ext.bwritten += key_size;
					break;
				}
				case ecdhe_private_use_end:
				{
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = named_group;
					ch->ext.bwritten += sizeof(named_group);

					memcpy(&key_size,&key_share_block[move_in_key_shares_block],sizeof(uint16_t));
					move_in_key_shares_block += sizeof(uint16_t);

					key_size = bswap_16(key_size);
					if(key_size == 1){
						move_in_key_shares_block++;
						continue;
					}
					ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)] = key_size;
					ch->ext.bwritten += sizeof(key_size);
					memcpy(&ch->ext.saved_extension[ch->ext.bwritten/sizeof(uint16_t)],
							&key_share_block[move_in_key_shares_block],key_size);
					/*verify the key*/
					ch->ext.bwritten += key_size;
					break;
				}
				default:
				{
					if(is_grease(named_group)){ 
						memcpy(&key_size,&key_share_block[move_in_key_shares_block],sizeof(uint16_t));
						move_in_key_shares_block += sizeof(uint16_t);
						key_size = bswap_16(key_size);
						if(key_size == 1){
							move_in_key_shares_block++;
							continue;
						}

						break;
					}
					return -1;
				}
				}


				}while(key_size == 1);

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
	return 0;
}

static int is_grease(uint16_t v) {
	return ((v & 0x0f0f) == 0x0a0a) && ((v >> 8) == (v & 0xff));
}

static void conditional_swap(uint64_t r[2][4],uint64_t r1[2][4],uint64_t mask)
{
	int i;
	for(i = 0; i < 4; i++){
		uint64_t temp = mask & (r[0][i] ^ r1[0][i]);
		r[0][i] ^= temp;	
		r1[0][i] ^= temp;	

		temp = mask & (r[1][i] ^ r1[1][i]);
		r[1][i] ^= temp;	
		r1[1][i] ^= temp;	
	}

}
