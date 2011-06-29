/*
 * sm-iasecc.c: Secure Messaging procedures specific to IAS/ECC card
 *
 * Copyright (C) 2010  Viktor Tarasov <vtarasov@opentrust.com>
 *					  OpenTrust <www.opentrust.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <string.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>

#include <openssl/des.h>

#include "libopensc/opensc.h"
#include "libopensc/sm.h"
#include "libopensc/log.h"
#include "libopensc/asn1.h"
#include "libopensc/iasecc.h"
#include "libopensc/iasecc-sdo.h"
#if 0
#include "libopensc/hash-strings.h"
#endif
#include "sm-module.h"

static const struct sc_asn1_entry c_asn1_card_response[2] = {
	{ "cardResponse", SC_ASN1_STRUCT, SC_ASN1_CTX | 1 | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};
static const struct sc_asn1_entry c_asn1_iasecc_response[4] = {
	{ "number",	SC_ASN1_INTEGER,	SC_ASN1_TAG_INTEGER,    0, NULL, NULL },
	{ "status",	SC_ASN1_INTEGER, 	SC_ASN1_TAG_INTEGER,    0, NULL, NULL },
	{ "data",       SC_ASN1_OCTET_STRING,   SC_ASN1_CTX | 2 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};
static const struct sc_asn1_entry c_asn1_iasecc_sm_response[4] = {
	{ "number",	SC_ASN1_INTEGER,	SC_ASN1_TAG_INTEGER,    0, NULL, NULL },
	{ "status",	SC_ASN1_INTEGER, 	SC_ASN1_TAG_INTEGER,    0, NULL, NULL },
	{ "data",	SC_ASN1_STRUCT,		SC_ASN1_CTX | 2 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};
static const struct sc_asn1_entry c_asn1_iasecc_sm_data_object[4] = {
	{ "encryptedData", 	SC_ASN1_OCTET_STRING,	SC_ASN1_CTX | 7,	SC_ASN1_OPTIONAL,	NULL, NULL },
	{ "commandStatus", 	SC_ASN1_OCTET_STRING,	SC_ASN1_CTX | 0x19,	0, 			NULL, NULL },
	{ "ticket", 		SC_ASN1_OCTET_STRING,	SC_ASN1_CTX | 0x0E,	0, 			NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};


int 
sm_cwa_get_mac(struct sc_context *ctx, unsigned char *key, DES_cblock *icv, 
			unsigned char *in, int in_len, DES_cblock *out, int force_padding)
{
	DES_cblock kk, k2;
	DES_key_schedule ks,ks2;
	unsigned char padding[8] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	unsigned char *buf;
		
	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "sm_cwa_get_mac() data length %i", in_len);	

	buf = malloc(in_len + 8);
	if (!buf)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	sc_log(ctx, "sm_cwa_get_mac() in_data(%i) %s", in_len, sc_dump_hex(in, in_len));
	memcpy(buf, in, in_len);
	memcpy(buf + in_len, padding, 8);

	if (force_padding)
		in_len = ((in_len + 8) / 8) * 8; 
	else
		in_len = ((in_len + 7) / 8) * 8; 

	sc_log(ctx, "sm_cwa_get_mac() data to MAC(%i) %s", in_len, sc_dump_hex(buf, in_len));
	sc_log(ctx, "sm_cwa_get_mac() ICV %s", sc_dump_hex((unsigned char *)icv, 8));

	memcpy(&kk, key, 8);
	memcpy(&k2, key + 8, 8);
	DES_set_key_unchecked(&kk,&ks);
	DES_set_key_unchecked(&k2,&ks2);
	DES_cbc_cksum_3des_emv96(buf, out, in_len ,&ks, &ks2, icv);

	free(buf);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
sm_cwa_encode_external_auth_data(struct sc_context *ctx, struct sm_cwa_session *session_data, 
		unsigned char *out, size_t out_len)
{
	if (out_len < 16)
		return SC_ERROR_BUFFER_TOO_SMALL;

	sc_log(ctx, "IFD.RND %s", sc_dump_hex(session_data->ifd.rnd, 8));
	sc_log(ctx, "IFD.SN  %s", sc_dump_hex(session_data->ifd.sn, 8));
	sc_log(ctx, "IFD.K   %s", sc_dump_hex(session_data->ifd.k, 32));
	sc_log(ctx, "ICC.RND %s", sc_dump_hex(session_data->icc.rnd, 8));
	sc_log(ctx, "ICC.SN  %s", sc_dump_hex(session_data->icc.sn, 8));

	memcpy(out + 0, session_data->icc.rnd, 8);
	memcpy(out + 8, session_data->icc.sn, 8);

	return 16;
}


int
sm_cwa_encode_mutual_auth_data(struct sc_context *ctx, struct sm_cwa_session *session_data, 
		unsigned char *out, size_t out_len)
{
	if (out_len < 64)
		return SC_ERROR_BUFFER_TOO_SMALL;

	sc_log(ctx, "IFD.RND %s", sc_dump_hex(session_data->ifd.rnd, 8));
	sc_log(ctx, "IFD.SN  %s", sc_dump_hex(session_data->ifd.sn, 8));
	sc_log(ctx, "IFD.K   %s", sc_dump_hex(session_data->ifd.k, 32));
	sc_log(ctx, "ICC.RND %s", sc_dump_hex(session_data->icc.rnd, 8));
	sc_log(ctx, "ICC.SN  %s", sc_dump_hex(session_data->icc.sn, 8));

	memcpy(out + 0, session_data->ifd.rnd, 8);
	memcpy(out + 8, session_data->ifd.sn, 8);
	memcpy(out + 16, session_data->icc.rnd, 8);
	memcpy(out + 24, session_data->icc.sn, 8);
	memcpy(out + 32, session_data->ifd.k, 32);

	return 64;
}


static int
sm_iasecc_parse_authentication_data(struct sc_context *ctx, char *data, struct sm_card_response *resp)
{
	struct sc_asn1_entry asn1_iasecc_response[4], asn1_card_response[2];
	unsigned char *hex = NULL;
	size_t hex_len;
	int num, status, rv;

	LOG_FUNC_CALLED(ctx);
	if (!data || !resp)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "SM parse response: invalid input arguments");

	hex_len = strlen(data) / 2;
	hex = calloc(1, hex_len);
	if (!hex)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "SM parse response: hex allocate error");

	sc_log(ctx, "SM parse response:  hex length %i", hex_len);
	rv = sc_hex_to_bin(data, hex, &hex_len);
	LOG_TEST_RET(ctx, rv, "SM parse response:  data 'HEX to BIN' conversion error");

	sc_log(ctx, "SM parse response:  hex length %i", hex_len);

	sc_copy_asn1_entry(c_asn1_iasecc_response, asn1_iasecc_response);
	sc_copy_asn1_entry(c_asn1_card_response, asn1_card_response);

	sc_format_asn1_entry(asn1_iasecc_response + 0, &num, NULL, 0);
	sc_format_asn1_entry(asn1_iasecc_response + 1, &status, NULL, 0);
	resp->len = sizeof(resp->data);
	sc_format_asn1_entry(asn1_iasecc_response + 2, resp->data, &resp->len, 0);

	sc_format_asn1_entry(asn1_card_response + 0, asn1_iasecc_response, NULL, 0);

	rv = sc_asn1_decode(ctx, asn1_card_response, hex, hex_len, NULL, NULL);
	LOG_TEST_RET(ctx, rv, "IAS/ECC decode answer(s): ASN1 decode error");

	if (status != 0x9000)
		LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);

	free(hex);
	LOG_FUNC_RETURN(ctx, rv);
}


int
sm_iasecc_decode_authentication_data(struct sc_context *ctx, struct sm_cwa_keyset *keyset, 
		struct sm_cwa_session *session_data, char *auth_data)
{
	struct sm_card_response resp;
	struct sc_hash *hash = NULL;
	DES_cblock icv = {0, 0, 0, 0, 0, 0, 0, 0};
	DES_cblock cblock;
	unsigned char *decrypted = NULL;
	size_t decrypted_len;
	int rv; 

	LOG_FUNC_CALLED(ctx);
	memset(&resp, 0, sizeof(resp));
#if 0
	if (strstr(auth_data, "DATA="))   {
		rv = sc_hash_parse(ctx, auth_data, strlen(auth_data), &hash);
		LOG_TEST_RET(ctx, rv, "Decode authentication data: parse error");

		auth_data = sc_hash_get(hash, "DATA");
	}
#endif

	sc_log(ctx, "Decode authentication data: data %s", auth_data);
	rv = sm_iasecc_parse_authentication_data(ctx, auth_data, &resp);
	LOG_TEST_RET(ctx, rv, "sm_ecc_decode_auth_data() response parse error");

	sc_hash_free(hash);

	if (resp.len != 0x48)
		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "sm_ecc_decode_auth_data() invalid auth data");

	memset(icv, 0, sizeof(icv));
	rv = sm_cwa_get_mac(ctx, keyset->mac, &icv, resp.data, 0x40, &cblock, 1);
	LOG_TEST_RET(ctx, rv, "Decode authentication data:  sm_ecc_get_mac failed");
	sc_log(ctx, "MAC:%s", sc_dump_hex(cblock, sizeof(cblock)));

	if(memcmp(resp.data + 0x40, cblock, 8))
		LOG_FUNC_RETURN(ctx, SC_ERROR_SM_AUTHENTICATION_FAILED);

	rv = sm_decrypt_des_cbc3(ctx, keyset->enc, resp.data, resp.len, &decrypted, &decrypted_len);
	LOG_TEST_RET(ctx, rv, "sm_ecc_decode_auth_data() DES CBC3 decrypt error");

	sc_log(ctx, "sm_ecc_decode_auth_data() decrypted(%i) %s", decrypted_len, sc_dump_hex(decrypted, decrypted_len));

	if (memcmp(decrypted, session_data->icc.rnd, 8))
		LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);

	if (memcmp(decrypted + 8, session_data->icc.sn, 8))
		LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);

	if (memcmp(decrypted + 16, session_data->ifd.rnd, 8))
		LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);

	if (memcmp(decrypted + 24, session_data->ifd.sn, 8))
		LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);

	memcpy(session_data->icc.k, decrypted + 32, 32);

	free(decrypted);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
sm_iasecc_init_session_keys(struct sc_context *ctx, struct sm_cwa_session *session_data, 
		unsigned char mechanism)
{
	unsigned char xored[36];
	unsigned char buff[SHA256_DIGEST_LENGTH];
	int ii;

	memset(xored, 0, sizeof(xored));

	for (ii=0; ii<32; ii++)
		xored[ii] = session_data->ifd.k[ii] ^ session_data->icc.k[ii];

	sc_log(ctx, "K_IFD %s", sc_dump_hex(session_data->ifd.k, 32));
	sc_log(ctx, "K_ICC %s", sc_dump_hex(session_data->icc.k, 32));

	if (mechanism == IASECC_ALGORITHM_SYMMETRIC_SHA1)   {
		xored[35] = 0x01;
		sc_log(ctx, "XOR for SkEnc %s", sc_dump_hex(xored, 36));
		SHA1(xored, 36, buff);
		memcpy(&session_data->session_enc[0], buff, sizeof(session_data->session_enc));

		xored[35] = 0x02;
		sc_log(ctx, "XOR for SkMac %s", sc_dump_hex(xored, 36));
		SHA1(xored, 36, buff);
		memcpy(&session_data->session_mac[0], buff, sizeof(session_data->session_mac));
	}
	else if (mechanism == IASECC_ALGORITHM_SYMMETRIC_SHA256)   {
		xored[35] = 0x01;
		SHA256(xored, 36, buff);
		memcpy(&session_data->session_enc[0], buff, sizeof(session_data->session_enc));

		xored[35] = 0x02;
		SHA256(xored, 36, buff);
		memcpy(&session_data->session_mac[0], buff, sizeof(session_data->session_mac));
	}
	else   {
		return SC_ERROR_INVALID_ARGUMENTS; 
	}

	memcpy(session_data->ssc + 0, session_data->icc.rnd + 4, 4);
	memcpy(session_data->ssc + 4, session_data->ifd.rnd + 4, 4);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


void
sm_cwa_incr_ssc(struct sm_cwa_session *session_data)
{
	int ii;

	if (!session_data)
		return;

	for (ii=7; ii>=0; ii--)   {
		session_data->ssc[ii] += 1;
		if (session_data->ssc[ii])
			break;
	}
}


int 
sm_cwa_initialize(struct sc_context *ctx, struct sm_info *sm_info, char *out, size_t *out_len)
{
	struct sm_cwa_session *session_data = &sm_info->schannel.session.cwa;
	struct sm_cwa_keyset *keyset = &sm_info->schannel.keyset.cwa;
	struct sc_serial_number sn = sm_info->serialnr;
	int icc_sn_len = sizeof(session_data->icc.sn);
	unsigned char sbuf[0x100], *encrypted;
	size_t encrypted_len;
	DES_cblock icv = {0, 0, 0, 0, 0, 0, 0, 0}, cblock;
	int rv, offs;

	SC_FUNC_CALLED(ctx, 1);
	sc_log(ctx, "SM IAS/ECC initialize: serial %s", sc_dump_hex(sm_info->serialnr.value, sm_info->serialnr.len));
	sc_log(ctx, "SM IAS/ECC initialize: card challenge %s", sc_dump_hex(sm_info->schannel.card_challenge, 8));
	sc_log(ctx, "SM IAS/ECC initialize: current_df_path %s", sc_print_path(&sm_info->current_path_df));
	sc_log(ctx, "SM IAS/ECC initialize: CRT_AT reference 0x%X", sm_info->sm_params.cwa.crt_at.refs[0]);

	memcpy(&session_data->icc.rnd[0], sm_info->schannel.card_challenge, 8);

	if (sn.len > icc_sn_len)
		memcpy(&session_data->icc.sn[0], &sn.value[sn.len - icc_sn_len], icc_sn_len);
	else
		memcpy(&session_data->icc.sn[icc_sn_len - sn.len], &sn.value[0], sn.len);

	if (sm_info->cmd == SM_CMD_EXTERNAL_AUTH)   {
		offs = sm_cwa_encode_external_auth_data(ctx, session_data, sbuf, sizeof(sbuf));
		if (offs != 0x10)
			SC_FUNC_RETURN(ctx, 1, offs);
	}
	else   {
		offs = sm_cwa_encode_mutual_auth_data(ctx, session_data, sbuf, sizeof(sbuf));
		if (offs != 0x40)
			SC_FUNC_RETURN(ctx, 1, offs);
	}

	sc_log(ctx, "S(%i) %s", offs, sc_dump_hex(sbuf, offs));

	rv = sm_encrypt_des_cbc3(ctx, keyset->enc, sbuf, offs, &encrypted, &encrypted_len, 1);
	LOG_TEST_RET(ctx, rv, "_encrypt_des_cbc3() failed");

	sc_log(ctx, "ENCed(%i) %s", encrypted_len, sc_dump_hex(encrypted, encrypted_len));

	offs = 0;
	memcpy(sbuf + offs, encrypted, encrypted_len);
	offs += encrypted_len;

	rv = sm_cwa_get_mac(ctx, keyset->mac, &icv, sbuf, offs, &cblock, 1);
	LOG_TEST_RET(ctx, rv, "sm_ecc_get_mac() failed");
	sc_log(ctx, "MACed(%i) %s", sizeof(cblock), sc_dump_hex(cblock, sizeof(cblock)));

	if (sm_info->cmd == SM_CMD_EXTERNAL_AUTH)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "For a moment EXTERNAL AUTHENTICATION not supported");

	offs = 0;
	sbuf[offs++] = 0x00;
	sbuf[offs++] = 0x82;
	sbuf[offs++] = 0x00;
	sbuf[offs++] = 0x00;
	sbuf[offs++] = encrypted_len + sizeof(cblock);
	memcpy(sbuf + offs, encrypted, encrypted_len);
	offs += encrypted_len;
	memcpy(sbuf + offs, cblock, sizeof(cblock));
	offs += sizeof(cblock);

	free(encrypted);
	encrypted = NULL;

	if (out && out_len)   {
		char out_str[0x400];
		sprintf(out_str, "APDU00=%s;APDU00_GET_RESPONSE=YES;NN_APDUS=01;STATUS=SUCCESS", sc_dump_hex(sbuf, offs));

		if (*out_len < strlen(out_str) + 1)
			LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "sm_cwa_initialize() buffer too small for the MA data");

		strcpy(out, out_str);
		*out_len = strlen(out_str);
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
sm_cwa_securize_apdu(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_apdu *rapdu)
{
	struct sm_cwa_session *session_data = &sm_info->schannel.session.cwa;
	struct sc_apdu *apdu = &rapdu->apdu;
	unsigned char sbuf[0x400];
	DES_cblock cblock, icv;
	unsigned char *encrypted = NULL, edfb_data[0x200], mac_data[0x200];
	size_t encrypted_len, edfb_len = 0, mac_len = 0;
	int rv, offs;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "securize APDU (cla:%X,ins:%X,p1:%X,p2:%X,data(%i):%p)", 
			apdu->cla, apdu->ins, apdu->p1, apdu->p2, apdu->datalen, apdu->data);

	sm_cwa_incr_ssc(session_data);

	rv = sm_encrypt_des_cbc3(ctx, session_data->session_enc, apdu->data, apdu->datalen, &encrypted, &encrypted_len, 0);
	LOG_TEST_RET(ctx, rv, "securize APDU: DES CBC3 encryption failed");
	sc_log(ctx, "encrypted data (len:%i, %s)", encrypted_len, sc_dump_hex(encrypted, encrypted_len));

	offs = 0;
	if (apdu->ins & 0x01)   {
		edfb_data[offs++] = IASECC_SM_DO_TAG_TCG_ODD_INS;
		if (encrypted_len + 1 > 0x7F)
			edfb_data[offs++] = 0x81;
		edfb_data[offs++] = encrypted_len;
	}
	else   {
		edfb_data[offs++] = IASECC_SM_DO_TAG_TCG_EVEN_INS;
		if (encrypted_len + 1 > 0x7F)
			edfb_data[offs++] = 0x81;
		edfb_data[offs++] = encrypted_len + 1;
		edfb_data[offs++] = 0x01;
	}
	memcpy(edfb_data + offs, encrypted, encrypted_len);
	offs += encrypted_len;
	edfb_len = offs;
	sc_log(ctx, "securize APDU: EDFB(len:%i,%sà", edfb_len, sc_dump_hex(edfb_data, edfb_len));

	free(encrypted);
	encrypted = NULL;

	offs = 0;
	memcpy(mac_data + offs, session_data->ssc, 8);
	offs += 8;
	mac_data[offs++] = apdu->cla | 0x0C;
	mac_data[offs++] = apdu->ins;
	mac_data[offs++] = apdu->p1;
	mac_data[offs++] = apdu->p2;
	mac_data[offs++] = 0x80;
	mac_data[offs++] = 0x00;
	mac_data[offs++] = 0x00;
	mac_data[offs++] = 0x00;

	memcpy(mac_data + offs, edfb_data, edfb_len);
	offs += edfb_len;

	/* if (apdu->le)   { */
		mac_data[offs++] = IASECC_SM_DO_TAG_TLE;
		mac_data[offs++] = 1;
		mac_data[offs++] = apdu->le;
	/* } */

	mac_len = offs;
	sc_log(ctx, "securize APDU: MAC data(len:%i,%s)", mac_len, sc_dump_hex(mac_data, mac_len));

	memset(icv, 0, sizeof(icv));
	rv = sm_cwa_get_mac(ctx, session_data->session_mac, &icv, mac_data, mac_len, &cblock, 0);
	LOG_TEST_RET(ctx, rv, "securize APDU: MAC calculation error");
	sc_log(ctx, "securize APDU: MAC:%s", sc_dump_hex(cblock, sizeof(cblock)));

	offs = 0;
	if (edfb_len)   {
		memcpy(sbuf + offs, edfb_data, edfb_len);
		offs += edfb_len;
	}

	/* if (apdu->le)   { */
		sbuf[offs++] = IASECC_SM_DO_TAG_TLE;
		sbuf[offs++] = 1;
		sbuf[offs++] = apdu->le;
	/* } */

	sbuf[offs++] = IASECC_SM_DO_TAG_TCC;
	sbuf[offs++] = 8;
	memcpy(sbuf + offs, cblock, 8);
	offs += 8;
	sc_log(ctx, "securize APDU: SM data(len:%i,%s)", offs, sc_dump_hex(sbuf, offs));

	if (offs > sizeof(rapdu->sbuf))
		LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "securize APDU: buffer too small for encrypted data");

	apdu->cse = SC_APDU_CASE_4_SHORT;
	apdu->cla |= 0x0C;
	apdu->lc = offs;
	apdu->datalen = offs;
	memcpy((unsigned char *)apdu->data, sbuf, offs);

	sm_cwa_incr_ssc(session_data);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

#if 0
static int
sm_iasecc_get_apdu_read_binary(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_apdu **rapdus)
{
	struct sm_info_read_binary *rb = &sm_info->cmd_params.read_binary;
	size_t offs = rb->offset, size = rb->size;
	int rv = SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(ctx);
	while (size)   {
		int sz = size > SM_MAX_DATA_SIZE ? SM_MAX_DATA_SIZE : size;
		struct sc_remote_apdu *rapdu = NULL;

		sc_log(ctx, "SM get 'READ BINARY' APDUs: offset:%i,size:%i", offs, size);
		rv = sc_remote_apdu_allocate(rapdus, &rapdu);
		LOG_TEST_RET(ctx, rv, "SM get 'READ BINARY' APDUs: cannot allocate remote apdu");

		rapdu->apdu.cse = SC_APDU_CASE_2_SHORT;
		rapdu->apdu.cla = 0x00;
		rapdu->apdu.ins = 0xB0;
		rapdu->apdu.p1 = (offs>>8)&0xFF;
		rapdu->apdu.p2 = offs&0xFF;
		rapdu->apdu.resplen = sz;
		rapdu->apdu.le = sz;

		rv = sm_iasecc_securize_apdu(ctx, sm_info, rapdu);
		LOG_TEST_RET(ctx, rv, "SM get 'READ BINARY' APDUs: securize error");

		rapdu->get_response = 1;

		offs += sz;
		size -= sz;
	}
			
	LOG_FUNC_RETURN(ctx, rv);
}


static int
sm_iasecc_get_apdu_update_binary(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_apdu **rapdus)
{
	struct sm_info_update_binary *ub = &sm_info->cmd_params.update_binary;
	size_t offs = ub->offset, size = ub->size, data_offs = 0;
	int rv = SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM get 'UPDATE BINARY' APDUs: offset:%i,size:%i", offs, size);
	while (size)   {
		int sz = size > SM_MAX_DATA_SIZE ? SM_MAX_DATA_SIZE : size;
		struct sc_remote_apdu *rapdu = NULL;

		rv = sc_remote_apdu_allocate(rapdus, &rapdu);
		LOG_TEST_RET(ctx, rv, "SM get 'UPDATE BINARY' APDUs: cannot allocate remote apdu");

		rapdu->apdu.cse = SC_APDU_CASE_3_SHORT;
		rapdu->apdu.cla = 0x00;
		rapdu->apdu.ins = 0xD6;
		rapdu->apdu.p1 = (offs>>8)&0xFF;
		rapdu->apdu.p2 = offs&0xFF;
		memcpy((unsigned char *)rapdu->apdu.data, ub->data + data_offs, sz);
		rapdu->apdu.datalen = sz;
		rapdu->apdu.lc = sz;

		rv = sm_iasecc_securize_apdu(ctx, sm_info, rapdu);
		LOG_TEST_RET(ctx, rv, "SM get 'UPDATE BINARY' APDUs: securize error");

		rapdu->get_response = 1;

		offs += sz;
		data_offs += sz;
		size -= sz;
	}
			
	LOG_FUNC_RETURN(ctx, rv);
}


static int
sm_iasecc_get_apdu_create_file(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_apdu **rapdus)
{
	struct sm_info_create_file *cf = &sm_info->cmd_params.create_file;
	struct sc_remote_apdu *rapdu = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM get 'CREATE FILE' APDU: FCP(%i) %p", cf->fcp_len, cf->fcp);

	rv = sc_remote_apdu_allocate(rapdus, &rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'CREATE FILE' APDU: cannot allocate remote apdu");

	rapdu->apdu.cse = SC_APDU_CASE_3_SHORT;
	rapdu->apdu.cla = 0x00;
	rapdu->apdu.ins = 0xE0;
	rapdu->apdu.p1 = 0x00;
	rapdu->apdu.p2 = 0x00;
	memcpy((unsigned char *)rapdu->apdu.data, cf->fcp, cf->fcp_len);
	rapdu->apdu.datalen = cf->fcp_len;
	rapdu->apdu.lc = cf->fcp_len;

	rv = sm_iasecc_securize_apdu(ctx, sm_info, rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'CREATE FILE' APDU: securize error");

	rapdu->get_response = 1;

	LOG_FUNC_RETURN(ctx, rv);
}


static int
sm_iasecc_get_apdu_delete_file(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_apdu **rapdus)
{
	struct sm_info_delete_file *df = &sm_info->cmd_params.delete_file;
	struct sc_remote_apdu *rapdu = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM get 'DELETE FILE' APDU: file-id %04X", df->file_id);

	rv = sc_remote_apdu_allocate(rapdus, &rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'DELETE FILE' APDU: cannot allocate remote apdu");

	rapdu->apdu.cse = SC_APDU_CASE_1;
	rapdu->apdu.cla = 0x00;
	rapdu->apdu.ins = 0xE4;
	rapdu->apdu.p1 = 0x00;
	rapdu->apdu.p2 = 0x00;

	rv = sm_iasecc_securize_apdu(ctx, sm_info, rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'DELETE FILE' APDU: securize error");

	rapdu->get_response = 1;

	LOG_FUNC_RETURN(ctx, rv);
}


static int
sm_iasecc_get_apdu_verify_pin(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_apdu **rapdus)
{
	struct sm_info_pin_verify *pv = &sm_info->cmd_params.pin_verify;
	struct sc_remote_apdu *rapdu = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM get 'VERIFY PIN' APDU");

	rv = sc_remote_apdu_allocate(rapdus, &rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'VERIFY PIN' APDU: cannot allocate remote apdu");

	rapdu->apdu.cse = SC_APDU_CASE_3_SHORT;
	rapdu->apdu.cla = 0x00;
	rapdu->apdu.ins = 0x20;
	rapdu->apdu.p1 = 0x00;
	rapdu->apdu.p2 = pv->pin.reference;
	if (pv->pin.size > SM_MAX_DATA_SIZE)
		LOG_TEST_RET(ctx, rv, "SM get 'VERIFY PIN' APDU: invelid PIN size");

	memcpy((unsigned char *)rapdu->apdu.data, pv->pin.data, pv->pin.size);
	rapdu->apdu.datalen = pv->pin.size;
	rapdu->apdu.lc = pv->pin.size;

	rv = sm_iasecc_securize_apdu(ctx, sm_info, rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'VERIFY_PIN' APDU: securize error");

	rapdu->get_response = 1;

	LOG_FUNC_RETURN(ctx, rv);
}


static int
sm_iasecc_get_apdu_reset_pin(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_apdu **rapdus)
{
	struct sm_info_pin_reset *pr = &sm_info->cmd_params.pin_reset;
	struct sc_remote_apdu *rapdu = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM get 'RESET PIN' APDU");

	rv = sc_remote_apdu_allocate(rapdus, &rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'RESET PIN' APDU: cannot allocate remote apdu");

	rapdu->apdu.cse = SC_APDU_CASE_3_SHORT;
	rapdu->apdu.cla = 0x00;
	rapdu->apdu.ins = 0x2C;
	rapdu->apdu.p2 = pr->pin2.reference;
	if (pr->pin2.size)   {
		if (pr->pin2.size > SM_MAX_DATA_SIZE)
			LOG_TEST_RET(ctx, rv, "SM get 'RESET PIN' APDU: invelid PIN size");

		rapdu->apdu.p1 = 0x02;
		memcpy((unsigned char *)rapdu->apdu.data, pr->pin2.data, pr->pin2.size);
		rapdu->apdu.datalen = pr->pin2.size;
		rapdu->apdu.lc = pr->pin2.size;
	}
	else   {
		rapdu->apdu.p1 = 0x03;
	}

	rv = sm_iasecc_securize_apdu(ctx, sm_info, rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'RESET_PIN' APDU: securize error");

	rapdu->get_response = 1;

	LOG_FUNC_RETURN(ctx, rv);
}


static int
sm_iasecc_get_apdu_generate_rsa(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_apdu **rapdus)
{
	struct sm_info_rsa_generate *rg = &sm_info->cmd_params.rsa_generate;
	struct sc_remote_apdu *rapdu = NULL;
	unsigned char put_exponent_data[14] = { 
		0x70, 0x0C, 
			IASECC_SDO_TAG_HEADER, IASECC_SDO_CLASS_RSA_PUBLIC | 0x80, rg->reference & 0x7F, 0x08, 
					0x7F, 0x49, 0x05, 0x82, 0x03, 0x01, 0x00, 0x01 
	};
	unsigned char generate_data[5] = { 
		0x70, 0x03, 
			IASECC_SDO_TAG_HEADER, IASECC_SDO_CLASS_RSA_PRIVATE | 0x80, rg->reference & 0x7F
	};
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM get 'GENERATE RSA' APDU: SDO(class:%X,reference:%X)", rg->sdo_class, rg->reference);

	/* Put Exponent */
	rv = sc_remote_apdu_allocate(rapdus, &rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'GENERATE RSA(put exponent)' APDU: cannot allocate remote apdu");

	rapdu->apdu.cse = SC_APDU_CASE_3_SHORT;
	rapdu->apdu.cla = 0x00;
	rapdu->apdu.ins = 0xDB;
	rapdu->apdu.p1 = 0x3F;
	rapdu->apdu.p2 = 0xFF;
	memcpy((unsigned char *)rapdu->apdu.data, put_exponent_data, sizeof(put_exponent_data));
	rapdu->apdu.datalen = sizeof(put_exponent_data);
	rapdu->apdu.lc = sizeof(put_exponent_data);

	rv = sm_iasecc_securize_apdu(ctx, sm_info, rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'GENERATE RSA(put exponent)' APDU: securize error");

	rapdu->get_response = 1;

	/* Generate Key */
	rv = sc_remote_apdu_allocate(rapdus, &rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'GENERATE RSA' APDU: cannot allocate remote apdu");

	rapdu->apdu.cse = SC_APDU_CASE_4_SHORT;
	rapdu->apdu.cla = 0x00;
	rapdu->apdu.ins = 0x47;
	rapdu->apdu.p1 = 0x00;
	rapdu->apdu.p2 = 0x00;
	memcpy((unsigned char *)rapdu->apdu.data, generate_data, sizeof(generate_data));
	rapdu->apdu.datalen = sizeof(generate_data);
	rapdu->apdu.lc = sizeof(generate_data);
	rapdu->apdu.le = 0x100;

	rv = sm_iasecc_securize_apdu(ctx, sm_info, rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'GENERATE RSA' APDU: securize error");

	rapdu->get_response = 1;

	LOG_FUNC_RETURN(ctx, rv);
}


static int
sm_iasecc_get_apdu_update_rsa(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_apdu **rapdus)
{
	struct sm_info_iasecc_rsa_update *iru = &sm_info->cmd_params.iasecc_rsa_update;
	struct sc_iasecc_sdo_rsa_update *ru = iru->data;
	struct sc_iasecc_sdo_update *to_update[2];
	struct sc_remote_apdu *rapdu = NULL;
	int rv, ii, jj;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM get 'UPDATE RSA' APDU: SDO(class:%X,reference:%X)", iru->sdo_class, iru->reference);
	if (ru->magic != IASECC_SDO_MAGIC_UPDATE_RSA)
		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "SM get 'UPDATE RSA' APDU: invalid magic");

	to_update[0] = &ru->update_prv;
	to_update[1] = &ru->update_pub;
	for (jj=0;jj<2;jj++)   {
		for (ii=0; to_update[jj]->fields[ii].tag && ii < IASECC_SDO_TAGS_UPDATE_MAX; ii++)   {
			unsigned char *encoded = NULL;
			size_t encoded_len, offs;

			sc_log(ctx, "SM get 'UPDATE RSA' APDU: comp %i:%i, SDO(class:%02X%02X)", jj, ii, 
					iru->sdo_class, iru->reference);
			encoded_len = iasecc_sdo_encode_update_field(ctx, to_update[jj]->sdo_class, to_update[jj]->sdo_ref,
						&to_update[jj]->fields[ii], &encoded);
			LOG_TEST_RET(ctx, encoded_len, "SM get 'UPDATE RSA' APDU: cannot encode key component");
			
			sc_log(ctx, "SM IAS/ECC get APDUs: component(num:%i:%i,class:%X,ref:%X,%s)", jj, ii,
					to_update[jj]->sdo_class, to_update[jj]->sdo_ref,
					sc_dump_hex(encoded, encoded_len));

			for (offs = 0; offs < encoded_len; )   {
				int len = encoded_len - offs > SM_MAX_DATA_SIZE ? SM_MAX_DATA_SIZE : encoded_len - offs;

				rv = sc_remote_apdu_allocate(rapdus, &rapdu);
				LOG_TEST_RET(ctx, rv, "SM get 'UPDATE RSA' APDU: cannot allocate remote apdu");

				rapdu->apdu.cse = SC_APDU_CASE_3_SHORT;
				rapdu->apdu.cla = len + offs < encoded_len ? 0x10 : 0x00;
				rapdu->apdu.ins = 0xDB;
				rapdu->apdu.p1 = 0x3F;
				rapdu->apdu.p2 = 0xFF;
				memcpy((unsigned char *)rapdu->apdu.data, encoded + offs, len);
				rapdu->apdu.datalen = len;
				rapdu->apdu.lc = len;

				rv = sm_iasecc_securize_apdu(ctx, sm_info, rapdu);
				LOG_TEST_RET(ctx, rv, "SM get 'UPDATE RSA' APDU: securize error");

				rapdu->get_response = 1;

				offs += len;
			}
			free(encoded);
		}
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
sm_iasecc_get_apdu_pso_dst(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_apdu **rapdus)
{
	struct sm_info_iasecc_pso_dst *ipd = &sm_info->cmd_params.iasecc_pso_dst;
	struct sc_remote_apdu *rapdu = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM get 'PSO DST' APDU");

	if (ipd->pso_data_len > SM_MAX_DATA_SIZE)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	rv = sc_remote_apdu_allocate(rapdus, &rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'PSO HASH' APDU: cannot allocate remote apdu");

	rapdu->apdu.cse = SC_APDU_CASE_3_SHORT;
	rapdu->apdu.cla = 0x00;
	rapdu->apdu.ins = 0x2A;
	rapdu->apdu.p1 = 0x90;
	rapdu->apdu.p2 = 0xA0;
	memcpy((unsigned char *)rapdu->apdu.data, ipd->pso_data, ipd->pso_data_len);
	rapdu->apdu.datalen = ipd->pso_data_len;
	rapdu->apdu.lc = ipd->pso_data_len;

	rv = sm_iasecc_securize_apdu(ctx, sm_info, rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'PSO HASH' APDU: securize error");

	rapdu->get_response = 1;

	rv = sc_remote_apdu_allocate(rapdus, &rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'PSO DST' APDU: cannot allocate remote apdu");

	rapdu->apdu.cse = SC_APDU_CASE_2_SHORT;
	rapdu->apdu.cla = 0x00;
	rapdu->apdu.ins = 0x2A;
	rapdu->apdu.p1 = 0x9E;
	rapdu->apdu.p2 = 0x9A;
	rapdu->apdu.le = ipd->key_size;

	rv = sm_iasecc_securize_apdu(ctx, sm_info, rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'PSO DST' APDU: securize error");

	rapdu->get_response = 1;


	LOG_FUNC_RETURN(ctx, rv);
}


static int
sm_iasecc_get_apdu_raw_apdu(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_apdu **rapdus)
{
	struct sc_apdu *apdu = sm_info->cmd_params.raw_apdu.apdu;
	size_t data_offs, data_len = apdu->datalen;
	int rv = SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM get 'RAW APDU' APDU");

	data_offs = 0;
	data_len = apdu->datalen;
	for (; data_len; )   {
		int sz = data_len > SM_MAX_DATA_SIZE ? SM_MAX_DATA_SIZE : data_len;
		struct sc_remote_apdu *rapdu = NULL;

		rv = sc_remote_apdu_allocate(rapdus, &rapdu);
		LOG_TEST_RET(ctx, rv, "SM get 'RAW APDU' APDUs: cannot allocate remote apdu");

		rapdu->apdu.cse = apdu->cse;
		rapdu->apdu.cla = apdu->cla | ((data_offs + sz) < data_len ? 0x10 : 0x00);
		rapdu->apdu.ins = apdu->ins;
		rapdu->apdu.p1 = apdu->p1;
		rapdu->apdu.p2 = apdu->p2;
		memcpy((unsigned char *)rapdu->apdu.data, apdu->data + data_offs, sz);
		rapdu->apdu.datalen = sz;
		rapdu->apdu.lc = sz;

		rv = sm_iasecc_securize_apdu(ctx, sm_info, rapdu);
		LOG_TEST_RET(ctx, rv, "SM get 'UPDATE BINARY' APDUs: securize error");

		rapdu->get_response = 1;

		data_offs += sz;
		data_len -= sz;
	}
			
	LOG_FUNC_RETURN(ctx, rv);
}
#endif

int
sm_iasecc_get_apdus(struct sc_context *ctx, struct sm_info *sm_info, 
	       unsigned char *init_data, size_t init_len, struct sc_remote_data *rdata, int release_sm)
{
	struct sm_cwa_session *session_data = &sm_info->schannel.session.cwa;
	struct sm_cwa_keyset *keyset = &sm_info->schannel.keyset.cwa;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (!sm_info)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "SM IAS/ECC get APDUs: init_data:%s", init_data);
	sc_log(ctx, "SM IAS/ECC get APDUs: rdata:%p", rdata);
	sc_log(ctx, "SM IAS/ECC get APDUs: serial %s", sc_dump_hex(sm_info->serialnr.value, sm_info->serialnr.len));

	rv = sm_iasecc_decode_authentication_data(ctx, keyset, session_data, init_data);
	LOG_TEST_RET(ctx, rv, "SM IAS/ECC get APDUs: decode authentication data error");

	rv = sm_iasecc_init_session_keys(ctx, session_data, sm_info->sm_params.cwa.crt_at.algo);
	LOG_TEST_RET(ctx, rv, "SM IAS/ECC get APDUs: cannot get session keys");

	sc_log(ctx, "SKENC %s", sc_dump_hex(session_data->session_enc, sizeof(session_data->session_enc)));
	sc_log(ctx, "SKMAC %s", sc_dump_hex(session_data->session_mac, sizeof(session_data->session_mac)));
	sc_log(ctx, "SSC   %s", sc_dump_hex(session_data->ssc, sizeof(session_data->ssc)));

	switch (sm_info->cmd)  {
#if 0
	case SM_CMD_FILE_READ:
		rv = sm_iasecc_get_apdu_read_binary(ctx, sm_info, &rapdus);
		LOG_TEST_RET(ctx, rv, "SM IAS/ECC get APDUs: 'READ BINARY' failed");
		break;
	case SM_CMD_FILE_UPDATE:
		rv = sm_iasecc_get_apdu_update_binary(ctx, sm_info, &rapdus);
		LOG_TEST_RET(ctx, rv, "SM IAS/ECC get APDUs: 'UPDATE BINARY' failed");
		break;
	case SM_CMD_FILE_CREATE:
		rv = sm_iasecc_get_apdu_create_file(ctx, sm_info, &rapdus);
		LOG_TEST_RET(ctx, rv, "SM IAS/ECC get APDUs: 'CREATE FILE' failed");
		break;
	case SM_CMD_FILE_DELETE:
		rv = sm_iasecc_get_apdu_delete_file(ctx, sm_info, &rapdus);
		LOG_TEST_RET(ctx, rv, "SM IAS/ECC get APDUs: 'CREATE FILE' failed");
		break;
	case SM_CMD_PIN_RESET:
		rv = sm_iasecc_get_apdu_reset_pin(ctx, sm_info, &rapdus);
		LOG_TEST_RET(ctx, rv, "SM IAS/ECC get APDUs: 'RESET PIN' failed");
		break;
	case SM_CMD_RSA_GENERATE:
		rv = sm_iasecc_get_apdu_generate_rsa(ctx, sm_info, &rapdus);
		LOG_TEST_RET(ctx, rv, "SM IAS/ECC get APDUs: 'GENERATE RSA' failed");
		break;
	case SM_CMD_RSA_UPDATE:
		rv = sm_iasecc_get_apdu_update_rsa(ctx, sm_info, &rapdus);
		LOG_TEST_RET(ctx, rv, "SM IAS/ECC get APDUs: 'UPDATE RSA' failed");
		break;
	case SM_CMD_PSO_DST:
		rv = sm_iasecc_get_apdu_pso_dst(ctx, sm_info, &rapdus);
		LOG_TEST_RET(ctx, rv, "SM IAS/ECC get APDUs: 'PSO DST' failed");
		break;
	case SM_CMD_APDU_RAW:
		rv = sm_iasecc_get_apdu_raw_apdu(ctx, sm_info, &rapdus);
		LOG_TEST_RET(ctx, rv, "SM IAS/ECC get APDUs: 'RAW APDU' failed");
		break;
	case SM_CMD_PIN_VERIFY:
		rv = sm_iasecc_get_apdu_verify_pin(ctx, sm_info, &rapdus);
		LOG_TEST_RET(ctx, rv, "SM IAS/ECC get APDUs: 'RAW APDU' failed");
		break;
#endif
	default:
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "unsupported SM command");
	}

	if (release_sm)   {
		/* Apparently useless for this card */
	}

	LOG_FUNC_RETURN(ctx, rv);
}


int 
sm_iasecc_decode_card_data(struct sc_context *ctx, struct sm_info *sm_info, char *str_data, 
		unsigned char *out, size_t out_len)
{
#if 0
	struct sm_cwa_session *session_data = &sm_info->schannel.session.cwa;
	struct sc_asn1_entry asn1_iasecc_sm_data_object[4], asn1_iasecc_sm_response[4], asn1_card_response[2];
	struct sc_hash *hash = NULL;
	unsigned char *hex = NULL;
	size_t hex_len, len_left;
	int rv, offs;

	LOG_FUNC_CALLED(ctx);

	if (!out || !out_len)
		LOG_FUNC_RETURN(ctx, 0);

	sc_log(ctx, "IAS/ECC decode answer(s): out length %i", out_len);
	if (strstr(str_data, "DATA="))   {
		rv = sc_hash_parse(ctx, str_data, strlen(str_data), &hash);
		LOG_TEST_RET(ctx, rv, "IAS/ECC decode answer(s): parse error");

		str_data = sc_hash_get(hash, "DATA");
	}

	if (!strlen(str_data))
		LOG_FUNC_RETURN(ctx, 0);

	hex_len = strlen(str_data) / 2;
	hex = calloc(1, hex_len);
	if (!hex)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "IAS/ECC decode answer(s): hex allocate error");

	rv = sc_hex_to_bin(str_data, hex, &hex_len);
	LOG_TEST_RET(ctx, rv, "IAS/ECC decode answer(s): data 'HEX to BIN' conversion error");
	sc_log(ctx, "IAS/ECC decode answer(s): hex length %i", hex_len);

	if (hash)
		sc_hash_free(hash);
	
	for (offs = 0, len_left = hex_len; len_left; )   {
                unsigned char *decrypted;
                size_t decrypted_len;
		unsigned char card_data[SC_MAX_APDU_BUFFER_SIZE], command_status[2];
		size_t card_data_len = sizeof(card_data), command_status_len = sizeof(command_status); 
		unsigned char ticket[8];
		size_t ticket_len = sizeof(ticket); 
		int num, status;

		sc_copy_asn1_entry(c_asn1_iasecc_sm_data_object, asn1_iasecc_sm_data_object);
		sc_copy_asn1_entry(c_asn1_iasecc_sm_response, asn1_iasecc_sm_response);
		sc_copy_asn1_entry(c_asn1_card_response, asn1_card_response);

		sc_format_asn1_entry(asn1_iasecc_sm_data_object + 0, card_data, &card_data_len, 0);
		sc_format_asn1_entry(asn1_iasecc_sm_data_object + 1, command_status, &command_status_len, 0);
		sc_format_asn1_entry(asn1_iasecc_sm_data_object + 2, ticket, &ticket_len, 0);

		sc_format_asn1_entry(asn1_iasecc_sm_response + 0, &num, NULL, 0);
		sc_format_asn1_entry(asn1_iasecc_sm_response + 1, &status, NULL, 0);
		sc_format_asn1_entry(asn1_iasecc_sm_response + 2, asn1_iasecc_sm_data_object, NULL, 0);

		sc_format_asn1_entry(asn1_card_response + 0, asn1_iasecc_sm_response, NULL, 0);

        	rv = sc_asn1_decode(ctx, asn1_card_response, hex + hex_len - len_left, len_left, NULL, &len_left);
		LOG_TEST_RET(ctx, rv, "IAS/ECC decode answer(s): ASN1 decode error");

		if (status != 0x9000)
			continue;

		if (asn1_iasecc_sm_data_object[0].flags & SC_ASN1_PRESENT)   {
			if (*card_data != 0x01)
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "IAS/ECC decode answer(s): invalid encrypted data format");

			decrypted_len = sizeof(decrypted);	
			rv = sm_decrypt_des_cbc3(ctx, session_data->session_enc, card_data + 1, card_data_len - 1, 
					&decrypted, &decrypted_len);
			LOG_TEST_RET(ctx, rv, "IAS/ECC decode answer(s): cannot decrypt card answer data");

			while(*(decrypted + decrypted_len - 1) == 0x00)
			       decrypted_len--;

			if (*(decrypted + decrypted_len - 1) != 0x80)
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "IAS/ECC decode answer(s): invalid card data padding ");

			decrypted_len--;

			if (out_len < offs + decrypted_len)
				LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "IAS/ECC decode answer(s): unsufficient output buffer size");

			memcpy(out + offs, decrypted, decrypted_len);
			offs += decrypted_len;
			sc_log(ctx, "IAS/ECC decode card answer(s): decrypted_len:%i, offs:%i", decrypted_len, offs);

			free(decrypted);
		}

		sc_log(ctx, "IAS/ECC decode card answer(s): decode answer: length left %i", len_left);
	}

	free(hex);
	LOG_FUNC_RETURN(ctx, offs);
#else
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
#endif
}
