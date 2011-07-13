/*
 * iasecc.h Support for IAS/ECC smart cards
 *
 * Copyright (C) 2010  Viktor Tarasov <vtarasov@opentrust.com>
 *                      OpenTrust <www.opentrust.com>
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

#include <string.h>
#include <stdlib.h>

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"

#ifndef ENABLE_OPENSSL
#error "Need OpenSSL"
#endif

#include "sm.h"
#include "iasecc.h"
#include "authentic.h"

static int
iasecc_sm_execute(struct sc_card *card, struct sc_remote_data *rdata,
		unsigned char *out, size_t *out_len)
{
	struct sc_context *ctx = card->ctx;
#ifdef ENABLE_SM	
	struct sc_remote_apdu *rapdu = rdata->data;
	int rv = SC_SUCCESS;

	LOG_FUNC_CALLED(ctx);
	while (rapdu)   {
		rv = sc_transmit_apdu(card, &rapdu->apdu);
        	LOG_TEST_RET(ctx, rv, "iasecc_sm_execute() failed to execute r-APDU");
		rv = sc_check_sw(card, rapdu->apdu.sw1, rapdu->apdu.sw2);
		if (rv < 0 && !(rapdu->apdu.flags & SC_REMOTE_APDU_FLAG_NOT_FATAL))
			LOG_TEST_RET(ctx, rv, "iasecc_sm_execute() fatal error %i");

		if (out && out_len && rapdu->apdu.flags & SC_REMOTE_APDU_FLAG_RETURN_ANSWER)   {
			/* TODO: decode and gather data answers */
		}

		rapdu = rapdu->next;
	}
	LOG_FUNC_RETURN(ctx, rv);
#else
	LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "built without support of SM and External Authentication");
#endif
}


int
iasecc_sm_external_authentication(struct sc_card *card, unsigned skey_ref, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
#ifdef ENABLE_SM	
	struct sm_info *sm_info = &card->sm_ctx.info;
	unsigned char mbuf[SC_MAX_APDU_BUFFER_SIZE*4], rbuf[SC_MAX_APDU_BUFFER_SIZE*4], tbuf[SC_MAX_APDU_BUFFER_SIZE*4];
	size_t mbuf_len = sizeof(mbuf), rbuf_len = sizeof(rbuf), tbuf_len = sizeof(rbuf);
	struct sc_remote_data rdata;
	struct sc_apdu apdu;
	unsigned char sbuf[0x100];
	int rv, offs;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_sm_external_authentication(): SKey ref %i", skey_ref);

	strncpy(sm_info->config_section, card->sm_ctx.config_section, sizeof(sm_info->config_section));
	sm_info->cmd = SM_CMD_EXTERNAL_AUTH;
	sm_info->serialnr = card->serialnr;
	sm_info->card_type = card->type;
	sm_info->sm_type = SM_TYPE_CWA14890;
	sm_info->sm_params.cwa.crt_at.usage = IASECC_UQB_AT_EXTERNAL_AUTHENTICATION;
	sm_info->sm_params.cwa.crt_at.algo = IASECC_ALGORITHM_ROLE_AUTH;
	sm_info->sm_params.cwa.crt_at.refs[0] = skey_ref;

	offs = 0;
	sbuf[offs++] = IASECC_CRT_TAG_ALGO;
	sbuf[offs++] = 0x01;
	sbuf[offs++] = IASECC_ALGORITHM_ROLE_AUTH;
	sbuf[offs++] = IASECC_CRT_TAG_REFERENCE;
	sbuf[offs++] = 0x01;
	sbuf[offs++] = skey_ref;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x81, 0xA4);
	apdu.data = sbuf;
	apdu.datalen = offs;
	apdu.lc = offs;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_external_authentication(): APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_external_authentication(): set SE error");

	rv = sc_get_challenge(card, sm_info->schannel.card_challenge, sizeof(sm_info->schannel.card_challenge));
	LOG_TEST_RET(ctx, rv, "iasecc_sm_external_authentication(): set SE error");

	sc_remote_data_init(&rdata);
        rv = card->sm_ctx.module.ops.initialize(ctx, sm_info, &rdata);
        LOG_TEST_RET(ctx, rv, "SM: INITIALIZE failed");

	sc_log(ctx, "sm_iasecc_external_authentication(): rdata length %i\n", rdata.length);

	rv = iasecc_sm_execute (card, &rdata, NULL, 0);
	LOG_TEST_RET(ctx, rv, "sm_iasecc_external_authentication(): execute failed");

	LOG_FUNC_RETURN(ctx, rv);
#else
	LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "builded without support of SM and External Authentication");
#endif
}

