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


int
iasecc_sm_external_authentication(struct sc_card *card, unsigned skey_ref, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sm_info *sm_info = &card->sm_ctx.info;
	struct sc_cmd_ext_auth *ext_auth = &sm_info->cmd_params.ext_auth;
	unsigned char mbuf[SC_MAX_APDU_BUFFER_SIZE*4], rbuf[SC_MAX_APDU_BUFFER_SIZE*4], tbuf[SC_MAX_APDU_BUFFER_SIZE*4];
	size_t mbuf_len = sizeof(mbuf), rbuf_len = sizeof(rbuf), tbuf_len = sizeof(rbuf);
	struct sc_remote_data rdata;
	struct sc_apdu apdu;
	unsigned char sbuf[0x100];
	int rv, offs;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_sm_external_authentication(): SKey ref %i", skey_ref);

	sm_info->cmd = SM_CMD_EXTERNAL_AUTH;
	sm_info->serialnr = card->serialnr;
	sm_info->card_type = card->type;
	sm_info->sm_type = SM_TYPE_CWA14890;
	ext_auth->skey_ref = skey_ref;

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

	rv = sc_get_challenge(card, ext_auth->challenge, sizeof(ext_auth->challenge));
	LOG_TEST_RET(ctx, rv, "iasecc_sm_external_authentication(): set SE error");

	sc_remote_data_init(&rdata);
        rv = card->sm_ctx.module.ops.initialize(ctx, sm_info, &rdata);
        LOG_TEST_RET(ctx, rv, "SM: INITIALIZE failed");

#if 0
	rv = sm_iasecc_initialize (card, &sm_info, mdata, &mdata_len);
	LOG_TEST_RET(ctx, rv, "sm_iasecc_external_authentication(): init failed");

	sc_log(ctx, "sm_iasecc_external_authentication() mdata(%i) '%s'\n", mdata_len, mdata);

	rv = sm_execute (card, &sm_info, mdata, mdata_len, rdata, &rdata_len);
	if (rv)   {
		sm_info.status = rv;
		iasecc_sm_release (card, &sm_info, NULL, 0);
		LOG_TEST_RET(ctx, rv, "iasecc_sm_pin_reset(): execute failed");
	}

	rv = iasecc_sm_release (card, &sm_info, rdata, rdata_len);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_pin_reset(): release failed");

	LOG_FUNC_RETURN(ctx, rv);
#else
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
#endif
}

