/*
 * minidriver.c: OpenSC minidriver
 *
 * Copyright (C) 2009,2010 francois.leblanc@cev-sa.com
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

/*
 * This module requires "cardmod.h" from CNG SDK or platform SDK to build.
 */

#include "config.h"
#ifdef ENABLE_MINIDRIVER

#ifdef _MANAGED
#pragma managed(push, off)
#endif

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <windows.h>
#include "cardmod.h"

#include "libopensc/cardctl.h"
#include "libopensc/opensc.h"
#include "libopensc/pkcs15.h"
#include "libopensc/log.h"
#include "libopensc/internal.h"
#include "pkcs15init/pkcs15-init.h"

#if defined(__MINGW32__)
/* Part of the build svn project in the include directory */
#include "cardmod-mingw-compat.h"
#endif

#define NULLSTR(a) (a == NULL ? "<NULL>" : a)
#define NULLWSTR(a) (a == NULL ? L"<NULL>" : a)

#define MD_MAX_KEY_CONTAINERS 12
#define MD_CARDID_SIZE 16

#define MD_KEY_USAGE_SIGNATURE 			\
	SC_PKCS15INIT_X509_DIGITAL_SIGNATURE	| \
	SC_PKCS15INIT_X509_KEY_CERT_SIGN	| \
	SC_PKCS15INIT_X509_CRL_SIGN
#define MD_KEY_USAGE_KEYEXCHANGE 		\
	SC_PKCS15INIT_X509_KEY_ENCIPHERMENT	| \
	SC_PKCS15INIT_X509_DATA_ENCIPHERMENT
#define MD_KEY_ACCESS 				\
	SC_PKCS15_PRKEY_ACCESS_SENSITIVE	| \
	SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE	| \
	SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE	| \
	SC_PKCS15_PRKEY_ACCESS_LOCAL
		
/* if use of internal-winscard.h */
#ifndef SCARD_E_INVALID_PARAMETER
#define SCARD_E_INVALID_PARAMETER		0x80100004L
#define SCARD_E_UNSUPPORTED_FEATURE		0x80100022L
#define SCARD_E_NO_MEMORY				0x80100006L
#define SCARD_W_WRONG_CHV				0x8010006BL
#define SCARD_E_FILE_NOT_FOUND			0x80100024L
#define SCARD_E_UNKNOWN_CARD			0x8010000DL
#define SCARD_F_UNKNOWN_ERROR			0x80100014L
#endif

struct md_directory {
	unsigned char parent[9];
	unsigned char name[9];
	CARD_DIRECTORY_ACCESS_CONDITION acl;
	
	struct md_file *files;
	struct md_directory *subdirs;

	struct md_directory *next;
};

struct md_file {
	unsigned char parent[9];
	unsigned char name[9];
	size_t size;
	CARD_FILE_ACCESS_CONDITION acl;
	unsigned char *blob;

	struct md_file *next;
};

typedef struct _VENDOR_SPECIFIC
{
	char *pin;

	sc_pkcs15_object_t *cert_objs[32];
	int cert_count;
	sc_pkcs15_object_t *prkey_objs[32];
	int prkey_count;
	sc_pkcs15_object_t *pin_objs[8];
	int pin_count;

	sc_context_t *ctx;
	sc_reader_t *reader;
	sc_card_t *card;
	sc_pkcs15_card_t *p15card;

	struct sc_pkcs15_object *generated_key;


	struct md_directory root;

	SCARDCONTEXT hSCardCtx;
	SCARDHANDLE hScard;

}VENDOR_SPECIFIC;

static int associate_card(PCARD_DATA pCardData);
static int disassociate_card(PCARD_DATA pCardData);

static void logprintf(PCARD_DATA pCardData, int level, const char* format, ...)
{
	va_list arg;
	VENDOR_SPECIFIC *vs;
#define CARDMOD_LOW_LEVEL_DEBUG 1
#ifdef CARDMOD_LOW_LEVEL_DEBUG
/* Use a simplied log to get all messages including messages
 * before opensc is loaded. The file must be modifiable by all
 * users as we maybe called under lsa or user. Note data from
 * multiple process and threads may get intermingled.
 * flush to get last message before ann crash
 * close so as the file is not left open during any wait.
 */
	{
		FILE* lldebugfp = NULL;

		lldebugfp = fopen("C:\\tmp\\md.log","a+");
		if (lldebugfp)   {
			va_start(arg, format);
			vfprintf(lldebugfp, format, arg);
			va_end(arg);
			fflush(lldebugfp);
			fclose(lldebugfp);
			lldebugfp = NULL;
		}
	}
#endif

	va_start(arg, format);
	if(pCardData != NULL)   {
		vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
		if(vs != NULL && vs->ctx != NULL)   {
#ifdef _MSC_VER
			sc_do_log_noframe(vs->ctx, level, format, arg);
#else
			/* FIXME: trouble in vsprintf with %S arg under mingw32 */
			if(vs->ctx->debug>=level) {
				vfprintf(vs->ctx->debug_file, format, arg);
			}
#endif
		}
	}
	va_end(arg);
}

static void loghex(PCARD_DATA pCardData, int level, PBYTE data, int len)
{
	char line[74];
	char *c;
	int i, a;
	unsigned char * p;

	logprintf(pCardData, level, "--- %p:%d\n", data, len);

	if (data == NULL || len <= 0) return;

	p = data;
	c = line;
	i = 0;
	a = 0;
	memset(line, 0, sizeof(line));

	while(i < len) {
		sprintf(c,"%02X", *p);
		p++;
		c += 2;
		i++;
		if (i%32 == 0) {
			logprintf(pCardData, level, " %04X  %s\n", a, line);
			a +=32;
			memset(line, 0, sizeof(line));
			c = line;
		} else {
			if (i%4 == 0) *(c++) = ' ';
			if (i%16 == 0) *(c++) = ' ';
		}
	}
	if (i%32 != 0)
		logprintf(pCardData, level, " %04X  %s\n", a, line);
}

static void print_werror(PCARD_DATA pCardData, char *str)
{
	void *buf;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
	  FORMAT_MESSAGE_FROM_SYSTEM |
	  FORMAT_MESSAGE_IGNORE_INSERTS,
	  NULL,GetLastError(),0,
	  (LPTSTR) &buf,0,NULL);

	logprintf(pCardData, 0, "%s%s\n", str, buf);
	LocalFree(buf);
}

/*
 * check if the card has been removed, or the
 * caller has changed the handles.
 * if so, then free up all previous card info
 * and reestablish
 */
static int 
check_reader_status(PCARD_DATA pCardData) 
{
	int r;
	VENDOR_SPECIFIC *vs = NULL;

	logprintf(pCardData, 4, "check_reader_status\n");
	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if(!vs)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 7, "pCardData->hSCardCtx:0x%08X hScard:0x%08X\n",
			pCardData->hSCardCtx, pCardData->hScard);

	if (pCardData->hSCardCtx != vs->hSCardCtx || pCardData->hScard != vs->hScard) {
		logprintf (pCardData, 1, "HANDLES CHANGED from 0x%08X 0x%08X\n", vs->hSCardCtx, vs->hScard);

		r = disassociate_card(pCardData);
		logprintf(pCardData, 1, "disassociate_card r = 0x%08X\n");
		r = associate_card(pCardData); /* need to check return codes */
		logprintf(pCardData, 1, "associate_card r = 0x%08X\n");
	} 
	else if (vs->reader) {
		/* This should always work, as BaseCSP should be checking for removal too */
		r = sc_detect_card_presence(vs->reader);
		logprintf(pCardData, 2, "check_reader_status r=%d flags 0x%08X\n",
			r, vs->reader->flags);
	}

	return SCARD_S_SUCCESS;
}


/*
 * Compute modulus length
 */
static size_t compute_keybits(sc_pkcs15_bignum_t *bn)
{
	unsigned int mask, bits;

	if (!bn || !bn->len)
		return 0;
	bits = bn->len << 3;
	for (mask = 0x80; !(bn->data[0] & mask); mask >>= 1)
		bits--;
	return bits;
}


static DWORD 
get_pin_by_role(PCARD_DATA pCardData, PIN_ID role, struct sc_pkcs15_object **ret_obj)
{
	VENDOR_SPECIFIC *vs;
	int i;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 2, "get PIN with role %i\n", role);

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (vs->pin_count == 0)   {
		logprintf(pCardData, 2, "cannot get PIN object: no PIN defined\n");
		return SCARD_E_UNSUPPORTED_FEATURE;
	}

	if (!ret_obj)
		return SCARD_E_INVALID_PARAMETER;

	*ret_obj = NULL;

	for(i = 0; i < vs->pin_count; i++)
	{
		struct sc_pkcs15_object *obj = vs->pin_objs[i];
		struct sc_pkcs15_auth_info *auth_info = (struct sc_pkcs15_auth_info *) (obj->data);
		unsigned int pin_flags = auth_info->attrs.pin.flags;
		unsigned int admin_pin_flags = SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN | SC_PKCS15_PIN_FLAG_SO_PIN;

		logprintf(pCardData, 2, "PIN[%s] flags 0x%X\n", obj->label, pin_flags);
		if (role == ROLE_USER)   {
			if (!(pin_flags & admin_pin_flags))   {
				*ret_obj = obj;
				break;
			}
		}
		else if (role == ROLE_ADMIN)   {
			if (pin_flags & admin_pin_flags)   {
				*ret_obj = obj;
				break;
			}
		}
		else   {
			logprintf(pCardData, 2, "cannot get PIN object: unsupported role\n");
			return SCARD_E_UNSUPPORTED_FEATURE;
		}
	}

	if (i == vs->pin_count)   {
		logprintf(pCardData, 2, "cannot get PIN object: not found\n");
		return SCARD_E_UNSUPPORTED_FEATURE;
	}

	return SCARD_S_SUCCESS;
}

static void dump_objects (PCARD_DATA pCardData)
{
	VENDOR_SPECIFIC *vs;
	sc_pkcs15_prkey_info_t *prkey_info;
	sc_pkcs15_cert_t *cert;
	int i;

	if (!pCardData)
		return;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		return;

	for(i = 0; i < vs->prkey_count; i++)   {
		prkey_info = (sc_pkcs15_prkey_info_t*)(vs->prkey_objs[i]->data);
		logprintf(pCardData, 5, "prkey_info->subject %d (subject_len=%d) modulus_length=%d", 
				i, prkey_info->subject.len, prkey_info->modulus_length);
		loghex(pCardData, 5, prkey_info->subject.value, prkey_info->subject.len);
	}

	for(i = 0; i < vs->cert_count; i++)   {
		sc_pkcs15_read_certificate(vs->p15card, (struct sc_pkcs15_cert_info *)(vs->cert_objs[i]->data), &cert);
		logprintf(pCardData, 5, "cert->subject %d ", i);
		loghex(pCardData, 5, cert->subject, cert->subject_len);
		sc_pkcs15_free_certificate(cert);
	}

	for(i = 0; i < vs->pin_count; i++)   {
		const char *pin_flags[] =   {
			"case-sensitive", "local", "change-disabled",
			"unblock-disabled", "initialized", "needs-padding",
			"unblockingPin", "soPin", "disable_allowed",
			"integrity-protected", "confidentiality-protected",
			"exchangeRefData"
		};
		const char *pin_types[] = {"bcd", "ascii-numeric", "UTF-8", "halfnibble bcd", "iso 9664-1"};
		const struct sc_pkcs15_object *obj = vs->pin_objs[i];
		const struct sc_pkcs15_auth_info *auth_info = (const struct sc_pkcs15_auth_info *) (obj->data);
		const struct sc_pkcs15_pin_attributes *pin_attrs = &auth_info->attrs.pin;
		const size_t pf_count = sizeof(pin_flags)/sizeof(pin_flags[0]);
		size_t j;

		logprintf(pCardData, 2, "PIN [%s]\n", obj->label);
		
		logprintf(pCardData, 2, "\tCom. Flags: 0x%X\n", obj->flags);
		
		logprintf(pCardData, 2, "\tID        : %s\n", sc_pkcs15_print_id(&auth_info->auth_id));
		
		logprintf(pCardData, 2, "\tFlags     : [0x%02X]", pin_attrs->flags);
		for (j = 0; j < pf_count; j++)
			if (pin_attrs->flags & (1 << j))
				logprintf(pCardData, 2, ", %s", pin_flags[j]);
		logprintf(pCardData, 2, "\n");
		
		logprintf(pCardData, 2, "\tLength    : min_len:%lu, max_len:%lu, stored_len:%lu\n",
			(unsigned long)pin_attrs->min_length, (unsigned long)pin_attrs->max_length,
			(unsigned long)pin_attrs->stored_length);

		logprintf(pCardData, 2, "\tPad char  : 0x%02X\n", pin_attrs->pad_char);
		
		logprintf(pCardData, 2, "\tReference : %d\n", pin_attrs->reference);

		if (pin_attrs->type < sizeof(pin_types)/sizeof(pin_types[0]))
			logprintf(pCardData, 2, "\tType      : %s\n", pin_types[pin_attrs->type]);
		else
			logprintf(pCardData, 2, "\tType      : [encoding %d]\n", pin_attrs->type);

		logprintf(pCardData, 2, "\tPath      : %s\n", sc_print_path(&auth_info->path));

		if (auth_info->tries_left >= 0)
			logprintf(pCardData, 2, "\tTries left: %d\n", auth_info->tries_left);
	}
}


static DWORD
md_fs_find_directory(PCARD_DATA pCardData, struct md_directory *parent, char *name, struct md_directory **out)
{
	VENDOR_SPECIFIC *vs;
	struct md_directory *dir = NULL;
	
	if (out)
		*out = NULL;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;
	if (!parent)
		parent = &vs->root;

	if (!name)   {
		dir = parent;
	}
	else   {
		dir = parent->subdirs;
		while(dir)   {
			if (!strcmp(dir->name, name))
				break;
			dir = dir->next;
		}
	}

	if (!dir)
		return SCARD_E_DIR_NOT_FOUND;

	if (out)
		*out = dir;

	logprintf(pCardData, 3, "MD virtual file system: found '%s' directory\n", name);
	return SCARD_S_SUCCESS;
}


static DWORD
md_fs_add_directory(PCARD_DATA pCardData, struct md_directory **head, char *name, CARD_FILE_ACCESS_CONDITION acl, 
		struct md_directory **out)
{
	struct md_directory *new_dir = NULL;

	if (!pCardData || !head || !name) 
		return SCARD_E_INVALID_PARAMETER;

	new_dir = pCardData->pfnCspAlloc(sizeof(struct md_directory));
	if (!new_dir)
		return SCARD_E_NO_MEMORY;
	memset(new_dir, 0, sizeof(struct md_directory));

	strncpy(new_dir->name, name, sizeof(new_dir->name) - 1);
	new_dir->acl = acl;

	if (*head == NULL)   {
		*head = new_dir;
	}
	else    {
		 struct md_directory *last = *head;
		 while (last->next)
			 last = last->next;
		 last->next = new_dir;
	}

	if (out)
		*out = new_dir;

	logprintf(pCardData, 3, "MD virtual file system: directory '%s' added\n", name);
	return SCARD_S_SUCCESS;
}


static DWORD
md_fs_find_file(PCARD_DATA pCardData, char *parent, char *name, struct md_file **out)
{
	VENDOR_SPECIFIC *vs;
	struct md_file *file = NULL;
	struct md_directory *dir = NULL;
	DWORD dwret;
	
	if (out)
		*out = NULL;

	if (!pCardData || !name)
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;

	dwret = md_fs_find_directory(pCardData, NULL, parent, &dir);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 2, "find directory '%s' error: %X\n", parent ? parent : "<null>", dwret);
		return dwret;
	}
	else if (!dir)   {
		logprintf(pCardData, 2, "directory '%s' not found\n", parent ? parent : "<null>");
		return SCARD_E_INVALID_PARAMETER;
	}

	for (file = dir->files; file!=NULL;)   {
		if (!strcmp(file->name, name))
			break;
		file = file->next;
	}
	if (!file)
		return SCARD_E_FILE_NOT_FOUND;

	if (out)
		*out = file;

	logprintf(pCardData, 3, "MD virtual file system: found '%s' file\n", name);
	return SCARD_S_SUCCESS;
}


static DWORD
md_fs_add_file(PCARD_DATA pCardData, struct md_file **head, char *name, CARD_FILE_ACCESS_CONDITION acl, 
		unsigned char *blob, size_t size, struct md_file **out)
{
	struct md_file *new_file = NULL;

	if (!pCardData || !head || !name) 
		return SCARD_E_INVALID_PARAMETER;

	new_file = pCardData->pfnCspAlloc(sizeof(struct md_file));
	if (!new_file)
		return SCARD_E_NO_MEMORY;
	memset(new_file, 0, sizeof(struct md_file));

	strncpy(new_file->name, name, sizeof(new_file->name) - 1);
	new_file->size = size;
	new_file->acl = acl;

	if (size)   {
		new_file->blob = pCardData->pfnCspAlloc(size);
		if (!new_file->blob)   {
			pCardData->pfnCspFree(new_file);
			return SCARD_E_NO_MEMORY;
		}

		if (blob)
			CopyMemory(new_file->blob, blob, size);
		else
			memset(new_file->blob, 0, size);
	}

	if (*head == NULL)   {
		*head = new_file;
	}
	else    {
		 struct md_file *last = *head;
		 while (last->next)
			 last = last->next;
		 last->next = new_file;
	}

	if (out)
		*out = new_file;

	logprintf(pCardData, 3, "MD virtual file system: file '%s' added\n", name);
	return SCARD_S_SUCCESS;
}


static void
md_fs_free_file(PCARD_DATA pCardData, struct md_file *file)   
{
	if (!file)
		return;
	if (file->blob)
		pCardData->pfnCspFree(file->blob);
	file->blob = NULL;
	file->size = 0;
}


static DWORD
md_fs_delete_file(PCARD_DATA pCardData, char *parent, char *name)
{
	VENDOR_SPECIFIC *vs;
	struct md_file *file = NULL;
	struct md_directory *dir = NULL;
	DWORD dwret;
	
	if (!pCardData || !name)
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;

	dwret = md_fs_find_directory(pCardData, NULL, parent, &dir);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 2, "find directory '%s' error: %X\n", parent ? parent : "<null>", dwret);
		return dwret;
	}
	else if (!dir)   {
		logprintf(pCardData, 2, "directory '%s' not found\n", parent ? parent : "<null>");
		return SCARD_E_INVALID_PARAMETER;
	}

	if (!dir->files)   {
		dwret = SCARD_E_FILE_NOT_FOUND;
	}
	else if (!strcmp(dir->files->name, name))   {
		md_fs_free_file(pCardData, dir->files);
		dir->files = NULL;
		dwret = SCARD_S_SUCCESS;
	}
	else   {
		int deleted = 0;
		struct md_file *file_to_rm = NULL;

		for (file = dir->files; file!=NULL; file = file->next)   {
			if (!file->next)
				break;
			if (!strcmp(file->next->name, name))   {
				file_to_rm = file->next;
				file->next = file->next->next;
				md_fs_free_file(pCardData, file_to_rm);
				deleted = 1;
				break;
			}
		}
		dwret = deleted ? SCARD_S_SUCCESS : SCARD_E_FILE_NOT_FOUND;
	}

	return dwret;
}


static DWORD 
md_fs_set_content(PCARD_DATA pCardData, struct md_file *file, unsigned char *blob, size_t size)
{
	if (!pCardData || !file) 
		return SCARD_E_INVALID_PARAMETER;

	if (file->blob)
		pCardData->pfnCspFree(file->blob);

	file->blob = pCardData->pfnCspAlloc(size);
	if (!file->blob)
		return SCARD_E_NO_MEMORY;
	CopyMemory(file->blob, blob, size);
	file->size = size;

	return SCARD_S_SUCCESS;
}


static DWORD
md_set_cardid(PCARD_DATA pCardData, struct md_file *file)
{
	VENDOR_SPECIFIC *vs;
	DWORD dwret;
	
	if (!pCardData || !file) 
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;
	if (vs->p15card->tokeninfo && vs->p15card->tokeninfo->serial_number) {
		unsigned char sn_bin[SC_MAX_SERIALNR];
		unsigned char cardid_bin[MD_CARDID_SIZE];
		size_t offs, wr, sn_len = sizeof(sn_bin);
		int rv;

		rv = sc_hex_to_bin(vs->p15card->tokeninfo->serial_number, sn_bin, &sn_len);
		if (rv)
			return SCARD_E_INVALID_VALUE;

		for (offs=0; offs < MD_CARDID_SIZE; )   {
			wr = MD_CARDID_SIZE - offs;
			if (wr > sn_len)
				wr = sn_len;
			memcpy(cardid_bin + offs, sn_bin, wr);
			offs += wr;
		}

		dwret = md_fs_set_content(pCardData, file, cardid_bin, MD_CARDID_SIZE);
		if (dwret != SCARD_S_SUCCESS)
			return dwret;
	}

	logprintf(pCardData, 3, "cardid(%i)\n", file->size);
	loghex(pCardData, 3, file->blob, file->size);
	return SCARD_S_SUCCESS;
}

static void
md_fs_read_content(PCARD_DATA pCardData, char *parent, struct md_file *file)
{
	VENDOR_SPECIFIC *vs;
	struct md_directory *dir = NULL;
	DWORD dwret;
	
	if (!pCardData || !file)
		return;

	vs = pCardData->pvVendorSpecific;

	dwret = md_fs_find_directory(pCardData, NULL, parent, &dir);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 2, "find directory '%s' error: %X\n", parent ? parent : "<null>", dwret);
		return;
	}
	else if (!dir)   {
		logprintf(pCardData, 2, "directory '%s' not found\n", parent ? parent : "<null>");
		return;
	}

	if (!strcmp(dir->name, "mscp"))   {
		int idx, rv;

		if(sscanf(file->name, "ksc%d", &idx) > 0)   {
		}
		else if(sscanf(file->name, "kxc%d", &idx) > 0)   {
		}
		else   {
			idx = -1;
		}

		if (idx >=0 && idx < vs->cert_count)   {
			struct sc_pkcs15_cert *cert = NULL;
			struct sc_pkcs15_object *cert_obj = vs->cert_objs[idx];
			struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *)cert_obj->data;
			
			rv = sc_pkcs15_read_certificate(vs->p15card, cert_info, &cert);
			if(rv)   {
				logprintf(pCardData, 2, "Cannot read certificate idx:%i: sc-error %d\n", idx, rv);
				return;
			}

			file->size = cert->data_len;
			file->blob = pCardData->pfnCspAlloc(cert->data_len);
			CopyMemory(file->blob, cert->data, cert->data_len);
			sc_pkcs15_free_certificate(cert);
		}
	}
	else   {
		return;
	}


}

static DWORD
md_set_cardcf(PCARD_DATA pCardData, struct md_file *file, CARD_CACHE_FILE_FORMAT *data)
{
	DWORD dwret;
	CARD_CACHE_FILE_FORMAT empty;
	
	if (!pCardData || !file) 
		return SCARD_E_INVALID_PARAMETER;

	srand((unsigned)time(NULL));

	empty.bVersion = 0;
	empty.bPinsFreshness = 0;
	empty.wContainersFreshness = rand()%30000;
	empty.wFilesFreshness = rand()%30000;	
	empty.wContainersFreshness = 1;
	empty.wFilesFreshness = 1;	
	logprintf(pCardData, 3, "empty.wContainersFreshness %i\n", empty.wContainersFreshness);
	if (!data)
		data = &empty;

	dwret = md_fs_set_content(pCardData, file, (unsigned char *)data, sizeof(CARD_CACHE_FILE_FORMAT));
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	logprintf(pCardData, 3, "cardcf(%i)\n", file->size);
	loghex(pCardData, 3, file->blob, file->size);
	return SCARD_S_SUCCESS;
}

static DWORD
md_get_cardcf(PCARD_DATA pCardData, CARD_CACHE_FILE_FORMAT **out)
{
	struct md_file *file = NULL;

	if (!pCardData) 
		return SCARD_E_INVALID_PARAMETER;

	md_fs_find_file(pCardData, NULL, "cardcf", &file);
	if (!file)   {
		logprintf(pCardData, 2, "file 'cardcf' not found\n");
		return SCARD_E_FILE_NOT_FOUND;
	}
	if (!file->blob || file->size < sizeof(CARD_CACHE_FILE_FORMAT))
		return SCARD_E_INVALID_VALUE;
	if (out)
		*out = (CARD_CACHE_FILE_FORMAT *)file->blob;

	return SCARD_S_SUCCESS;
}

static DWORD
md_set_cardapps(PCARD_DATA pCardData, struct md_file *file)
{
	DWORD dwret;
	unsigned char mscp[8] = {'m','s','c','p',0,0,0,0};
	
	if (!pCardData || !file) 
		return SCARD_E_INVALID_PARAMETER;

	dwret = md_fs_set_content(pCardData, file, mscp, sizeof(mscp));
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	logprintf(pCardData, 3, "mscp(%i)\n", file->size);
	loghex(pCardData, 3, file->blob, file->size);
	return SCARD_S_SUCCESS;
}


static DWORD
md_set_cmapfile(PCARD_DATA pCardData, struct md_file *file)
{
	VENDOR_SPECIFIC *vs;
	PCONTAINER_MAP_RECORD p;
	sc_pkcs15_pubkey_t *pubkey = NULL;
	unsigned char *cmap_buf = NULL;
	size_t cmap_len;
	DWORD dwret;
	int ii, rv;

	if (!pCardData || !file) 
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;
	cmap_len = MD_MAX_KEY_CONTAINERS*sizeof(CONTAINER_MAP_RECORD);
	cmap_buf = pCardData->pfnCspAlloc(cmap_len);
	if(!cmap_buf)
		return SCARD_E_NO_MEMORY;
	memset(cmap_buf, 0, cmap_len);

	p = (PCONTAINER_MAP_RECORD)cmap_buf;
	for(ii = 0; ii < vs->prkey_count && ii < MD_MAX_KEY_CONTAINERS; ii++,p++)   {
		struct sc_pkcs15_object *key_obj = vs->prkey_objs[ii], *cert_obj = NULL;
		struct sc_pkcs15_prkey_info *prkey_info = (struct sc_pkcs15_prkey_info *)key_obj->data;

		if(key_obj->type == SC_PKCS15_TYPE_PRKEY_RSA)   {
			char guid[MAX_CONTAINER_NAME_LEN + 1];

			rv = sc_pkcs15_get_guid(vs->p15card, key_obj, guid, sizeof(guid));
			if (rv)   {
				logprintf(pCardData, 2, "sc_pkcs15_get_guid() error %d\n", rv);
				return SCARD_F_INTERNAL_ERROR;
			}

			logprintf(pCardData, 7, "Container's Guid=%s\n", guid);

			mbstowcs(p->wszGuid, guid, MAX_CONTAINER_NAME_LEN + 1);
			p->bFlags += CONTAINER_MAP_VALID_CONTAINER;
			/* TODO: default container to be defined in a different manner */
			if(ii == 0)
				p->bFlags += CONTAINER_MAP_DEFAULT_CONTAINER;
			/* TODO Looks like these should be based on sc_pkcs15_prkey_info usage */
			/* On PIV on W7, auth cert is AT_KEYEXCHANGE, Signing cert is AT_SIGNATURE */

			p->wSigKeySizeBits = prkey_info->modulus_length;
			p->wKeyExchangeKeySizeBits = prkey_info->modulus_length;
		}
		else   {
			logprintf(pCardData, 7, "Non 'RSA' key are ignored\n");
			continue;
		}

		rv = sc_pkcs15_find_cert_by_id(vs->p15card, &prkey_info->id, &cert_obj);
		if (!rv && cert_obj)   {
			char k_name[6];

			snprintf((char *)k_name, sizeof(k_name), "kxc%02i", ii);
			dwret = md_fs_add_file(pCardData, &(file->next), k_name, file->acl, NULL, 0, NULL);
			if (dwret != SCARD_S_SUCCESS)
				return dwret;

			snprintf((char *)k_name, sizeof(k_name), "ksc%02i", ii);
			dwret = md_fs_add_file(pCardData, &(file->next), k_name, file->acl, NULL, 0, NULL);
			if (dwret != SCARD_S_SUCCESS)
				return dwret;
		}

		logprintf(pCardData, 7, "cmapfile entry %d ",ii);
		loghex(pCardData, 7, (PBYTE) p, sizeof(CONTAINER_MAP_RECORD));
	}

	dwret = md_fs_set_content(pCardData, file, cmap_buf, cmap_len);
	pCardData->pfnCspFree(cmap_buf);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	logprintf(pCardData, 3, "cmap(%i)\n", file->size);
	loghex(pCardData, 3, file->blob, file->size);
	return SCARD_S_SUCCESS;
}


static DWORD
md_fs_init(PCARD_DATA pCardData)
{
	VENDOR_SPECIFIC *vs;
	DWORD dwret;
	struct md_file *cardid, *cardcf, *cardapps, *cmapfile;
	struct md_directory *mscp;

	if (!pCardData || !pCardData->pvVendorSpecific) 
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;

	dwret = md_fs_add_file(pCardData, &(vs->root.files), "cardid", EveryoneReadAdminWriteAc, NULL, 0, &cardid);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;
	dwret = md_set_cardid(pCardData, cardid);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	dwret = md_fs_add_file(pCardData, &(vs->root.files), "cardcf", EveryoneReadUserWriteAc, NULL, 0, &cardcf);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;
	logprintf(pCardData, 3, "Now set cardcf\n");
	dwret = md_set_cardcf(pCardData, cardcf, NULL);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	dwret = md_fs_add_file(pCardData, &(vs->root.files), "cardapps", EveryoneReadAdminWriteAc, NULL, 0, &cardapps);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;
	dwret = md_set_cardapps(pCardData, cardapps);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	dwret = md_fs_add_directory(pCardData, &(vs->root.subdirs), "mscp", UserCreateDeleteDirAc, &mscp);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	dwret = md_fs_add_file(pCardData, &(mscp->files), "cmapfile", EveryoneReadUserWriteAc, NULL, 0, &cmapfile);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;
	dwret = md_set_cmapfile(pCardData, cmapfile);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;



	logprintf(pCardData, 3, "MD virtual file system initialized\n");
	return SCARD_S_SUCCESS;
}

static DWORD 
md_create_context(PCARD_DATA pCardData, VENDOR_SPECIFIC *vs)
{
	sc_context_param_t ctx_param;
	int r;

	if (!pCardData) 
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 3, "create sc ccontext\n");
	vs->ctx = NULL;

	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver = 1;
	ctx_param.app_name = "cardmod";

	r = sc_context_create(&(vs->ctx), &ctx_param);
	if (r)   {
		logprintf(pCardData, 0, "Failed to establish context: %s\n", sc_strerror(r));
		return SCARD_F_UNKNOWN_ERROR;
	}

	logprintf(pCardData, 3, "sc context created\n");
	return SCARD_S_SUCCESS;
}

static DWORD
md_card_capabilities(PCARD_CAPABILITIES  pCardCapabilities)
{
	if (!pCardCapabilities) 
		return SCARD_E_INVALID_PARAMETER;

	if (pCardCapabilities->dwVersion != CARD_CAPABILITIES_CURRENT_VERSION && pCardCapabilities->dwVersion != 0)
		return ERROR_REVISION_MISMATCH;

	pCardCapabilities->dwVersion = CARD_CAPABILITIES_CURRENT_VERSION;
	pCardCapabilities->fCertificateCompression = TRUE;
	pCardCapabilities->fKeyGen = TRUE;

	return SCARD_S_SUCCESS;
}

static DWORD
md_free_space(PCARD_DATA pCardData, PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo)
{
	VENDOR_SPECIFIC *vs;

	if (!pCardData || !pCardFreeSpaceInfo) 
		return SCARD_E_INVALID_PARAMETER;

	if (pCardFreeSpaceInfo->dwVersion > CARD_FREE_SPACE_INFO_CURRENT_VERSION )
		return ERROR_REVISION_MISMATCH;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	pCardFreeSpaceInfo->dwVersion = CARD_FREE_SPACE_INFO_CURRENT_VERSION;
	pCardFreeSpaceInfo->dwBytesAvailable = CARD_DATA_VALUE_UNKNOWN;
	pCardFreeSpaceInfo->dwKeyContainersAvailable = MD_MAX_KEY_CONTAINERS - vs->cert_count;
	pCardFreeSpaceInfo->dwMaxKeyContainers = MD_MAX_KEY_CONTAINERS;

	return SCARD_S_SUCCESS;
}


static DWORD
md_check_key_compatibility(PCARD_DATA pCardData, DWORD flags, DWORD key_type, DWORD key_size)
{
	VENDOR_SPECIFIC *vs;
	struct sc_algorithm_info *algo_info;
	unsigned int count, key_algo;

	if (!pCardData) 
		return SCARD_E_INVALID_PARAMETER;

	if (key_type == AT_SIGNATURE || key_type == AT_KEYEXCHANGE)   {
		key_algo = SC_ALGORITHM_RSA;
	}
	else   {
		logprintf(pCardData, 3, "Unsupported key type: 0x%X\n", key_type);
		return SCARD_E_UNSUPPORTED_FEATURE;
	}

	if (flags & CARD_CREATE_CONTAINER_KEY_IMPORT)   {
		logprintf(pCardData, 3, "Key import is not supported yet\n");
		return SCARD_E_UNSUPPORTED_FEATURE;
	}

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	count = vs->p15card->card->algorithm_count;
	for (algo_info = vs->p15card->card->algorithms; count--; algo_info++) {
		if (algo_info->algorithm != key_algo || algo_info->key_length != key_size)
			continue;
		logprintf(pCardData, 3, "Key compatible with the card capabilities\n");
		return SCARD_S_SUCCESS;
	}

	logprintf(pCardData, 3, "No card support for key(type:0x%X,size:0x%X)\n", key_type, key_size);
	return SCARD_E_UNSUPPORTED_FEATURE;
}


static DWORD
md_generate_key(PCARD_DATA pCardData, DWORD idx, DWORD key_type, DWORD key_size)
{
	VENDOR_SPECIFIC *vs;
	struct sc_card *card = NULL;
	struct sc_profile *profile = NULL;
	struct sc_pkcs15_object *pin_obj;
	struct sc_pkcs15_auth_info *auth_info;
	struct sc_pkcs15init_keygen_args keygen_args;
	struct sc_pkcs15init_pubkeyargs pub_args;
	int rv;
	DWORD dw, dwret = SCARD_F_INTERNAL_ERROR;

	if (!pCardData) 
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	card = vs->p15card->card;

	memset(&pub_args, 0, sizeof(pub_args));
	memset(&keygen_args, 0, sizeof(keygen_args));
	keygen_args.prkey_args.label = keygen_args.pubkey_label = "TODO: key label";

	if (key_type == AT_SIGNATURE)   {
		keygen_args.prkey_args.key.algorithm = SC_ALGORITHM_RSA;
		pub_args.key.algorithm = SC_ALGORITHM_RSA;
		keygen_args.prkey_args.x509_usage = MD_KEY_USAGE_SIGNATURE;
	}
	else if (key_type == AT_KEYEXCHANGE)   {
		keygen_args.prkey_args.key.algorithm = SC_ALGORITHM_RSA;
		pub_args.key.algorithm = SC_ALGORITHM_RSA;
		keygen_args.prkey_args.x509_usage = MD_KEY_USAGE_KEYEXCHANGE; 
	}
	else    {
		logprintf(pCardData, 3, "MdGenerateKey(): unsupported key type: 0x%X\n", key_type);
		return SCARD_E_INVALID_PARAMETER;
	}

	keygen_args.prkey_args.access_flags = MD_KEY_ACCESS;

	dw = get_pin_by_role(pCardData, ROLE_USER, &pin_obj);
	if (dw != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 2, "MdGenerateKey(): cannot get User PIN object");
		return dw;
	}

	auth_info = (struct sc_pkcs15_auth_info *) pin_obj->data;
	keygen_args.prkey_args.auth_id = pub_args.auth_id = auth_info->auth_id;

        rv = sc_lock(card);
	if (rv)   {
		logprintf(pCardData, 3, "MdGenerateKey(): cannot lock card\n");
		return SCARD_F_INTERNAL_ERROR;
	}
	rv = sc_pkcs15init_bind(card, "pkcs15", NULL, &profile);
	if (rv) {
		logprintf(pCardData, 3, "MdGenerateKey(): PKCS#15 bind failed\n");
        	sc_unlock(card);
		return SCARD_F_INTERNAL_ERROR;
	}

	rv = sc_pkcs15init_finalize_profile(card, profile, NULL);
	if (rv) {
		logprintf(pCardData, 3, "MdGenerateKey(): cannot finalize profile\n");
		goto done;
	}

	sc_pkcs15init_set_p15card(profile, vs->p15card);

	rv = sc_pkcs15init_generate_key(vs->p15card, profile, &keygen_args, key_size, &vs->generated_key);
	if (rv < 0) {
		logprintf(pCardData, 3, "MdGenerateKey(): key generation failed: sc-error %i\n", rv);
		goto done;
	}
	logprintf(pCardData, 3, "MdGenerateKey(): key generated\n");

	dwret = SCARD_S_SUCCESS;
done:
	sc_pkcs15init_unbind(profile);
        sc_unlock(card);
	return dwret;
}


static DWORD
md_store_certificate(PCARD_DATA pCardData, char *file_name, unsigned char *blob, size_t len)
{
	VENDOR_SPECIFIC *vs;
	struct sc_card *card = NULL;
	struct sc_profile *profile = NULL;
	struct sc_pkcs15_object *cert_obj;
	struct sc_pkcs15init_certargs args;
	int rv;
	DWORD dwret = SCARD_F_INTERNAL_ERROR;

	if (!pCardData) 
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	card = vs->p15card->card;

	memset(&args, 0, sizeof(args));
	args.der_encoded.value = blob;
	args.der_encoded.len = len;

        rv = sc_lock(card);
	if (rv)   {
		logprintf(pCardData, 3, "MdStoreCert(): cannot lock card\n");
		return SCARD_F_INTERNAL_ERROR;
	}
	rv = sc_pkcs15init_bind(card, "pkcs15", NULL, &profile);
	if (rv) {
		logprintf(pCardData, 3, "MsStoreCert(): PKCS#15 bind failed\n");
        	sc_unlock(card);
		return SCARD_F_INTERNAL_ERROR;
	}

	rv = sc_pkcs15init_finalize_profile(card, profile, NULL);
	if (rv) {
		logprintf(pCardData, 3, "MdStoreCert(): cannot finalize profile\n");
		goto done;
	}

	sc_pkcs15init_set_p15card(profile, vs->p15card);

	rv = sc_pkcs15init_store_certificate(vs->p15card, profile, &args, &cert_obj);
	if (rv < 0) {
		logprintf(pCardData, 3, "MdStoreCert(): cannot store certificate: sc-error %i\n", rv);
		goto done;
	}

	dwret = SCARD_S_SUCCESS;
done:
	sc_pkcs15init_unbind(profile);
        sc_unlock(card);
	return dwret;
}

static DWORD
md_query_key_sizes(CARD_KEY_SIZES *pKeySizes)
{
	if (!pKeySizes) 
		return SCARD_E_INVALID_PARAMETER;

	if (pKeySizes->dwVersion != CARD_KEY_SIZES_CURRENT_VERSION && pKeySizes->dwVersion != 0) 
		return ERROR_REVISION_MISMATCH;

	pKeySizes->dwVersion = CARD_KEY_SIZES_CURRENT_VERSION;
	pKeySizes->dwMinimumBitlen = 1024;
	pKeySizes->dwDefaultBitlen = 2048;
	pKeySizes->dwMaximumBitlen = 2048;
	pKeySizes->dwIncrementalBitlen = 1024;

	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardDeleteContext(__inout PCARD_DATA  pCardData)
{
	VENDOR_SPECIFIC *vs = NULL;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDeleteContext\n");

	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	if(!vs)
		return SCARD_E_INVALID_PARAMETER;

	disassociate_card(pCardData);

	if(vs->ctx)   {
		logprintf(pCardData, 6, "release context\n");
		sc_release_context(vs->ctx);
		vs->ctx = NULL;
	}

	logprintf(pCardData, 1, "**********************************************************************\n");

	pCardData->pfnCspFree(pCardData->pvVendorSpecific);
	pCardData->pvVendorSpecific = NULL;

	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardQueryCapabilities(__in PCARD_DATA pCardData,
	__in PCARD_CAPABILITIES  pCardCapabilities)
{
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "pCardCapabilities=%X\n", pCardCapabilities);

	if (!pCardData || !pCardCapabilities) 
		return SCARD_E_INVALID_PARAMETER;

	dwret = md_card_capabilities(pCardCapabilities);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	check_reader_status(pCardData);

	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardDeleteContainer(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in DWORD dwReserved)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDeleteContainer(idx:%i)\n", bContainerIndex);

	logprintf(pCardData, 1, "CardDeleteContainer() not supported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}


DWORD WINAPI 
CardCreateContainer(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in DWORD dwFlags,
	__in DWORD dwKeySpec,
	__in DWORD dwKeySize,
	__in PBYTE pbKeyData)
{
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardCreateContainer(idx:%i,flags:%X,type:%X,size:%i,data:%p)\n", 
			bContainerIndex, dwFlags,dwKeySpec,dwKeySize,pbKeyData);

	dwret = md_check_key_compatibility(pCardData, dwFlags, dwKeySpec, dwKeySize);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 1, "check key compatibility failed");
		return dwret;
	}

	if (dwFlags & CARD_CREATE_CONTAINER_KEY_GEN)   {
		dwret = md_generate_key(pCardData, bContainerIndex, dwKeySpec, dwKeySize);
		if (dwret != SCARD_S_SUCCESS)   {
			logprintf(pCardData, 1, "key generation failed");
			return dwret;
		}
	}
	else if (dwFlags & CARD_CREATE_CONTAINER_KEY_IMPORT) {
		logprintf(pCardData, 1, "KEY IMPORT not supported");
		return SCARD_E_UNSUPPORTED_FEATURE;
	}
	else   {
		logprintf(pCardData, 1, "Invalid dwFlags value: 0x%X", dwFlags);
		return SCARD_E_INVALID_PARAMETER;
	}

	logprintf(pCardData, 1, "key generated");
	return SCARD_S_SUCCESS;
}

typedef struct {
	PUBLICKEYSTRUC  publickeystruc;
	RSAPUBKEY rsapubkey;
} PUBKEYSTRUCT_BASE;


DWORD WINAPI 
CardGetContainerInfo(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in DWORD dwFlags,
	__in PCONTAINER_INFO pContainerInfo)
{
	int rv;
	sc_pkcs15_cert_t *cert = NULL;
	VENDOR_SPECIFIC *vs = NULL;

	PUBKEYSTRUCT_BASE *oh = NULL;
	PUBKEYSTRUCT_BASE *oh2 = NULL;

	DWORD sz = 0;
	DWORD sz2 = 0;

	DWORD ret;
	sc_pkcs15_pubkey_t *pubkey = NULL;

	if(!pCardData) 
		return SCARD_E_INVALID_PARAMETER;
	if (!pContainerInfo) 
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardGetContainerInfo bContainerIndex=%u, dwFlags=0x%08X, " \
		"dwVersion=%u, cbSigPublicKey=%u, cbKeyExPublicKey=%u\n", \
		bContainerIndex, dwFlags, pContainerInfo->dwVersion, \
		pContainerInfo->cbSigPublicKey, pContainerInfo->cbKeyExPublicKey);

	if (dwFlags) 
		return SCARD_E_INVALID_PARAMETER;
	if (pContainerInfo->dwVersion < 0 || pContainerInfo->dwVersion >  CONTAINER_INFO_CURRENT_VERSION)
		return ERROR_REVISION_MISMATCH;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	check_reader_status(pCardData);

	if(bContainerIndex >= vs->cert_count)   {
		if (vs->generated_key)   {
			logprintf(pCardData, 7, "Key Content:");
			loghex(pCardData, 7,  vs->generated_key->content.value, vs->generated_key->content.len);

			sz = 0;	
			oh = NULL;
			rv = CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, 
						vs->generated_key->content.value, vs->generated_key->content.len, 0, oh, &sz);
			if (!rv)   {
				logprintf(pCardData, 1, "cannot decode public key\n");
				return SCARD_F_INTERNAL_ERROR;
			}

			oh =  (PUBKEYSTRUCT_BASE*)pCardData->pfnCspAlloc(sz);
			oh2 = (PUBKEYSTRUCT_BASE*)pCardData->pfnCspAlloc(sz);

			CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, 
					vs->generated_key->content.value, vs->generated_key->content.len, 0, oh, &sz);
			CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, 
					vs->generated_key->content.value, vs->generated_key->content.len, 0, oh2, &sz);

			oh->publickeystruc.aiKeyAlg = CALG_RSA_SIGN;
			pContainerInfo->cbSigPublicKey = sz;
			pContainerInfo->pbSigPublicKey = (PBYTE)oh;

			oh2->publickeystruc.aiKeyAlg = CALG_RSA_KEYX;
			pContainerInfo->cbKeyExPublicKey = sz;
			pContainerInfo->pbKeyExPublicKey = (PBYTE)oh2;

			pContainerInfo->dwVersion = CONTAINER_INFO_CURRENT_VERSION;

			logprintf(pCardData, 7, "returns container info for key size %i", sz);
			return SCARD_S_SUCCESS;
		}
		else   {
			logprintf(pCardData, 1, "invalid container index: idx:%i, cert_count:%i\n", bContainerIndex, vs->cert_count);
			return SCARD_E_INVALID_PARAMETER;
		}
	}

	rv = sc_pkcs15_read_certificate(vs->p15card, (struct sc_pkcs15_cert_info *)(vs->cert_objs[bContainerIndex]->data), &cert);
	if(rv)   {
		logprintf(pCardData, 1, "certificate '%d' read error %d\n", bContainerIndex, rv);
		return SCARD_E_FILE_NOT_FOUND;
	}
	pubkey = cert->key;

	if(pubkey->algorithm == SC_ALGORITHM_RSA)   {
		int modulus = compute_keybits(&(pubkey->u.rsa.modulus));

		PCCERT_CONTEXT cer = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert->data, cert->data_len);
		PCERT_PUBLIC_KEY_INFO pinf = &(cer->pCertInfo->SubjectPublicKeyInfo);

		logprintf(pCardData, 7, "SubjectPublicKeyInfo");
		loghex(pCardData, 7,  pinf->PublicKey.pbData, pinf->PublicKey.cbData);

		sz = 0; /* get size */
		CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, 
				pinf->PublicKey.pbData, pinf->PublicKey.cbData , 0, oh, &sz);
		sz2 = sz;

		oh =  (PUBKEYSTRUCT_BASE*)pCardData->pfnCspAlloc(sz);
		oh2 = (PUBKEYSTRUCT_BASE*)pCardData->pfnCspAlloc(sz2);
		if(oh && oh2)   {
			CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, 
					pinf->PublicKey.pbData, pinf->PublicKey.cbData, 0, oh, &sz);

			oh->publickeystruc.aiKeyAlg = CALG_RSA_SIGN;
			pContainerInfo->cbSigPublicKey = sz;
			pContainerInfo->pbSigPublicKey = (PBYTE)oh;

			CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, 
					pinf->PublicKey.pbData, pinf->PublicKey.cbData, 0, oh2, &sz2);

			oh2->publickeystruc.aiKeyAlg = CALG_RSA_KEYX;
			pContainerInfo->cbKeyExPublicKey = sz2;
			pContainerInfo->pbKeyExPublicKey = (PBYTE)oh2;

			pContainerInfo->dwVersion = CONTAINER_INFO_CURRENT_VERSION;

			logprintf(pCardData, 3, "return info on SIGN_CONTAINER_INDEX\n");
			ret = SCARD_S_SUCCESS;
		}
		else   {
			ret = SCARD_E_NO_MEMORY;
		}
	}

	if(cert)
		sc_pkcs15_free_certificate(cert);

	return ret;
}

DWORD WINAPI CardAuthenticatePin(__in PCARD_DATA pCardData,
	__in LPWSTR pwszUserId,
	__in PBYTE pbPin,
	__in DWORD cbPin,
	__out_opt PDWORD pcAttemptsRemaining)
{
	int r;
	sc_pkcs15_object_t *pin_obj;
	char type[256];
	VENDOR_SPECIFIC *vs;
	struct md_file *cardcf_file = NULL;
	CARD_CACHE_FILE_FORMAT *cardcf = NULL;
	DWORD dwret;

	if(!pCardData) 
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardAuthenticatePin '%S':%d\n", NULLWSTR(pwszUserId), cbPin);

	check_reader_status(pCardData);

	dwret = md_get_cardcf(pCardData, &cardcf);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	if (NULL == pwszUserId) 
		return SCARD_E_INVALID_PARAMETER;
	if (wcscmp(wszCARD_USER_USER,pwszUserId) != 0 && wcscmp(wszCARD_USER_ADMIN,pwszUserId) != 0)
		return SCARD_E_INVALID_PARAMETER;
	if (NULL == pbPin) 
		return SCARD_E_INVALID_PARAMETER;

	if (cbPin < 4 || cbPin > 12) 
		return SCARD_W_WRONG_CHV;

	if (wcscmp(wszCARD_USER_ADMIN,pwszUserId) == 0)
		return SCARD_W_WRONG_CHV;

	wcstombs(type, pwszUserId, 100);
	type[10] = 0;

	logprintf(pCardData, 1, "CardAuthenticatePin %.20s, %d, %d\n", NULLSTR(type),
		cbPin, (pcAttemptsRemaining==NULL?-2:*pcAttemptsRemaining));

	r = get_pin_by_role(pCardData, ROLE_USER, &pin_obj);
	if (r != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 2, "Cannot get User PIN object");
		return r;
	}

	r = sc_pkcs15_verify_pin(vs->p15card, pin_obj, (const u8 *) pbPin, cbPin);
	if (r)   {
		logprintf(pCardData, 1, "PIN code verification failed: %s\n", sc_strerror(r));
		/* TODO: get 'tries-left' value */
		if(pcAttemptsRemaining)
			(*pcAttemptsRemaining) = -1;

		return SCARD_W_WRONG_CHV;
	}

	logprintf(pCardData, 3, "Pin code correct.\n");

	SET_PIN(cardcf->bPinsFreshness, ROLE_USER);
	logprintf(pCardData, 3, "PinsFreshness = %d\n", cardcf->bPinsFreshness);
	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardGetChallenge(__in PCARD_DATA pCardData,
	__deref_out_bcount(*pcbChallengeData) PBYTE *ppbChallengeData,
	__out                                 PDWORD pcbChallengeData)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardGetChallenge - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardAuthenticateChallenge(__in PCARD_DATA  pCardData,
	__in_bcount(cbResponseData) PBYTE  pbResponseData,
	__in DWORD  cbResponseData,
	__out_opt PDWORD pcAttemptsRemaining)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardAuthenticateChallenge - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardUnblockPin(__in PCARD_DATA  pCardData,
	__in LPWSTR pwszUserId,
	__in_bcount(cbAuthenticationData) PBYTE  pbAuthenticationData,
	__in DWORD  cbAuthenticationData,
	__in_bcount(cbNewPinData) PBYTE  pbNewPinData,
	__in DWORD  cbNewPinData,
	__in DWORD  cRetryCount,
	__in DWORD  dwFlags)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardUnblockPin - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardChangeAuthenticator(__in PCARD_DATA  pCardData,
	__in LPWSTR pwszUserId,
	__in_bcount(cbCurrentAuthenticator) PBYTE pbCurrentAuthenticator,
	__in DWORD cbCurrentAuthenticator,
	__in_bcount(cbNewAuthenticator) PBYTE pbNewAuthenticator,
	__in DWORD cbNewAuthenticator,
	__in DWORD cRetryCount,
	__in DWORD dwFlags,
	__out_opt PDWORD pcAttemptsRemaining)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardChangeAuthenticator - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}


DWORD WINAPI 
CardDeauthenticate(__in PCARD_DATA pCardData,
	__in LPWSTR pwszUserId,
	__in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs;
	CARD_CACHE_FILE_FORMAT *cardcf = NULL;
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDeauthenticate%S %d\n", NULLWSTR(pwszUserId), dwFlags);

	if(!pCardData) 
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	check_reader_status(pCardData);

	dwret = md_get_cardcf(pCardData, &cardcf);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;
	logprintf(pCardData, 1, "CardDeauthenticate bPinsFreshness:%d\n", cardcf->bPinsFreshness);

	/* TODO This does not look correct, as it does not look at the pwszUserId */
	/* TODO We need to tell the card the pin is no longer valid */
	CLEAR_PIN(cardcf->bPinsFreshness, ROLE_USER);
	logprintf(pCardData, 5, "PinsFreshness = %d\n",  cardcf->bPinsFreshness);

	/*TODO Should we reset the card ? */

	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardCreateDirectory(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in CARD_DIRECTORY_ACCESS_CONDITION AccessCondition)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardCreateDirectory - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardDeleteDirectory(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDeleteDirectory(%s) - unsupported\n", NULLSTR(pszDirectoryName));
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardCreateFile(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD cbInitialCreationSize,
	__in CARD_FILE_ACCESS_CONDITION AccessCondition)
{
	struct md_directory *dir = NULL;
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardCreateFile(%s::%s, size %i, acl:0x%X) called\n", 
			NULLSTR(pszDirectoryName), NULLSTR(pszFileName), cbInitialCreationSize, AccessCondition);

	dwret = md_fs_find_directory(pCardData, NULL, pszDirectoryName, &dir);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 1, "CardCreateFile() cannot find parent directory '%s'", NULLSTR(pszDirectoryName));
		return dwret;
	}

	dwret = md_fs_add_file(pCardData, &dir->files, pszFileName, AccessCondition, NULL, cbInitialCreationSize, NULL);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	return SCARD_S_SUCCESS;
}


DWORD WINAPI 
CardReadFile(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD dwFlags,
	__deref_out_bcount(*pcbData) PBYTE *ppbData,
	__out PDWORD pcbData)
{
	VENDOR_SPECIFIC *vs;
	struct md_directory *dir = NULL;
	struct md_file *file = NULL;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardReadFile\n");

	if(!pCardData) 
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	logprintf(pCardData, 2, "pszDirectoryName = %s, pszFileName = %s, dwFlags = %X, pcbData=%d, *ppbData=%X\n",
		NULLSTR(pszDirectoryName), NULLSTR(pszFileName), dwFlags, *pcbData, *ppbData);

	if (!pszFileName || !strlen(pszFileName)) 
		return SCARD_E_INVALID_PARAMETER;
	if (!ppbData || !pcbData) 
		return SCARD_E_INVALID_PARAMETER;
	if (dwFlags) 
		return SCARD_E_INVALID_PARAMETER;

	check_reader_status(pCardData);

	md_fs_find_file(pCardData, pszDirectoryName, pszFileName, &file);
	if (!file)   {
		logprintf(pCardData, 2, "CardReadFile(): file '%s' not found in '%s'\n", NULLSTR(pszFileName), NULLSTR(pszDirectoryName));
		return SCARD_E_FILE_NOT_FOUND;
	}

	if (!file->blob)
		md_fs_read_content(pCardData, pszDirectoryName, file);

	*ppbData = pCardData->pfnCspAlloc(file->size);
	if(!*ppbData)
		return SCARD_E_NO_MEMORY;
	*pcbData = file->size;
	memcpy(*ppbData, file->blob, file->size);

	logprintf(pCardData, 7, "returns '%s' content: ",  NULLSTR(pszFileName));
	loghex(pCardData, 7, *ppbData, *pcbData);
	return SCARD_S_SUCCESS;
}


DWORD WINAPI 
CardWriteFile(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD dwFlags,
	__in_bcount(cbData) PBYTE pbData,
	__in DWORD cbData)
{
	struct md_file *file = NULL;
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardWriteFile() dirName:'%s', fileName:'%s' \n", NULLSTR(pszDirectoryName), NULLSTR(pszFileName));

	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	if (pbData && cbData)   {
		logprintf(pCardData, 1, "CardWriteFile try to write (%i)\n", cbData);
		loghex(pCardData, 2, pbData, cbData);
	}

	md_fs_find_file(pCardData, pszDirectoryName, pszFileName, &file);
	if (!file)   {
		logprintf(pCardData, 2, "CardWriteFile(): file '%s' not found in '%s'\n", NULLSTR(pszFileName), NULLSTR(pszDirectoryName));
		return SCARD_E_FILE_NOT_FOUND;
	}

	dwret = md_fs_set_content(pCardData, file, pbData, cbData);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	if (pszDirectoryName && !strcmp(pszDirectoryName, "mscp"))   {
		if (strlen(pszFileName) == 5 && 
			(strstr(pszFileName, "kxc") == pszFileName || strstr(pszFileName, "ksc") == pszFileName))   {
		
			dwret = md_store_certificate(pCardData, pszFileName, pbData, cbData);
			if (dwret != SCARD_S_SUCCESS)
				return dwret;
			logprintf(pCardData, 2, "md_store_certificate() OK\n");
		}
	}

	logprintf(pCardData, 2, "write '%s' ok.\n",  NULLSTR(pszFileName));
	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardDeleteFile(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD dwFlags)
{
	struct md_file *file = NULL;
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDeleteFile(%s, %s) called\n", NULLSTR(pszDirectoryName), NULLSTR(pszFileName));

	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	dwret = md_fs_delete_file(pCardData, pszDirectoryName, pszFileName);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 2, "CardDeleteFile(): delete file error: %X\n", dwret);
		return dwret;
	}

	return SCARD_S_SUCCESS;
}


DWORD WINAPI 
CardEnumFiles(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__out_ecount(*pdwcbFileName) LPSTR *pmszFileNames,
	__out LPDWORD pdwcbFileName,
	__in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs = NULL;
	char mstr[0x100];
	struct md_directory *dir = NULL;
	struct md_file *file = NULL;
	size_t offs; 

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardEnumFiles() directory '%s'\n", NULLSTR(pszDirectoryName));

	if (!pCardData) 
		return SCARD_E_INVALID_PARAMETER;
	if (!pmszFileNames || !pdwcbFileName) 
		return SCARD_E_INVALID_PARAMETER;
	if (dwFlags)   { 
		logprintf(pCardData, 1, "CardEnumFiles() dwFlags not 'zero' -- %X\n", dwFlags);
		return SCARD_E_INVALID_PARAMETER;
	}

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	memset(mstr, 0, sizeof(mstr));

	if (!pszDirectoryName || !strlen(pszDirectoryName))
		dir = &vs->root;
	else 
		md_fs_find_directory(pCardData, NULL, pszDirectoryName, &dir);
	if (!dir)   {
		logprintf(pCardData, 2, "enum files() failed: directory '%s' not found\n", NULLSTR(pszDirectoryName));
		return SCARD_E_FILE_NOT_FOUND;
	}
	
	file = dir->files; 
	for (offs = 0; file != NULL && offs < sizeof(mstr) - 10;)   {
		logprintf(pCardData, 2, "enum files(): file name '%s'\n", file->name);
		strcpy(mstr+offs, file->name);
		offs += strlen(file->name) + 1;
		file = file->next;
	}
	offs += 1;
		
	*pmszFileNames = (LPSTR)(*pCardData->pfnCspAlloc)(offs);
	if (*pmszFileNames == NULL) 
		return SCARD_E_NO_MEMORY;

	CopyMemory(*pmszFileNames, mstr, offs);
	*pdwcbFileName = offs;
	return SCARD_S_SUCCESS;
}


DWORD WINAPI 
CardGetFileInfo(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in PCARD_FILE_INFO pCardFileInfo)
{
	VENDOR_SPECIFIC *vs = NULL;
	struct md_directory *dir = NULL;
	struct md_file *file = NULL;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardGetFileInfo(dirName:'%s',fileName:'%s', out %p)\n", NULLSTR(pszDirectoryName), NULLSTR(pszFileName), pCardFileInfo);

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	md_fs_find_file(pCardData, pszDirectoryName, pszFileName, &file);
	if (!file)   {
		logprintf(pCardData, 2, "CardWriteFile(): file '%s' not found in '%s'\n", NULLSTR(pszFileName), NULLSTR(pszDirectoryName));
		return SCARD_E_FILE_NOT_FOUND;
	}

	pCardFileInfo->dwVersion = CARD_FILE_INFO_CURRENT_VERSION;
	pCardFileInfo->cbFileSize = file->size;
	pCardFileInfo->AccessCondition = file->acl;

	return SCARD_S_SUCCESS;
}


DWORD WINAPI 
CardQueryFreeSpace(__in PCARD_DATA pCardData, __in DWORD dwFlags,
	__in PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo)
{
	VENDOR_SPECIFIC *vs;
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardQueryFreeSpace %p, dwFlags=%X, version=%X\n",
		pCardFreeSpaceInfo, dwFlags, pCardFreeSpaceInfo->dwVersion);

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	check_reader_status(pCardData);

	dwret = md_free_space(pCardData, pCardFreeSpaceInfo);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 1, "CardQueryFreeSpace() md free space error");
		return dwret;
	}

	logprintf(pCardData, 7, "FreeSpace: ");
	loghex(pCardData, 7, (BYTE *)pCardFreeSpaceInfo, sizeof(*pCardFreeSpaceInfo));
	return SCARD_S_SUCCESS;
}


DWORD WINAPI
CardQueryKeySizes(__in PCARD_DATA pCardData,
	__in  DWORD dwKeySpec,
	__in  DWORD dwFlags,
	__out PCARD_KEY_SIZES pKeySizes)
{
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardQueryKeySizes dwKeySpec=%X, dwFlags=%X, version=%X\n",  dwKeySpec, dwFlags, pKeySizes->dwVersion);

	if (!pCardData) 
		return SCARD_E_INVALID_PARAMETER;

	dwret = md_query_key_sizes(pKeySizes);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	logprintf(pCardData, 7, "pKeySizes ");
	loghex(pCardData, 7, (BYTE *)pKeySizes, sizeof(*pKeySizes));
	return SCARD_S_SUCCESS;
}


DWORD WINAPI CardRSADecrypt(__in PCARD_DATA pCardData,
	__inout PCARD_RSA_DECRYPT_INFO  pInfo)

{
	int r, i, opt_crypt_flags = 0;
	unsigned ui;
	VENDOR_SPECIFIC *vs;
	struct sc_pkcs15_cert_info *cert_info;
	struct sc_pkcs15_prkey_info *prkey_info;
	BYTE *pbuf = NULL, *pbuf2 = NULL;
	DWORD lg= 0, lg2 = 0;
	sc_pkcs15_object_t *pkey = NULL;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardRSADecrypt\n");
	if (!pCardData) 
		return SCARD_E_INVALID_PARAMETER;
	if (!pInfo) 
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	check_reader_status(pCardData);

	logprintf(pCardData, 2, "CardRSADecrypt dwVersion=%u, bContainerIndex=%u,dwKeySpec=%u pbData=%p, cbData=%u\n",
		pInfo->dwVersion,pInfo->bContainerIndex ,pInfo->dwKeySpec, pInfo->pbData,  pInfo->cbData);

	if (pInfo->dwVersion == CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO)
		logprintf(pCardData, 2, "  pPaddingInfo=%p dwPaddingType=0x%08X\n", pInfo->pPaddingInfo, pInfo->dwPaddingType);

	if (pInfo->bContainerIndex >= vs->cert_count)
		return SCARD_E_INVALID_PARAMETER;

	cert_info = (struct sc_pkcs15_cert_info *)vs->cert_objs[pInfo->bContainerIndex]->data;
	for(i = 0; i < vs->prkey_count; i++)   {
		struct sc_pkcs15_object *obj = (struct sc_pkcs15_object *)vs->prkey_objs[i];

		if(sc_pkcs15_compare_id(&((struct sc_pkcs15_prkey_info *) obj->data)->id, &(cert_info->id)))   {
			pkey = vs->prkey_objs[i];
			break;
		}
	}

	if(pkey == NULL)   {
		logprintf(pCardData, 2, "CardRSADecrypt prkey not found\n");
		return SCARD_E_INVALID_PARAMETER;
	}
	prkey_info = (sc_pkcs15_prkey_info_t*)(pkey->data);

	/* input and output buffers are always the same size */
	pbuf = pCardData->pfnCspAlloc(pInfo->cbData);
	if (!pbuf)
		return SCARD_E_NO_MEMORY;

	lg2 = pInfo->cbData;
	pbuf2 = pCardData->pfnCspAlloc(pInfo->cbData);
	if (!pbuf2)
		return SCARD_E_NO_MEMORY;

	/*inversion donnees*/
<<<<<<< HEAD
	for(ui = 0; ui < pInfo->cbData; ui++) pbuf[ui] = pInfo->pbData[pInfo->cbData-ui-1];
	logprintf(pCardData, 2, "Data to be decrypted(%i):\n", pInfo->cbData);
	loghex(pCardData, 7, pbuf, pInfo->cbData);
	r = sc_pkcs15_decipher(vs->p15card, vs->pkey, opt_crypt_flags, pbuf, pInfo->cbData, pbuf2, pInfo->cbData);
	logprintf(pCardData, 2, "sc_pkcs15_decipher returned %d\n", r);
	/* FIXME: 
=======
	for(ui = 0; ui < pInfo->cbData; ui++) 
		pbuf[ui] = pInfo->pbData[pInfo->cbData-ui-1];
	logprintf(pCardData, 2, "Data to be decrypted (inverted):\n");
	loghex(pCardData, 7, pbuf, pInfo->cbData);

	/* TODO: check RSA mechanism allowed and do not try to decipher two times */
	r = sc_pkcs15_decipher(vs->p15card, pkey, opt_crypt_flags, pbuf, pInfo->cbData, pbuf2, pInfo->cbData);
	logprintf(pCardData, 2, "sc_pkcs15_decipher returned %d\n", r);
	/* FIXME: Invalid comments: 
>>>>>>> 483fa4b1d025d8ef43bdabe4287b9f358439efbe
	 * On-card padding do not supported by the minidriver specification version 6.
	 * Here follows a temporary (until the OpenSC minidriver will be updated to specification v7) hack 
	 * for the cards that do have no RSA_RAW mechanism allowed (IAS/ECC).
	 */
	if (r == SC_ERROR_NOT_SUPPORTED)   {
		int rr;
<<<<<<< HEAD
		rr = sc_pkcs15_decipher(vs->p15card, vs->pkey, opt_crypt_flags | SC_ALGORITHM_RSA_PAD_PKCS1, 
				pbuf, pInfo->cbData, pbuf2, pInfo->cbData);
		logprintf(pCardData, 2, "sc_pkcs15_decipher rreturned %d\n", rr);
		if (rr > 0 && rr <= pInfo->cbData - 9)   {
=======
		rr = sc_pkcs15_decipher(vs->p15card, pkey, opt_crypt_flags | SC_ALGORITHM_RSA_PAD_PKCS1, 
				pbuf, pInfo->cbData, pbuf2, pInfo->cbData);
		logprintf(pCardData, 2, "sc_pkcs15_decipher rreturned %d\n", rr);
		if (rr > 0 && (unsigned)rr <= pInfo->cbData - 9)   {
>>>>>>> 483fa4b1d025d8ef43bdabe4287b9f358439efbe
			/* add pkcs1 02 padding */
			logprintf(pCardData, 2, "Add padding '%s'", "PKCS#1 BT02 padding");
			memset(pbuf, 0x30, pInfo->cbData);
			*(pbuf + 0) = 0;
			*(pbuf + 1) = 2;
			memcpy(pbuf + pInfo->cbData - rr, pbuf2, rr);
			*(pbuf + pInfo->cbData - rr - 1) = 0;
			memcpy(pbuf2, pbuf, pInfo->cbData);

			r = rr;
		}
	}
	if ( r < 0)   {
		logprintf(pCardData, 2, "sc_pkcs15_decipher erreur %s\n", sc_strerror(r));
		return SCARD_E_INVALID_VALUE;
	}

	logprintf(pCardData, 2, "decrypted data(%i):\n", pInfo->cbData);
	loghex(pCardData, 7, pbuf2, pInfo->cbData);

	/*inversion donnees */
        for(ui = 0; ui < pInfo->cbData; ui++) 
		pInfo->pbData[ui] = pbuf2[pInfo->cbData-ui-1];

	pCardData->pfnCspFree(pbuf);
	pCardData->pfnCspFree(pbuf2);
	return SCARD_S_SUCCESS;
}


DWORD WINAPI 
CardSignData(__in PCARD_DATA pCardData, __in PCARD_SIGNING_INFO pInfo)
{
	VENDOR_SPECIFIC *vs;
	ALG_ID hashAlg;
	sc_pkcs15_cert_info_t *cert_info;
	sc_pkcs15_prkey_info_t *prkey_info;
	BYTE dataToSign[0x200];
	int r, opt_crypt_flags = 0, opt_hash_flags = 0;
	size_t dataToSignLen = sizeof(dataToSign);
	sc_pkcs15_object_t *pkey;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardSignData\n");

	if (!pCardData) 
		return SCARD_E_INVALID_PARAMETER;
	if (!pInfo) 
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 2, "CardSignData dwVersion=%u, bContainerIndex=%u, dwKeySpec=%u, dwSigningFlags=0x%08X, aiHashAlg=0x%08X\n",
		pInfo->dwVersion,pInfo->bContainerIndex ,pInfo->dwKeySpec, pInfo->dwSigningFlags, pInfo->aiHashAlg);

	logprintf(pCardData, 7, "pInfo->pbData(%i) ", pInfo->cbData);
	loghex(pCardData, 7, pInfo->pbData, pInfo->cbData);

	hashAlg = pInfo->aiHashAlg;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	check_reader_status(pCardData);

	pkey = NULL;

	logprintf(pCardData, 2, "pInfo->dwVersion = %d\n", pInfo->dwVersion);

	if (dataToSignLen < pInfo->cbData) return SCARD_E_INSUFFICIENT_BUFFER;
	memcpy(dataToSign, pInfo->pbData, pInfo->cbData);
	dataToSignLen = pInfo->cbData;

	if (CARD_PADDING_INFO_PRESENT & pInfo->dwSigningFlags)   {
		BCRYPT_PKCS1_PADDING_INFO *pinf = (BCRYPT_PKCS1_PADDING_INFO *)pInfo->pPaddingInfo;
		if (CARD_PADDING_PKCS1 != pInfo->dwPaddingType)   {
			logprintf(pCardData, 0, "unsupported paddingtype\n");
			return SCARD_E_UNSUPPORTED_FEATURE;
		}
		if (!pinf->pszAlgId)   {
			/* hashAlg = CALG_SSL3_SHAMD5; */
			logprintf(pCardData, 3, "Using CALG_SSL3_SHAMD5  hashAlg\n");
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_MD5_SHA1;
		}
		else   {
			if (wcscmp(pinf->pszAlgId, L"MD5") == 0)  
				opt_hash_flags = SC_ALGORITHM_RSA_HASH_MD5;
			else if (wcscmp(pinf->pszAlgId, L"SHA1") == 0)  
				opt_hash_flags = SC_ALGORITHM_RSA_HASH_SHA1;
			else if (wcscmp(pinf->pszAlgId, L"SHAMD5") == 0) 
				opt_hash_flags = SC_ALGORITHM_RSA_HASH_MD5_SHA1;
			else
				logprintf(pCardData, 0,"unknown AlgId %S\n",NULLWSTR(pinf->pszAlgId));
		}
	}
	else   {
		logprintf(pCardData, 3, "CARD_PADDING_INFO_PRESENT not set\n");

		if (GET_ALG_CLASS(hashAlg) != ALG_CLASS_HASH)   {
			logprintf(pCardData, 0, "bogus aiHashAlg\n");
			return SCARD_E_INVALID_PARAMETER;
		}

		if (hashAlg == CALG_MD5)
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_MD5;
		else if (hashAlg == CALG_SHA1)
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_SHA1;
		else if (hashAlg == CALG_SSL3_SHAMD5)
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_MD5_SHA1;
		else if (hashAlg !=0)
			return SCARD_E_UNSUPPORTED_FEATURE;
	}

	/* From sc-minidriver_specs_v7.docx pp.76:
	 * 'The Base CSP/KSP performs the hashing operation on the data before passing it
	 * 	to CardSignData for signature.'
         * So, the SC_ALGORITHM_RSA_HASH_* flags should not be passed to pkcs15 library
	 * 	when calculating the signature .
	 *
	 * From sc-minidriver_specs_v7.docx pp.76:
	 * 'If the aiHashAlg member is nonzero, it specifies the hash algorithm’s object identifier (OID)
	 *  that is encoded in the PKCS padding.'
	 * So, the digest info has be included into the data to be signed.
	 * */
	if (opt_hash_flags)   {
		logprintf(pCardData, 2, "include digest info of the algorithm 0x%08X\n", opt_hash_flags);
		dataToSignLen = sizeof(dataToSign);
		r = sc_pkcs1_encode(vs->p15card->card->ctx, opt_hash_flags, pInfo->pbData, pInfo->cbData, dataToSign, &dataToSignLen, 0);
		if (r)   {
			logprintf(pCardData, 2, "PKCS#1 encode error %s\n", sc_strerror(r));
			return SCARD_E_INVALID_VALUE;
		}
	}
	opt_crypt_flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE;

	if(pInfo->bContainerIndex >= vs->cert_count)   {
		if (vs->generated_key)   {
			pkey = vs->generated_key;
		}
		else   {
			logprintf(pCardData, 2, "invalid container index\n", pInfo->bContainerIndex, vs->cert_count);
			return SCARD_E_INVALID_PARAMETER;
		}
	}
	else   {
		cert_info = (struct sc_pkcs15_cert_info *) (vs->cert_objs[pInfo->bContainerIndex]->data);
		r = sc_pkcs15_find_prkey_by_id(vs->p15card, &cert_info->id, &pkey);
		if (r)   {
			logprintf(pCardData, 2, "cannot find private key friend of the certificate\n");
			return SCARD_E_INVALID_PARAMETER;
		}
	}

	prkey_info = (sc_pkcs15_prkey_info_t*)(pkey->data);

	pInfo->cbSignedData = prkey_info->modulus_length / 8;
	logprintf(pCardData, 3, "pInfo->cbSignedData = %d\n", pInfo->cbSignedData);

	if(!(pInfo->dwSigningFlags&CARD_BUFFER_SIZE_ONLY))   {
		int r,i;
		BYTE *pbuf = NULL;
		DWORD lg;

		lg = pInfo->cbSignedData;
		logprintf(pCardData, 3, "lg = %d\n", lg);
		pbuf = pCardData->pfnCspAlloc(lg);
		if (!pbuf)
			return SCARD_E_NO_MEMORY;

		logprintf(pCardData, 7, "Data to sign: ");
		loghex(pCardData, 7, dataToSign, dataToSignLen);

		pInfo->pbSignedData = pCardData->pfnCspAlloc(pInfo->cbSignedData);
		if (!pInfo->pbSignedData)   {
			pCardData->pfnCspFree(pbuf);
			return SCARD_E_NO_MEMORY;
		}

		r = sc_pkcs15_compute_signature(vs->p15card, pkey, opt_crypt_flags, dataToSign, dataToSignLen, pbuf, lg);
		logprintf(pCardData, 2, "sc_pkcs15_compute_signature return %d\n", r);
		if(r < 0)   {
			logprintf(pCardData, 2, "sc_pkcs15_compute_signature erreur %s\n", sc_strerror(r));
			return SCARD_F_INTERNAL_ERROR;
		}

		pInfo->cbSignedData = r;

		/*inversion donnees*/
		for(i = 0; i < r; i++) 
			pInfo->pbSignedData[i] = pbuf[r-i-1];
		pCardData->pfnCspFree(pbuf);

		logprintf(pCardData, 7, "Signature (inverted): ");
		loghex(pCardData, 7, pInfo->pbSignedData, pInfo->cbSignedData);
	}

	logprintf(pCardData, 3, "CardSignData, dwVersion=%u, name=%S, hScard=0x%08X, hSCardCtx=0x%08X\n", 
			pCardData->dwVersion, NULLWSTR(pCardData->pwszCardName),pCardData->hScard, pCardData->hSCardCtx);

	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardConstructDHAgreement(__in PCARD_DATA pCardData,
	__in PCARD_DH_AGREEMENT_INFO pAgreementInfo)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardConstructDHAgreement - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardDeriveKey(__in PCARD_DATA pCardData,
	__in PCARD_DERIVE_KEY pAgreementInfo)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDeriveKey - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardDestroyDHAgreement(
	__in PCARD_DATA pCardData,
	__in BYTE bSecretAgreementIndex,
	__in DWORD dwFlags)
{
	logprintf(pCardData, 1, "CardDestroyDHAgreement - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CspGetDHAgreement(__in  PCARD_DATA pCardData,
	__in  PVOID hSecretAgreement,
	__out BYTE* pbSecretAgreementIndex,
	__in  DWORD dwFlags)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CspGetDHAgreement - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardGetChallengeEx(__in PCARD_DATA pCardData,
	__in PIN_ID PinId,
	__deref_out_bcount(*pcbChallengeData) PBYTE *ppbChallengeData,
	__out PDWORD pcbChallengeData,
	__in DWORD dwFlags)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardGetChallengeEx - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardAuthenticateEx(__in PCARD_DATA pCardData,
	__in   PIN_ID PinId,
	__in   DWORD dwFlags,
	__in   PBYTE pbPinData,
	__in   DWORD cbPinData,
	__deref_out_bcount_opt(*pcbSessionPin) PBYTE *ppbSessionPin,
	__out_opt PDWORD pcbSessionPin,
	__out_opt PDWORD pcAttemptsRemaining)
{
	int r;
	VENDOR_SPECIFIC *vs;
	CARD_CACHE_FILE_FORMAT *cardcf = NULL;
	DWORD dwret;
	sc_pkcs15_object_t *pin_obj = NULL;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardAuthenticateEx\n");

	if (!pCardData) return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 2, "CardAuthenticateEx: PinId=%u, dwFlags=0x%08X, cbPinData=%u, Attempts %s\n",
		PinId,dwFlags,cbPinData,pcAttemptsRemaining ? "YES" : "NO");

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	check_reader_status(pCardData);

	if (dwFlags == CARD_AUTHENTICATE_GENERATE_SESSION_PIN ||
		dwFlags == CARD_AUTHENTICATE_SESSION_PIN)
			return SCARD_E_UNSUPPORTED_FEATURE;
	if (dwFlags && dwFlags != CARD_PIN_SILENT_CONTEXT)
		return SCARD_E_INVALID_PARAMETER;

	if (NULL == pbPinData) return SCARD_E_INVALID_PARAMETER;

	if (PinId != ROLE_USER) return SCARD_E_INVALID_PARAMETER;

	r = get_pin_by_role(pCardData, ROLE_USER, &pin_obj);
	if (r != SCARD_S_SUCCESS)
	{
		logprintf(pCardData, 2, "Cannot get User PIN object");
		return r;
	}

	r = sc_pkcs15_verify_pin(vs->p15card, pin_obj, (const u8 *) pbPinData, cbPinData);
	if (r)   {
		logprintf(pCardData, 2, "PIN code verification failed: %s\n", sc_strerror(r));

		if(pcAttemptsRemaining)
			(*pcAttemptsRemaining) = -1;
		return SCARD_W_WRONG_CHV;
	}

	logprintf(pCardData, 2, "Pin code correct.\n");

	dwret = md_get_cardcf(pCardData, &cardcf);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	SET_PIN(cardcf->bPinsFreshness, ROLE_USER);
	logprintf(pCardData, 7, "PinsFreshness = %d\n", cardcf->bPinsFreshness);
	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardChangeAuthenticatorEx(__in PCARD_DATA pCardData,
	__in   DWORD dwFlags,
	__in   PIN_ID dwAuthenticatingPinId,
	__in_bcount(cbAuthenticatingPinData) PBYTE pbAuthenticatingPinData,
	__in   DWORD cbAuthenticatingPinData,
	__in   PIN_ID dwTargetPinId,
	__in_bcount(cbTargetData) PBYTE pbTargetData,
	__in   DWORD cbTargetData,
	__in   DWORD cRetryCount,
	__out_opt PDWORD pcAttemptsRemaining)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardChangeAuthenticatorEx - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardDeauthenticateEx(__in PCARD_DATA pCardData,
	__in PIN_SET PinId,
	__in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs;
	CARD_CACHE_FILE_FORMAT *cardcf = NULL;
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDeauthenticateEx PinId=%d dwFlags=0x%08X\n",PinId, dwFlags);

	if (!pCardData) return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	check_reader_status(pCardData);

	dwret = md_get_cardcf(pCardData, &cardcf);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	/*TODO Should we reset the card? */
	cardcf->bPinsFreshness &= ~PinId;
	logprintf(pCardData, 7, "PinsFreshness = %d\n", cardcf->bPinsFreshness);
	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardGetContainerProperty(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in LPCWSTR wszProperty,
	__out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData,
	__in DWORD cbData,
	__out PDWORD pdwDataLen,
	__in DWORD dwFlags)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardGetContainerProperty\n");

	check_reader_status(pCardData);

	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	logprintf(pCardData, 2, "CardGetContainerProperty bContainerIndex=%u, wszProperty=%S," \
		"cbData=%u, dwFlags=0x%08X\n",bContainerIndex,NULLWSTR(wszProperty),cbData,dwFlags);
	if (!wszProperty) return SCARD_E_INVALID_PARAMETER;
	if (dwFlags) return SCARD_E_INVALID_PARAMETER;
	if (!pbData) return SCARD_E_INVALID_PARAMETER;
	if (!pdwDataLen) return SCARD_E_INVALID_PARAMETER;

	if (wcscmp(CCP_CONTAINER_INFO,wszProperty)  == 0)
	{
		PCONTAINER_INFO p = (PCONTAINER_INFO) pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData >= sizeof(DWORD))
			if (p->dwVersion != CONTAINER_INFO_CURRENT_VERSION &&
				p->dwVersion != 0 ) return ERROR_REVISION_MISMATCH;
		if (cbData < sizeof(*p)) return ERROR_INSUFFICIENT_BUFFER;
		return CardGetContainerInfo(pCardData,bContainerIndex,0,p);
	}

	if (wcscmp(CCP_PIN_IDENTIFIER,wszProperty) == 0)
	{
		PPIN_ID p = (PPIN_ID) pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ERROR_INSUFFICIENT_BUFFER;
		*p = ROLE_USER;
		logprintf(pCardData, 2,"Return Pin id %u\n",*p);
		return SCARD_S_SUCCESS;
	}

	return SCARD_E_INVALID_PARAMETER;
}

DWORD WINAPI CardSetContainerProperty(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in LPCWSTR wszProperty,
	__in_bcount(cbDataLen) PBYTE pbData,
	__in DWORD cbDataLen,
	__in DWORD dwFlags)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardSetContainerProperty - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}


DWORD WINAPI CardGetProperty(__in PCARD_DATA pCardData,
	__in LPCWSTR wszProperty,
	__out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData,
	__in DWORD cbData,
	__out PDWORD pdwDataLen,
	__in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs;
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 2, "CardGetProperty('%S',cbData=%u,dwFlags=%u) called\n", NULLWSTR(wszProperty),cbData,dwFlags);

	if (!pCardData) 
		return SCARD_E_INVALID_PARAMETER;
	if (!wszProperty)
		return SCARD_E_INVALID_PARAMETER;
	if (!pbData || !pdwDataLen)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	check_reader_status(pCardData);

	if (wcscmp(CP_CARD_FREE_SPACE,wszProperty) == 0)   {
		PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo = (PCARD_FREE_SPACE_INFO )pbData;
		if (pdwDataLen) 
			*pdwDataLen = sizeof(*pCardFreeSpaceInfo);
		if (cbData < sizeof(*pCardFreeSpaceInfo)) 
			return SCARD_E_NO_MEMORY;

		dwret = md_free_space(pCardData, pCardFreeSpaceInfo);
		if (dwret != SCARD_S_SUCCESS)   {
			logprintf(pCardData, 1, "Get free space error");
			return dwret;
		}
	}
	else if (wcscmp(CP_CARD_CAPABILITIES, wszProperty) == 0)   {
		PCARD_CAPABILITIES pCardCapabilities = (PCARD_CAPABILITIES )pbData;

		if (pdwDataLen) 
			*pdwDataLen = sizeof(*pCardCapabilities);
		if (cbData < sizeof(*pCardCapabilities)) 
			return ERROR_INSUFFICIENT_BUFFER;
		dwret = md_card_capabilities(pCardCapabilities);
		if (dwret != SCARD_S_SUCCESS)
			return dwret;
	}
	else if (wcscmp(CP_CARD_KEYSIZES,wszProperty) == 0)   {
		PCARD_KEY_SIZES pKeySizes = (PCARD_KEY_SIZES )pbData;
		if (pdwDataLen) 
			*pdwDataLen = sizeof(*pKeySizes);
		if (cbData < sizeof(*pKeySizes)) 
			return ERROR_INSUFFICIENT_BUFFER;

		dwret = md_query_key_sizes(pKeySizes);
		if (dwret != SCARD_S_SUCCESS)
			return dwret;
	}
	else if (wcscmp(CP_CARD_READ_ONLY, wszProperty) == 0)   {
		BOOL *p = (BOOL*)pbData;
		if (pdwDataLen) 
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) 
			return ERROR_INSUFFICIENT_BUFFER;

		*p = TRUE; /* XXX HACK */
		if (vs->ctx && vs->reader)   {
			/* TODO: use atr from pCardData */
			scconf_block *atrblock = _sc_match_atr_block(vs->ctx, NULL, &vs->reader->atr);
			if (atrblock)
				if (scconf_get_bool(atrblock, "md_read_only", 1) == 0)
					*p = FALSE;
		}
	}
	else if (wcscmp(CP_CARD_CACHE_MODE, wszProperty) == 0)   {
		DWORD *p = (DWORD *)pbData;
		if (pdwDataLen) 
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) 
			return ERROR_INSUFFICIENT_BUFFER;
		*p = CP_CACHE_MODE_NO_CACHE;
	}
	else if (wcscmp(CP_SUPPORTS_WIN_X509_ENROLLMENT, wszProperty) == 0)   {
		DWORD *p = (DWORD *)pbData;
		if (pdwDataLen) 
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) 
			return ERROR_INSUFFICIENT_BUFFER;
		*p = 0;
	}
	else if (wcscmp(CP_CARD_GUID, wszProperty) == 0)   {
		struct md_file *cardid = NULL;

		md_fs_find_file(pCardData, NULL, "cardid", &cardid);
		if (!cardid)   {
			logprintf(pCardData, 2, "file 'cardid' not found\n");
			return SCARD_E_FILE_NOT_FOUND;
		}

		if (pdwDataLen) 
			*pdwDataLen = cardid->size;
		if (cbData < cardid->size)
			return ERROR_INSUFFICIENT_BUFFER;

		CopyMemory(pbData, cardid->blob, cardid->size);
	}
	else if (wcscmp(CP_CARD_SERIAL_NO, wszProperty) == 0)   {
		unsigned char buf[64];
		size_t buf_len = sizeof(buf);
		size_t sn_len = strlen(vs->p15card->tokeninfo->serial_number)/2;

		if (sc_hex_to_bin(vs->p15card->tokeninfo->serial_number, buf, &buf_len))   {
			logprintf(pCardData, 0, "Hex to Bin conversion error");
			return SCARD_F_INTERNAL_ERROR;
		}

		if (pdwDataLen) 
			*pdwDataLen = buf_len;
		if (cbData < buf_len) 
			return ERROR_INSUFFICIENT_BUFFER;

		CopyMemory(pbData, buf, buf_len);
	}
	else if (wcscmp(CP_CARD_PIN_INFO,wszProperty) == 0)   {
		PPIN_INFO p = (PPIN_INFO) pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ERROR_INSUFFICIENT_BUFFER;
		if (p->dwVersion != PIN_INFO_CURRENT_VERSION) return ERROR_REVISION_MISMATCH;
		p->PinType = AlphaNumericPinType;
		p->dwFlags = 0;
		switch (dwFlags)   {
			case ROLE_USER:
				logprintf(pCardData, 2,"returning info on PIN ROLE_USER ( Auth ) [%u]\n",dwFlags);
				p->PinPurpose = DigitalSignaturePin;
				p->PinCachePolicy.dwVersion = PIN_CACHE_POLICY_CURRENT_VERSION;
				p->PinCachePolicy.dwPinCachePolicyInfo = 0;
				p->PinCachePolicy.PinCachePolicyType = PinCacheNormal;
				p->dwChangePermission = 0;
				p->dwUnblockPermission = 0;
				break;
			default:
				logprintf(pCardData, 0,"Invalid Pin number %u requested\n",dwFlags);
				return SCARD_E_INVALID_PARAMETER;
		}
	}
	else if (wcscmp(CP_CARD_LIST_PINS,wszProperty) == 0)   {
		PPIN_SET p = (PPIN_SET) pbData;
		if (pdwDataLen) 
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) 
			return ERROR_INSUFFICIENT_BUFFER;
		SET_PIN(*p, ROLE_USER);
	}
	else if (wcscmp(CP_CARD_AUTHENTICATED_STATE,wszProperty) == 0)   {
		PPIN_SET p = (PPIN_SET) pbData;
		if (pdwDataLen) 
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) 
			return ERROR_INSUFFICIENT_BUFFER;

		logprintf(pCardData, 7, "CARD_AUTHENTICATED_STATE invalid\n");
		return SCARD_E_INVALID_PARAMETER;
	}
	else if (wcscmp(CP_CARD_PIN_STRENGTH_VERIFY,wszProperty) == 0)   {
		DWORD *p = (DWORD *)pbData;
		
		if (dwFlags != ROLE_USER)
			return SCARD_E_INVALID_PARAMETER;
		if (pdwDataLen) 
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) 
			return ERROR_INSUFFICIENT_BUFFER;
		*p = CARD_PIN_STRENGTH_PLAINTEXT;
	}
	else   {
		logprintf(pCardData, 3, "Unsupported property '%S'\n", wszProperty);
		return SCARD_E_INVALID_PARAMETER;
		
	}

	logprintf(pCardData, 7, "returns '%S' ", wszProperty);
	loghex(pCardData, 7, pbData, *pdwDataLen);
	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardSetProperty(__in   PCARD_DATA pCardData,
	__in LPCWSTR wszProperty,
	__in_bcount(cbDataLen)  PBYTE pbData,
	__in DWORD cbDataLen,
	__in DWORD dwFlags)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardSetProperty\n");

	if (!pCardData) return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 2, "CardSetProperty wszProperty=%S, cbDataLen=%u, dwFlags=%u",\
		NULLWSTR(wszProperty),cbDataLen,dwFlags);

	if (!wszProperty) return SCARD_E_INVALID_PARAMETER;

	if (wcscmp(CP_CARD_PIN_STRENGTH_VERIFY, wszProperty) == 0 ||
		wcscmp(CP_CARD_PIN_INFO, wszProperty) == 0) return SCARD_E_INVALID_PARAMETER;

	if (dwFlags) return SCARD_E_INVALID_PARAMETER;

	if (wcscmp(CP_PIN_CONTEXT_STRING, wszProperty) == 0)
		return SCARD_S_SUCCESS;

	if (wcscmp(CP_CARD_CACHE_MODE, wszProperty) == 0 ||
		wcscmp(CP_SUPPORTS_WIN_X509_ENROLLMENT, wszProperty) == 0 ||
		wcscmp(CP_CARD_GUID, wszProperty) == 0 ||
		wcscmp(CP_CARD_SERIAL_NO, wszProperty) == 0) {
			return SCARD_E_INVALID_PARAMETER;
	}

	if (!pbData) return SCARD_E_INVALID_PARAMETER;
	if (!cbDataLen) return SCARD_E_INVALID_PARAMETER;

	if (wcscmp(CP_PARENT_WINDOW, wszProperty) == 0) {
		if (cbDataLen != sizeof(DWORD))
			return SCARD_E_INVALID_PARAMETER;
		else
		{
			HWND cp = *((HWND *) pbData);
			if (cp!=0 && !IsWindow(cp))  return SCARD_E_INVALID_PARAMETER;
		}
		return SCARD_S_SUCCESS;
	}

	logprintf(pCardData, 3, "INVALID PARAMETER\n");
	return SCARD_E_INVALID_PARAMETER;
}

#define MINIMUM_VERSION_SUPPORTED (4)
#define CURRENT_VERSION_SUPPORTED (7)

DWORD WINAPI 
CardAcquireContext(IN PCARD_DATA pCardData, __in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs;
	DWORD dwret, suppliedVersion = 0;
	//u8 challenge[8];

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;
	if (dwFlags)
		return SCARD_E_INVALID_PARAMETER;

	suppliedVersion = pCardData->dwVersion;

	/* VENDOR SPECIFIC */
	vs = pCardData->pvVendorSpecific = pCardData->pfnCspAlloc(sizeof(VENDOR_SPECIFIC));
	memset(vs, 0, sizeof(VENDOR_SPECIFIC));

	logprintf(pCardData, 1, "==================================================================\n");
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardAcquireContext, dwVersion=%u, name=%S,hScard=0x%08X, hSCardCtx=0x%08X\n", 
			pCardData->dwVersion, NULLWSTR(pCardData->pwszCardName),pCardData->hScard, pCardData->hSCardCtx);

	vs->hScard = pCardData->hScard;
	vs->hSCardCtx = pCardData->hSCardCtx;

	/* The lowest supported version is 4. */
	if (pCardData->dwVersion < MINIMUM_VERSION_SUPPORTED)
		return (DWORD) ERROR_REVISION_MISMATCH;

	if( pCardData->hScard == 0)   {
		logprintf(pCardData, 0, "Invalide handle.\n");
		return SCARD_E_INVALID_HANDLE;
	}

	logprintf(pCardData, 2, "request version pCardData->dwVersion = %d\n", pCardData->dwVersion);
	pCardData->dwVersion = min(pCardData->dwVersion, CURRENT_VERSION_SUPPORTED);
	logprintf(pCardData, 2, "pCardData->dwVersion = %d\n", pCardData->dwVersion);

	dwret = md_create_context(pCardData, vs);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	pCardData->pfnCardDeleteContext = CardDeleteContext;
	pCardData->pfnCardQueryCapabilities = CardQueryCapabilities;
	pCardData->pfnCardDeleteContainer = CardDeleteContainer;
	pCardData->pfnCardCreateContainer = CardCreateContainer;
	pCardData->pfnCardGetContainerInfo = CardGetContainerInfo;
	pCardData->pfnCardAuthenticatePin = CardAuthenticatePin;
	pCardData->pfnCardGetChallenge = CardGetChallenge;
	pCardData->pfnCardAuthenticateChallenge = CardAuthenticateChallenge;
	pCardData->pfnCardUnblockPin = CardUnblockPin;
	pCardData->pfnCardChangeAuthenticator = CardChangeAuthenticator;
	pCardData->pfnCardDeauthenticate = CardDeauthenticate; /* NULL */
	pCardData->pfnCardCreateDirectory = CardCreateDirectory;
	pCardData->pfnCardDeleteDirectory = CardDeleteDirectory;
	pCardData->pvUnused3 = NULL;
	pCardData->pvUnused4 = NULL;
	pCardData->pfnCardCreateFile = CardCreateFile;
	pCardData->pfnCardReadFile = CardReadFile;
	pCardData->pfnCardWriteFile = CardWriteFile;
	pCardData->pfnCardDeleteFile = CardDeleteFile;
	pCardData->pfnCardEnumFiles = CardEnumFiles;
	pCardData->pfnCardGetFileInfo = CardGetFileInfo;
	pCardData->pfnCardQueryFreeSpace = CardQueryFreeSpace;
	pCardData->pfnCardQueryKeySizes = CardQueryKeySizes;
	pCardData->pfnCardSignData = CardSignData;
	pCardData->pfnCardRSADecrypt = CardRSADecrypt;
	pCardData->pfnCardConstructDHAgreement = CardConstructDHAgreement;

	associate_card(pCardData);

	dwret = md_fs_init(pCardData);
	if (dwret != SCARD_S_SUCCESS) 
		return dwret;

	logprintf(pCardData, 1, "OpenSC init done.\n");

	if (suppliedVersion > 4) {
		pCardData->pfnCardDeriveKey = CardDeriveKey;
		pCardData->pfnCardDestroyDHAgreement = CardDestroyDHAgreement;
		pCardData->pfnCspGetDHAgreement = CspGetDHAgreement;

		if (suppliedVersion > 5 ) {
			pCardData->pfnCardGetChallengeEx = CardGetChallengeEx;
			pCardData->pfnCardAuthenticateEx = CardAuthenticateEx;
			pCardData->pfnCardChangeAuthenticatorEx = CardChangeAuthenticatorEx;
			pCardData->pfnCardDeauthenticateEx = CardDeauthenticateEx;
			pCardData->pfnCardGetContainerProperty = CardGetContainerProperty;
			pCardData->pfnCardSetContainerProperty = CardSetContainerProperty;
			pCardData->pfnCardGetProperty = CardGetProperty;
			pCardData->pfnCardSetProperty = CardSetProperty;
		}
	}

	return SCARD_S_SUCCESS;
}

static int associate_card(PCARD_DATA pCardData)
{
	VENDOR_SPECIFIC *vs;
	int  r;

	logprintf(pCardData, 1, "associate_card\n");
	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	/*
	 * set the addresses of the reader and card handles
	 * Our cardmod pcsc code will use these  when we call sc_ctx_use_reader
	 * We use the address of the handles as provided in the pCardData
	 */
	vs->hSCardCtx = pCardData->hSCardCtx;
	vs->hScard = pCardData->hScard;

	/* set the provided reader and card handles into ctx */
	logprintf(pCardData, 5, "cardmod_use_handles %d\n", 
			sc_ctx_use_reader(vs->ctx, &vs->hSCardCtx, &vs->hScard));

	/* should be only one reader */
	logprintf(pCardData, 5, "sc_ctx_get_reader_count(ctx): %d\n",
			sc_ctx_get_reader_count(vs->ctx));

	vs->reader = sc_ctx_get_reader(vs->ctx, 0);
	if(vs->reader)   {
		logprintf(pCardData, 3, "%s\n", NULLSTR(vs->reader->name));

		r = sc_connect_card(vs->reader, &(vs->card));
		logprintf(pCardData, 2, "sc_connect_card result = %d, %s\n",
				r, sc_strerror(r));
		if(!r)   {
			r = sc_pkcs15_bind(vs->card, NULL, &(vs->p15card));
			logprintf(pCardData, 2, "PKCS#15 initialization result: %d, %s\n",
					r, sc_strerror(r));
		}
	}

	if(vs->card == NULL || vs->p15card == NULL)   {
		logprintf(pCardData, 0, "Card unknow.\n");
		return SCARD_E_UNKNOWN_CARD;
	}

	/*
	 * We want a 16 byte unique serial number
	 * PKCS15 gives us a char string, that
	 * appears to have been formated with %02x or %02X
	 * so as to make it printable.
	 * So for now we will try and convert back to bin,
	 * and use the last 32 bytes of the vs-p15card->tokeninfo->serial_number
	 * TODO needs to be looked at closer
	 */

#if 0
	if (vs->p15card->tokeninfo && vs->p15card->tokeninfo->serial_number) {
		size_t len1, len2;
		char * cserial;

		len1 = strlen(vs->p15card->tokeninfo->serial_number);
		cserial = vs->p15card->tokeninfo->serial_number;
		len2 = sizeof(vs->cardFiles.file_cardid) * 2;
		if ( len1 > len2) {
			cserial += len1 - len2;
			len1 = len2;
		}
		len1 /= 2;
		r = sc_hex_to_bin(cserial, vs->cardFiles.file_cardid, &len1);
		logprintf(pCardData, 7, "serial number r=%d len1=%d len2=%d ",r, len1, len2);
		loghex(pCardData, 7, vs->cardFiles.file_cardid, sizeof(vs->cardFiles.file_cardid));
	}
#endif

	r = sc_pkcs15_get_objects(vs->p15card, SC_PKCS15_TYPE_CERT_X509, vs->cert_objs, 32);
	if (r < 0)   {
		logprintf(pCardData, 0, "Certificate enumeration failed: %s\n", sc_strerror(r));
		return SCARD_F_UNKNOWN_ERROR;
	}

	vs->cert_count = r;
	logprintf(pCardData, 2, "Found %d certificat(s) in the card.\n", vs->cert_count);

	r = sc_pkcs15_get_objects(vs->p15card, SC_PKCS15_TYPE_PRKEY_RSA, vs->prkey_objs, 32);
	if (r < 0)   {
		logprintf(pCardData, 0, "Private key enumeration failed: %s\n", sc_strerror(r));
		return SCARD_F_UNKNOWN_ERROR;
	}

	vs->prkey_count = r;
	logprintf(pCardData, 2, "Found %d private key(s) in the card.\n", vs->prkey_count);

	r = sc_pkcs15_get_objects(vs->p15card, SC_PKCS15_TYPE_AUTH_PIN, vs->pin_objs, 8);
	if (r < 0)   {
		logprintf(pCardData, 2, "Pin object enumeration failed: %s\n", sc_strerror(r));
		return SCARD_F_UNKNOWN_ERROR;
	}

	vs->pin_count = r;
	logprintf(pCardData, 2, "Found %d pin(s) in the card.\n", vs->pin_count);

#if 1
	dump_objects(pCardData);
#endif

	return SCARD_S_SUCCESS;

}

static int disassociate_card(PCARD_DATA pCardData)
{

    VENDOR_SPECIFIC *vs;
	int i;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	logprintf(pCardData, 1, "disassociate_card\n");

	if(vs->pin != NULL)
	{
		free(vs->pin);
		vs->pin = NULL;
	}

	for (i = 0; i < vs->cert_count; i++) {
		vs->cert_objs[i] = NULL;
	}
	vs->cert_count = 0;

	for (i = 0; i < vs->prkey_count; i++) {
		vs->prkey_objs[i] = NULL;
	}
	vs->prkey_count = 0;

	for (i = 0; i < vs->pin_count; i++) {
		vs->pin_objs[i] = NULL;
	}
	vs->pin_count = 0;


	if(vs->p15card)
	{
		logprintf(pCardData, 6, "sc_pkcs15_unbind\n");
		sc_pkcs15_unbind(vs->p15card);
		vs->p15card = NULL;
	}

	if(vs->card)
	{
		logprintf(pCardData, 6, "sc_disconnect_card\n");
		sc_disconnect_card(vs->card);
		vs->card = NULL;
	}

	vs->reader = NULL;

	vs->hSCardCtx = -1;
	vs->hScard = -1;

	return SCARD_S_SUCCESS;
}


BOOL APIENTRY DllMain( HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
#ifdef CARDMOD_LOW_LEVEL_DEBUG
	logprintf(NULL,8,"\n********** DllMain hModule=0x%08X reason=%d Reserved=%p P:%d T:%d\n",
		hModule, ul_reason_for_call, lpReserved, GetCurrentProcessId(), GetCurrentThreadId());
#endif
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
#ifdef CARDMOD_LOW_LEVEL_DEBUG
			{
				CHAR name[MAX_PATH + 1] = "\0";
				GetModuleFileName(GetModuleHandle(NULL),name,MAX_PATH);
				logprintf(NULL,1,"** DllMain Attach ModuleFileName=%s\n",name);
			}
#endif
			break;
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
			break;
       case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}

#ifdef _MANAGED
#pragma managed(pop)
#endif
#endif

