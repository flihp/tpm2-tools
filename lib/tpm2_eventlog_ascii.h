/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef TPM2_EVENTLOG_ASCII_H
#define TPM2_EVENTLOG_ASCII_H

#include <stdbool.h>
#include <stdlib.h>

#include "tcg-efi-event.h"
#include "tpm2_eventlog.h"

#define MAX_LINE_LENGTH 200

char* eventtype_to_string (UINT32 event_type);
char* get_alg_name(UINT16 alg_id);
bool dump_bytes(uint8_t const *buf, size_t buf_size, size_t width, size_t indent);

bool ascii_tpm2_digest(TCG_DIGEST2 const *digest, size_t size);
bool ascii_tpm2_digest_callback(TCG_DIGEST2 const *digest, size_t size, void *data);
bool ascii_tpm2_event_header(TCG_EVENT_HEADER2 const *event_hdr, size_t size);
bool ascii_tpm2_eventbuf(TCG_EVENT2 const *event, size_t size);
bool ascii_event_callback(TCG_EVENT_HEADER2 *event_hdr,
                                 size_t size,
                                 void *data);

#endif
