/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef TPM2_EVENTLOG_H
#define TPM2_EVENTLOG_H

#include <stdbool.h>
#include <stdlib.h>

#include <tss2/tss2_tpm2_types.h>

#include "tcg-efi-event.h"

#define TCG_DIGEST2_SHA1_SIZE (sizeof(TCG_DIGEST2) + TPM2_SHA_DIGEST_SIZE)

typedef struct {
    size_t digests_size;
    size_t digest_count;
} digestcb_data_t;

typedef bool (*DIGEST2_CALLBACK)(TCG_DIGEST2 const *digest, size_t size, void *data);
typedef bool (*EVENT2_CALLBACK)(TCG_EVENT_HEADER2 const *event_hdr, size_t size, void *data);

size_t sizeof_alg(UINT16 alg_id);
TCG_DIGEST2* get_next_digest(TCG_DIGEST2 const *digest, size_t *size);
bool foreach_digest2(TCG_DIGEST2 const *event_hdr, size_t count, size_t size, DIGEST2_CALLBACK callback, void *data);
bool digest2_accumulator_callback (TCG_DIGEST2 const *digest, size_t size, void *data);
TCG_EVENT_HEADER2* get_next_event(TCG_EVENT_HEADER2 const *event_hdr, size_t *size);
bool foreach_event2(TCG_EVENT_HEADER2 const *event_first,
                    size_t size,
                    EVENT2_CALLBACK callback,
                    void *data);

#endif
