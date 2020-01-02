#include <inttypes.h>
#include <stdlib.h>
#include <tss2/tss2_tpm2_types.h>

#include "log.h"
#include "tcg-efi-event.h"
#include "tpm2_eventlog.h"

/* Functions to parse / process the structures that make up the eventlog. */
size_t sizeof_alg(UINT16 alg_id) {

    switch (alg_id) {
    case TPM2_ALG_SHA1:
        return TPM2_SHA1_DIGEST_SIZE;
    case TPM2_ALG_SHA256:
        return TPM2_SHA256_DIGEST_SIZE;
    case TPM2_ALG_SHA384:
        return TPM2_SHA384_DIGEST_SIZE;
    case TPM2_ALG_SHA512:
        return TPM2_SHA512_DIGEST_SIZE;
    default:
        return 0;
    }
}
/*
 * Invoke callback function for each TCG_DIGEST2 structure in the provided
 * TCG_EVENT_HEADER2. The callback function is only invoked if this function
 * is first able to determine that the provided buffer is large enough to
 * hold the digest. The size of the digest is passed to the callback in the
 * 'size' parameter.
 */
bool foreach_digest2(TCG_DIGEST2 const *digest,
                     size_t count,
                     size_t size,
                     DIGEST2_CALLBACK callback,
                     void *data) {

    if (digest == NULL) {
        LOG_ERR("digest cannot be NULL");
        return false;
    }

    if (size < sizeof(TCG_DIGEST2)) {
        LOG_ERR("buffer insufficient for digest header");
        return false;
    }

    bool ret = true;

    for (size_t i = 0; i < count; ++i) {
        if (size < sizeof(*digest)) {
            LOG_ERR("insufficient size for digest structure");
            return false;
        }
        size_t alg_size = sizeof_alg(digest->AlgorithmId);
        if (size < sizeof(*digest) + alg_size) {
            LOG_ERR("insufficient size for digest buffer");
            return false;
        }
        if (callback != NULL) {
            ret = callback(digest, alg_size, data);
            if (!ret) {
                LOG_INFO("callback failed for digest at %p with size %zu", digest, alg_size);
                break;
            }
        }
        size -= sizeof(*digest) + alg_size;
        digest = (TCG_DIGEST2*)((uintptr_t)digest->Digest + alg_size);
    }

    return ret;
}
bool digest2_accumulator_callback (TCG_DIGEST2 const *digest, size_t size, void *data){

    if (digest == NULL || data == NULL) {
        LOG_ERR("neither parameter may be NULL");
        return false;
    }
    size_t *accumulator = (size_t*)data;

    *accumulator += sizeof(*digest) + size;

    return true;
}
/*
 * This function takes a reference to the start of the binary event log
 * and invokes a callback for each event structure from the log. The 'size'
 * parameter is the total size of the buffer holding the log. As the log is
 * parsed the size is consulted to ensure appropriate memory accesses and
 * to guarantee the callback is passed a valid / complete event structure.
 * Callers implementing callbacks do not need to implement these checks
 * themselves.
 */
bool foreach_event2(TCG_EVENT_HEADER2 const *eventhdr_start,
                    size_t size,
                    EVENT2_CALLBACK callback,
                    void *data) {

    if (eventhdr_start == NULL || callback == NULL) {
        LOG_ERR("invalid parameter");
        return false;
    }

    TCG_EVENT_HEADER2 const *eventhdr;
    size_t event_size;

    for (eventhdr = eventhdr_start, event_size = 0;
         size > 0;
         eventhdr = (TCG_EVENT_HEADER2*)((uintptr_t)eventhdr + event_size),
         size -= event_size) {

        size_t digests_size = 0;
        if (size < sizeof(*eventhdr)) {
            LOG_ERR("corrupted log, insufficient size for event header: %zu", size);
            return false;
        }
        event_size = sizeof(*eventhdr);

        if (!foreach_digest2(eventhdr->Digests,
                             eventhdr->DigestCount,
                             size - sizeof(*eventhdr),
                             digest2_accumulator_callback,
                             &digests_size)) {
            return false;
        }
        event_size += digests_size;

        TCG_EVENT2 *event = (TCG_EVENT2*)((uintptr_t)eventhdr + event_size);
        if (size < event_size + sizeof(*event)) {
            LOG_ERR("corrupted log: size insufficient for EventSize");
            return false;
        }
        event_size += sizeof(*event);

        if (size < event_size + event->EventSize) {
            LOG_ERR("size insufficient for event data");
            return false;
        }
        event_size += event->EventSize;

        if (!callback(eventhdr, event_size, data)) {
            return false;
        }
    }

    return true;
}
