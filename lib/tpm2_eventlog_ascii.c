#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <tss2/tss2_tpm2_types.h>

#include "log.h"
#include "tcg-efi-event.h"
#include "tpm2_eventlog.h"
#include "tpm2_eventlog_ascii.h"

char* get_alg_name(UINT16 alg_id) {

    switch (alg_id) {
    case TPM2_ALG_SHA1:
        return "TPM2_ALG_SHA1";
    case TPM2_ALG_SHA256:
        return "TPM2_ALG_SHA256";
    case TPM2_ALG_SHA384:
        return "TPM2_ALG_SHA384";
    case TPM2_ALG_SHA512:
        return "TPM2_ALG_SHA512";
    default:
        return "UNKNOWN_ALGORITHM";
    }
}
char* eventtype_to_string (UINT32 event_type) {

    switch (event_type) {
    case EV_PREBOOT_CERT:
        return "EV_PREBOOT_CERT";
    case EV_POST_CODE:
        return "EV_POST_CODE";
    case EV_UNUSED:
        return "EV_UNUSED";
    case EV_NO_ACTION:
        return "EV_NO_ACTION";
    case EV_SEPARATOR:
        return "EV_SEPARATOR";
    case EV_ACTION:
        return "EV_ACTION";
    case EV_EVENT_TAG:
        return "EV_EVENT_TAG";
    case EV_S_CRTM_CONTENTS:
        return "EV_S_CRTM_CONTENTS";
    case EV_S_CRTM_VERSION:
        return "EV_S_CRTM_VERSION";
    case EV_CPU_MICROCODE:
        return "EV_CPU_MICROCODE";
    case EV_PLATFORM_CONFIG_FLAGS:
        return "EV_PLATFORM_CONFIG_FLAGS";
    case EV_TABLE_OF_DEVICES:
        return "EV_TABLE_OF_DEVICES";
    case EV_COMPACT_HASH:
        return "EV_COMPACT_HASH";
    case EV_IPL:
        return "EV_IPL";
    case EV_IPL_PARTITION_DATA:
        return "EV_IPL_PARTITION_DATA";
    case EV_NONHOST_CODE:
        return "EV_NONHOST_CODE";
    case EV_NONHOST_CONFIG:
        return "EV_NONHOST_CONFIG";
    case EV_NONHOST_INFO:
        return "EV_NONHOST_INFO";
    case EV_OMIT_BOOT_DEVICE_EVENTS:
        return "EV_OMIT_BOOT_DEVICE_EVENTS";
    case EV_EFI_VARIABLE_DRIVER_CONFIG:
        return "EV_EFI_VARIABLE_DRIVER_CONFIG";
    case EV_EFI_VARIABLE_BOOT:
        return "EV_EFI_VARIABLE_BOOT";
    case EV_EFI_BOOT_SERVICES_APPLICATION:
        return "EV_EFI_BOOT_SERVICES_APPLICATION";
    case EV_EFI_BOOT_SERVICES_DRIVER:
        return "EV_EFI_BOOT_SERVICES_DRIVER";
    case EV_EFI_RUNTIME_SERVICES_DRIVER:
        return "EV_EFI_RUNTIME_SERVICES_DRIVER";
    case EV_EFI_GPT_EVENT:
        return "EV_EFI_GPT_EVENT";
    case EV_EFI_ACTION:
        return "EV_EFI_ACTION";
    case EV_EFI_PLATFORM_FIRMWARE_BLOB:
        return "EV_EFI_PLATFORM_FIRMWARE_BLOB";
    case EV_EFI_HANDOFF_TABLES:
        return "EV_EFI_HANDOFF_TABLES";
    case EV_EFI_VARIABLE_AUTHORITY:
        return "EV_EFI_VARIABLE_AUTHORITY";
    default:
        return "Unknown event type";
    }
}
bool dump_bytes(uint8_t const *buf,
                size_t buf_size,
                size_t width,
                size_t indent) {

    size_t byte_ctr, indent_ctr, line_length = indent + width * 3 + 1;
    char line [MAX_LINE_LENGTH] = { 0 };
    char *line_position = NULL;

    if (line_length > MAX_LINE_LENGTH) {
        LOG_ERR("MAX_LINE_LENGTH exceeded");
        return false;
    }

    for (byte_ctr = 0; byte_ctr < buf_size; ++byte_ctr) {
        /* index into line where next byte is written */
        line_position = line + indent + (byte_ctr % width) * 3;
        /* detect the beginning of a line, pad indent spaces */
        if (byte_ctr % width == 0) {
            for (indent_ctr = 0; indent_ctr < indent; ++indent_ctr) {
                line [indent_ctr] = ' ';
            }
        }
        sprintf(line_position, "%02x", buf[byte_ctr]);
        /*
         *  If we're not width bytes into the array AND we're not at the end
         *  of the byte array: print a space. This is padding between the
         *  current byte and the next.
         */
        if (byte_ctr % width != width - 1 && byte_ctr != buf_size - 1) {
            sprintf(line_position + 2, " ");
        } else {
            printf("%s\n", line);
        }
    }

    return true;
}


bool ascii_tpm2_event_header(TCG_EVENT_HEADER2 const *event_hdr, size_t size) {

    if (size < sizeof(*event_hdr)) {
        LOG_ERR("size is insufficient for event header");
        return false;
    }
    printf("  PCRIndex: %d\n", event_hdr->PCRIndex);
    printf("  EventType: %s (0x%" PRIx32 ")\n",
           eventtype_to_string(event_hdr->EventType),
           event_hdr->EventType);
    printf("  DigestCount: %d\n", event_hdr->DigestCount);
    return true;
}
bool ascii_tpm2_eventbuf(TCG_EVENT2 const *event, size_t size) {

    if (size < sizeof(*event)) {
        LOG_ERR("size is insufficient for event");
        return false;
    }
    printf("  Event: %" PRIu32 " bytes\n", event->EventSize);
    if (size < sizeof(*event) + event->EventSize) {
        LOG_ERR("size is insufficient for event body");
        return false;
    }
    dump_bytes(event->Event, event->EventSize, 20, 4);
    return true;
}

bool ascii_tpm2_digest_callback(TCG_DIGEST2 const *digest, size_t size, void *data) {

    digestcb_data_t *digestcb_data = (digestcb_data_t*)data;

    if (data) {
        printf("  Digest[%zu]:\n", digestcb_data->digest_count++);
        digestcb_data->digests_size += sizeof(*digest) + size;
    }

    printf("    AlgorithmId: %s (0x%" PRIx16 ")\n",
          get_alg_name(digest->AlgorithmId), digest->AlgorithmId);

    printf("    Digest: %zd bytes\n", size);
    dump_bytes(digest->Digest, size, 20, 6);

    return true;
}/*
 * Callback function for use with foreach_event2 to display an entry from
 * the event log in a human readable form.
 * The foreach_event2 function parses the event and ensures that the size of
 * the buffer holding it is sufficiently large before calling this function.
 */
bool ascii_event_callback(TCG_EVENT_HEADER2 const *event_hdr,
                                 size_t size,
                                 void *data) {

    TCG_EVENT2 *event;
    digestcb_data_t digestcb_data = { 0, };
    bool ret;

    if (data != NULL) {
        printf("Event[%zu]:\n", (*(size_t*)data)++);
    }
    if (!ascii_tpm2_event_header(event_hdr, size)) {
        return false;
    }

    ret = foreach_digest2(event_hdr->Digests,
                          event_hdr->DigestCount,
                          size - sizeof(*event_hdr),
                          ascii_tpm2_digest_callback,
                          &digestcb_data);
    if (!ret) {
        return ret;
    }

    event = (TCG_EVENT2*)((uintptr_t)event_hdr->Digests +
                          digestcb_data.digests_size);
    ascii_tpm2_eventbuf(event, sizeof(*event) + event->EventSize);
    return true;
}
