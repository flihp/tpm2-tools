#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <tss2/tss2_tpm2_types.h>

#include "log.h"
#include "efi_event.h"
#include "tpm2_alg_util.h"
#include "tpm2_eventlog.h"
#include "tpm2_eventlog_yaml.h"
#include "tpm2_tool.h"

char const *eventtype_to_string (UINT32 event_type) {

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
void bytes_to_str(uint8_t const *buf, size_t size, char *dest, size_t dest_size) {

    size_t i, j;

    for(i = 0, j = 0; i < size && j < dest_size - 1; ++i, j+=2) {
        sprintf(&dest[j], "%02x", buf[i]);
    }
    dest[j] = '\0';
}
bool yaml_event2hdr(TCG_EVENT_HEADER2 const *eventhdr, size_t size) {

    (void)size;

    tpm2_tool_output("    PCRIndex: %d\n", eventhdr->PCRIndex);
    tpm2_tool_output("    EventType: %s\n",
           eventtype_to_string(eventhdr->EventType));
    tpm2_tool_output("    DigestCount: %d\n", eventhdr->DigestCount);
    return true;
}
/* converting byte buffer to hex string requires 2x, plus 1 for '\0' */
#define BYTES_TO_HEX_STRING_SIZE(byte_count) (byte_count * 2 + 1)
#define DIGEST_HEX_STRING_MAX BYTES_TO_HEX_STRING_SIZE(TPM2_MAX_DIGEST_BUFFER)
bool yaml_digest2(TCG_DIGEST2 const *digest, size_t size) {

    char hexstr[DIGEST_HEX_STRING_MAX] = { 0, };

    tpm2_tool_output("        AlgorithmId: %s\n",
           tpm2_alg_util_algtostr(digest->AlgorithmId,
                                  tpm2_alg_util_flags_hash));
    bytes_to_str(digest->Digest, size, hexstr, sizeof(hexstr));
    tpm2_tool_output("        Digest: %s\n", hexstr);

    return true;
}
#define EVENT_BUF_MAX BYTES_TO_HEX_STRING_SIZE(1024)
bool yaml_event2data(TCG_EVENT2 const *event, UINT32 type) {

    (void)type;

    tpm2_tool_output("    EventSize: %" PRIu32 "\n", event->EventSize);

    if (event->EventSize > 0) {
        char hexstr[EVENT_BUF_MAX] = { 0, };

        bytes_to_str(event->Event, event->EventSize, hexstr, sizeof(hexstr));
        tpm2_tool_output("    Event: %s\n", hexstr);
    }

    return true;
}
bool yaml_event2data_callback(TCG_EVENT2 const *event, UINT32 type,
                              bool validated, void *data) {

    (void)validated;
    (void)data;

    return yaml_event2data(event, type);
}
bool yaml_digest2_callback(TCG_DIGEST2 const *digest, size_t size,
                            void *data_in) {

    yaml_cbdata_t *data = (yaml_cbdata_t*)data_in;

    if (data == NULL) {
        LOG_ERR("callback requires user data");
        return false;
    }
    tpm2_tool_output("      - Digest[%zu]:\n", data->digest_count++);

    return yaml_digest2(digest, size);
}

bool yaml_event2hdr_callback(TCG_EVENT_HEADER2 const *eventhdr, size_t size,
                             void *data_in) {

    bool ret;
    yaml_cbdata_t *data = (yaml_cbdata_t*)data_in;

    if (data == NULL) {
        LOG_ERR("callback requires user data");
        return false;
    }
    tpm2_tool_output("- Event[%zu]:\n", data->event_count++);

    ret = yaml_event2hdr(eventhdr, size);
    if (!ret) {
        return ret;
    }

    tpm2_tool_output("    Digests:\n");

    return true;
}

bool yaml_eventlog(UINT8 const *eventlog, size_t size) {

    yaml_cbdata_t data = { 0, };

    tpm2_tool_output("---\n");
    return foreach_event2((TCG_EVENT_HEADER2*)eventlog, size,
                          yaml_event2hdr_callback,
                          yaml_digest2_callback,
                          yaml_event2data_callback, &data);
}
