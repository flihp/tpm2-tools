/* SPDX-License-Identifier: BSD-3-Clause */
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tcg-efi-event.h"
#include "tpm2.h"
#include "tpm2_eventlog.h"
#include "tpm2_eventlog_ascii.h"
#include "tpm2_tool.h"

/* tpm2-tools setup / option processing */
#define ALLOC_SIZE 1024
#define EVENTLOG_FILENAME "/sys/kernel/security/tpm0/binary_bios_measurements"

static char *filename = EVENTLOG_FILENAME;

static bool on_positional(int argc, char **argv) {

    if (argc != 1) {
        LOG_ERR("Expected one file name as a positional parameter. Got: %d",
                argc);
        return false;
    }

    filename = argv[0];

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    *opts = tpm2_options_new(NULL, 0, NULL, NULL, on_positional,
                             TPM2_OPTIONS_NO_SAPI);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);
    UNUSED(ectx);

    bool ret = false;
    UINT8 *eventlog;
    size_t size = 0, count = 0;

    LOG_INFO("Loading event log from file: %s", filename);
    if (!files_get_file_size_path(filename, &size)){
        return tool_rc_general_error;
    }

    eventlog = calloc(1, size);
    if (eventlog == NULL){
        LOG_ERR("failed to allocate %zd bytes: %s", size, strerror(errno));
        return tool_rc_general_error;
    }

    /*
     * We must cast 'size' here as 'files_get_file_size_path' and
     * 'files_load_bytes_from_path' use different types for their size params.
     * We use the larger type for 'size' and cast to the smaller size.
     * Further the use of UINT16 for the size limits us to processing eventlogs
     * no larger than ~65k.
     */
    if (size > UINT16_MAX) {
        LOG_WARN("event log exceeds %" PRIu16 " and will be truncated",
                 UINT16_MAX);
    }
    if (!files_load_bytes_from_path(filename, eventlog, (UINT16*)&size)) {
        return tool_rc_general_error;
    }

    ret = foreach_event2((TCG_EVENT_HEADER2*)eventlog,
                         size,
                         ascii_event_callback,
                         &count);
    if (eventlog)
        free(eventlog);
    if (ret) {
        return tool_rc_success;
    } else {
        LOG_ERR("failed to parse tpm2 eventlog");
        return tool_rc_general_error;
    }
}
