/* SPDX-License-Identifier: BSD-3-Clause */
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tcg-efi-event.h"
#include "tpm2_eventlog.h"
#include "tpm2_eventlog_ascii.h"
#include "tpm2_eventlog_files.h"
#include "tpm2_tool.h"

#define EVENTLOG_FILENAME "/sys/kernel/security/tpm0/binary_bios_measurements"
#define OUT_DIR "."

typedef enum {
    FORMAT_UNKNOWN,
    FORMAT_ASCII,
    FORMAT_FILES,
    FORMAT_N,
} format_t;
static char *filename = EVENTLOG_FILENAME;
static char *out_dir = OUT_DIR;
static format_t format = FORMAT_ASCII;

static format_t str_to_format(char const *str) {

    if (strcmp(str, "ascii") == 0) {
        return FORMAT_ASCII;
    } else if (strcmp(str, "files") == 0) {
        return FORMAT_FILES;
    } else {
        return FORMAT_UNKNOWN;
    }
}

static bool on_positional(int argc, char **argv) {

    if (argc != 1) {
        LOG_ERR("Expected one file name as a positional parameter. Got: %d",
                argc);
        return false;
    }

    filename = argv[0];

    return true;
}

static bool on_option(char key, char *value) {

    if (key == 'F') {
        format = str_to_format(value);
    }

    return true;
}
bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        {
            .name = "format",
            .has_arg = required_argument,
            .val = 'F'
        },
    };

    *opts = tpm2_options_new("F:", ARRAY_LEN(topts), topts, on_option,
                             on_positional, TPM2_OPTIONS_NO_SAPI);

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

    if (size > UINT16_MAX) {
        LOG_WARN("event log exceeds %" PRIu16 " and will be truncated",
                 UINT16_MAX);
    }
    UINT16 size_tmp = size;
    if (!files_load_bytes_from_path(filename, eventlog, &size_tmp)) {
        return tool_rc_general_error;
    }

    LOG_INFO("parsing %" PRIu16 " byte eventlog", size_tmp);
    switch (format) {
    case FORMAT_ASCII:
        ret = foreach_event2((TCG_EVENT_HEADER2*)eventlog,
                             size_tmp,
                             ascii_event_callback,
                             &count);
        break;
    case FORMAT_FILES:
        ret = foreach_event2((TCG_EVENT_HEADER2*)eventlog,
                             size_tmp,
                             files_event_callback,
                             out_dir);
        break;
    default:
        ret = false;
        LOG_ERR("unknown output format");
    }
    if (eventlog)
        free(eventlog);
    if (ret) {
        return tool_rc_success;
    } else {
        LOG_ERR("failed to parse tpm2 eventlog");
        return tool_rc_general_error;
    }
}
