/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef TPM2_EVENTLOG_FILES_H
#define TPM2_EVENTLOG_FILES_H

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>

#include "tcg-efi-event.h"

typedef struct {
    char *out_dir;
    size_t count;
    char path[PATH_MAX];
} files_event_cbdata_t;

/* A callback function for use with the foreach_event2 */
bool files_event_callback(TCG_EVENT_HEADER2 const *eventhdr, size_t size, void *data);

#endif /* TPM2_EVENTLOG_FILES_H */
