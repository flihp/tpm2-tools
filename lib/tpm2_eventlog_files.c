/* SPDX-License-Identifier: BSD-3-Clause */
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <tss2/tss2_tpm2_types.h>

#include "files.h"
#include "log.h"
#include "tpm2_eventlog.h"
#include "tpm2_eventlog_ascii.h"
#include "tpm2_eventlog_files.h"
#include "tcg-efi-event.h"

bool files_write_PCRINDEX(UINT32 pcr_index,
                          files_event_cbdata_t *data) {

    int status = 0;

    status = snprintf(data->path,
                      PATH_MAX,
                      "%s/Event_%03zd/PCRIndex.bin",
                      data->out_dir,
                      data->count);
    if (status < 0) {
        LOG_ERR("failed to generate PCRIndex path: %s", strerror(errno));
        return false;
    }

    /* host byte order, not network byte order */
    return files_save_bytes_to_file(data->path,
                                    (UINT8*)&pcr_index,
                                    sizeof(pcr_index));
}

bool files_write_EVENTTYPE(UINT32 event_type,
                           files_event_cbdata_t *data) {

    int status = 0;

    status = snprintf(data->path,
                      PATH_MAX,
                      "%s/Event_%03zd/EventType.bin",
                      data->out_dir,
                      data->count);
    if (status < 0) {
        LOG_ERR("failed to generate EventType path: %s", strerror(errno));
        return false;
    }
    /* host byte order, not network byte order */
    return files_save_bytes_to_file(data->path,
                                    (UINT8*)&event_type,
                                    sizeof(event_type));
}

bool files_mkeventdir(files_event_cbdata_t *data) {

    int status = 0;

    status = snprintf(data->path,
                      PATH_MAX,
                      "%s/Event_%03zd",
                      data->out_dir,
                      data->count);
    if (status < 0) {
        LOG_ERR("failed to generate event path: %s", strerror(errno));
        return false;
    }

    status = mkdir(data->path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
    if (status != 0) {
        LOG_ERR("failed to make event directory: %s", strerror(errno));
        return false;
    }

    return true;
}

typedef struct {
    char *out_dir;
    size_t event_num;
    size_t count;
    size_t digests_size;
    char path[PATH_MAX];
} files_digest_cbdata_t;

bool files_write_event(TCG_EVENT2 *event,
                       files_event_cbdata_t *data) {

    int ret;

    if (event->EventSize != 0 && event->Event != NULL) {
        ret = snprintf(data->path,
                       PATH_MAX,
                       "%s/Event_%03zu/Event.bin",
                       data->out_dir,
                       data->count);
        if (ret < 0) {
            LOG_ERR("failed to generate event data path: %s", strerror(errno));
            return false;
        }

        return files_save_bytes_to_file(data->path,
                                        event->Event,
                                        event->EventSize);
    }

    return true;
}
 
bool files_digest2_callback(TCG_DIGEST2 const *digest, size_t size, void *data_in) {

    files_digest_cbdata_t *data = (files_digest_cbdata_t*)data_in;
    int ret;

    data->digests_size += sizeof(*digest) + size;
    ret = snprintf(data->path,
                   PATH_MAX,
                   "%s/Event_%03zu/Digest.%s",
                   data->out_dir,
                   data->event_num,
                   get_alg_name(digest->AlgorithmId));
    if (ret < 0) {
        LOG_ERR("failed to generate digest file path: %s", strerror(errno));
        return false;
    }

    return files_save_bytes_to_file(data->path,
                                    (UINT8*)&digest->Digest,
                                    sizeof_alg(digest->AlgorithmId));
}
bool files_event_callback(TCG_EVENT_HEADER2 const *eventhdr,
                          size_t size,
                          void *data_in) {

    files_event_cbdata_t data = { .out_dir = (char*)data_in, };
    bool ret;
    TCG_EVENT2 *event;

    if (!data_in) {
        LOG_ERR("'data' cannot be NULL");
        return false;
    }

    files_digest_cbdata_t digest_data = {
        .out_dir = data.out_dir,
    };

    ret = files_mkeventdir(&data);
    if (!ret) {
        return false;
    }

    ret = files_write_PCRINDEX(eventhdr->PCRIndex, &data);
    if (!ret) {
        return false;
    }

    ret = files_write_EVENTTYPE(eventhdr->EventType, &data);
    if (!ret) {
        return false;
    }

    ret = foreach_digest2(eventhdr->Digests,
                          eventhdr->DigestCount,
                          size - sizeof(*eventhdr),
                          files_digest2_callback,
                          &digest_data);
    if (!ret) {
        return false;
    }

    event = (TCG_EVENT2*)((uintptr_t)eventhdr->Digests +
                                     digest_data.digests_size);
    ret = files_write_event(event, &data);
    if (!ret) {
        return false;
    }

    return true;
}
