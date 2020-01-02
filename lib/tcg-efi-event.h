/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef TCG_EFI_EVENT_H
#define TCG_EFI_EVENT_H 1

#include <tss2/tss2_tpm2_types.h>

/*
 * Log event types. These are spread out over 2 specs:
 * "TCG EFI Protocol Specification For TPM Family 1.1 or 1.2" and
 * "TCG PC Client Specific Implementation Specification for Conventional BIOS"
 */
#define EV_PREBOOT_CERT            0x0
#define EV_POST_CODE               0x1
#define EV_UNUSED                  0x2
#define EV_NO_ACTION               0x3
#define EV_SEPARATOR               0x4
#define EV_ACTION                  0x5
#define EV_EVENT_TAG               0x6
#define EV_S_CRTM_CONTENTS         0x7
#define EV_S_CRTM_VERSION          0x8
#define EV_CPU_MICROCODE           0x9
#define EV_PLATFORM_CONFIG_FLAGS   0xa
#define EV_TABLE_OF_DEVICES        0xb
#define EV_COMPACT_HASH            0xc
#define EV_IPL                     0xd
#define EV_IPL_PARTITION_DATA      0xe
#define EV_NONHOST_CODE            0xf
#define EV_NONHOST_CONFIG          0x10
#define EV_NONHOST_INFO            0x11
#define EV_OMIT_BOOT_DEVICE_EVENTS 0x12

/* TCG EFI Platform Specification For TPM Family 1.1 or 1.2 */
#define EV_EFI_EVENT_BASE                0x80000000
#define EV_EFI_VARIABLE_DRIVER_CONFIG    EV_EFI_EVENT_BASE + 0x1
#define EV_EFI_VARIABLE_BOOT             EV_EFI_EVENT_BASE + 0x2
#define EV_EFI_BOOT_SERVICES_APPLICATION EV_EFI_EVENT_BASE + 0x3
#define EV_EFI_BOOT_SERVICES_DRIVER      EV_EFI_EVENT_BASE + 0x4
#define EV_EFI_RUNTIME_SERVICES_DRIVER   EV_EFI_EVENT_BASE + 0x5
#define EV_EFI_GPT_EVENT                 EV_EFI_EVENT_BASE + 0x6
#define EV_EFI_ACTION                    EV_EFI_EVENT_BASE + 0x7
#define EV_EFI_PLATFORM_FIRMWARE_BLOB    EV_EFI_EVENT_BASE + 0x8
#define EV_EFI_HANDOFF_TABLES            EV_EFI_EVENT_BASE + 0x9
#define EV_EFI_VARIABLE_AUTHORITY        EV_EFI_EVENT_BASE + 0xe0

#ifndef PACKED
#define PACKED __attribute__((__packed__))
#endif

typedef struct {
  UINT16 AlgorithmId;
  UINT8 Digest[];
} PACKED TCG_DIGEST2;

typedef struct {
  UINT32 EventSize;
  UINT8 Event [];
} PACKED TCG_EVENT2;

typedef struct {
  UINT32 PCRIndex;
  UINT32 EventType;
  UINT32 DigestCount;
  TCG_DIGEST2 Digests [];
 /* TCG_EVENT2 comes next */
} PACKED TCG_EVENT_HEADER2;

#endif
