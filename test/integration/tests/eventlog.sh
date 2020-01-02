# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

trap - EXIT

tpm2_eventlog ${srcdir}/test/integration/fixtures/event.bin

exit 0
