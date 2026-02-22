#include "erasure_print.h"
#include "erasure_data.h"
#include "../common/logging.h"

#include <stdio.h>

/*  Function: erasure_print_info
    Description:
    Prints codec configuration in a formatted box.

    Parameters:
    - codec: Pointer to the erasure_codec_t structure.

    Steps:
    1. Checks initialization; logs a message if not initialized.
    2. Prints k, n, parity, max failures, fault tolerance %, and storage overhead %.
*/
void erasure_print_info(const erasure_codec_t* codec) {
    if (!codec || !codec->initialized) {
        LOG_INFO("erasure: <not initialized>");
        return;
    }

    LOG_INFO("╔══════════════════════════════════════╗");
    LOG_INFO("║       REED-SOLOMON CODEC             ║");
    LOG_INFO("╠══════════════════════════════════════╣");
    LOG_INFO("║  Data shards (k):    %-15d ║", codec->k);
    LOG_INFO("║  Total shards (n):   %-15d ║", codec->n);
    LOG_INFO("║  Parity shards:      %-15d ║", codec->parity);
    LOG_INFO("║  Max failures:       %-15d ║", codec->parity);
    LOG_INFO("║  Fault tolerance:    %-14.1f%% ║",
             (double)codec->parity / codec->n * 100.0);
    LOG_INFO("║  Storage overhead:   %-14.1f%% ║",
             (double)codec->parity / codec->k * 100.0);
    LOG_INFO("╚══════════════════════════════════════╝");
}

/*  Function: erasure_print_status
    Description:
    Prints shard availability status showing data and parity shards.

    Parameters:
    - enc: Pointer to the erasure_encoded_t structure.

    Steps:
    1. Counts available shards and checks reconstructability.
    2. Builds a status line with D (data) and P (parity) markers.
    3. Logs the summary with available/total/needed counts.
*/
void erasure_print_status(const erasure_encoded_t* enc) {
    if (!enc) return;

    int available = erasure_count_available(enc);
    bool can_rebuild = erasure_can_reconstruct(enc);

    LOG_INFO("Shard status: [");
    char status_line[512] = {0};
    int pos = 0;
    for (int i = 0; i < enc->n && pos < 500; i++) {
        if (i < enc->k) {
            pos += snprintf(status_line + pos, 512 - pos,
                            " D%d:%s", i, enc->present[i] ? "✓" : "✗");
        } else {
            pos += snprintf(status_line + pos, 512 - pos,
                            " P%d:%s", i - enc->k, enc->present[i] ? "✓" : "✗");
        }
    }
    LOG_INFO("  %s", status_line);
    LOG_INFO("  Available: %d/%d | Need: %d | Reconstruct: %s",
             available, enc->n, enc->k, can_rebuild ? "YES" : "NO");
}