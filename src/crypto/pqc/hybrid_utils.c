#include "hybrid_utils.h"

/*  Function: hybrid_state_string
    Description:
    Returns a human-readable string for the given hybrid handshake state.

    Parameters:
    - state: The hybrid_state_t value.

    Returns:
    - A constant string such as "INIT", "ESTABLISHED", "ERROR", etc.
    - Returns "UNKNOWN" if the state is not recognized.
*/
const char* hybrid_state_string(hybrid_state_t state) {
    switch (state) {
        case HYBRID_STATE_INIT:            return "INIT";
        case HYBRID_STATE_KEYS_GENERATED:  return "KEYS_GENERATED";
        case HYBRID_STATE_BUNDLE_SENT:     return "BUNDLE_SENT";
        case HYBRID_STATE_BUNDLE_RECEIVED: return "BUNDLE_RECEIVED";
        case HYBRID_STATE_ESTABLISHED:     return "ESTABLISHED";
        case HYBRID_STATE_ERROR:           return "ERROR";
        default:                           return "UNKNOWN";
    }
}