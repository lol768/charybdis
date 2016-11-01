#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "s_serv.h"

// module description.
static const char sts_desc[] = "This module provides hardcoded strict transport security support. No support for CAP NEW!";

// filled in with cap index
unsigned int CAP_STS_SERVER;

static bool sts_visible(struct Client *client_p) {
    return 1; // show the CAP all the time, we don't give a damn about the client
}

static const char* sts_data(struct Client *client_p) {
    if (!IsSSL(client_p)) {
        inotice("Called to get STS data for insecure client, giving them the (hardcoded) port\n");
        return "port=6697"; // compliant clients will now reconnect
    } else {
        inotice("Called to get STS data for secure client, giving them the (hardcoded) duration\n");
        return "duration=300"; // compliant clients will now store the policy for 5 minutes (or disconnect + 5m if still valid)
    }
}

static struct ClientCapability capdata_sts = {
        .visible = sts_visible, // Function pointer, not a bool!
        .data = sts_data, // Function pointer, not a string!
        .flags = CLICAP_FLAGS_STICKY, // STS cannot be disabled
};

mapi_cap_list_av2 sts_cap_list[] = {
      // CAP Type     name    data          index, filled in for us
    { MAPI_CAP_CLIENT, "sts", &capdata_sts, &CAP_STS_SERVER },
    { 0, NULL, NULL, NULL }
};

// When the module is loaded
static int modinit(void) {
    inotice("Hello from the STS module\n");
    return 0; // success
}

// ... and when it's unloaded
static void moddeinit(void) {
    return 0; // success
}

DECLARE_MODULE_AV2(
    // Module name -- seemingly unused and not quoted. God knows why - yay magic macros
    sts,
    // on load functions
    modinit,
    // unload function
    moddeinit,
    // don't care (commands)
    NULL,
    // don't care (hooks)
    NULL,
    // don't care (hook handlers)
    NULL,
    // FINALLY, the capabilities list
    sts_cap_list,
    /* Then the version number of this module (NULL for bundled) */
    NULL,
    /* And finally, the description of this module */
    sts_desc);

