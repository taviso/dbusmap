#define _GNU_SOURCE
#include <gio/gio.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "polkitagent.h"

static GOptionEntry entries[] = {
    { "auth-password", 0, 0, G_OPTION_ARG_STRING, &polkit_auth_password, "If specified, send polkit the specified password", "password" },
    { NULL },
};

int main(int argc, char **argv)
{
    GOptionContext *context;
    GDBusConnection *bus;
    GPid childpid;
    int status;

    context = g_option_context_new("-- COMMAND [OPTIONS...]");

    g_option_context_add_main_entries(context, entries, NULL);

    if (g_option_context_parse(context, &argc, &argv, NULL) == false) {
        g_option_context_free(context);
        g_message("failed to parse options");
        return 1;
    }

    childpid = fork();

    if (childpid == 0) {
        sleep(10);

        execvp(argv[2], &argv[2]);

        // Execution failed.
        g_error("execvp(%s) failed, %m", argv[1]);

        _exit(1);
    }

    sleep(5);
    bus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);
    register_polkit_agent(bus, childpid);

    if (waitpid(childpid, &status, 0) != childpid) {
        g_error("failed to wait for child to complete");
    }

    g_object_unref(bus);
    return 0;
}
