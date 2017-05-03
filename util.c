#define _GNU_SOURCE
#include <gio/gio.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

// Simple wrapper for a common D-Bus pattern.
GVariant * g_dbus_simple_send(GDBusConnection *bus, GDBusMessage *msg, const gchar *type)
{
    GDBusMessage *reply;
    GVariant *body;
    gchar *fmt;

    if (!(reply = g_dbus_send(bus, msg, 0, timeout, 0, 0, 0))) {
        g_object_unref(msg);
        return NULL;
    }

    body  = g_dbus_message_get_body(reply);
    fmt   = g_dbus_message_print(reply, 0);

    g_variant_ref(body);

    if (g_strcmp0(g_variant_type_peek_string(g_variant_get_type(body)), type) != 0) {
        g_message("body type %s does not match expected type %s, message: %s",
                  g_variant_type_peek_string(g_variant_get_type(body)),
                  type,
                  fmt);
        g_variant_unref(body);

        // return error
        body = NULL;
    }

    g_free(fmt);
    g_object_unref(reply);
    g_object_unref(msg);
    return body;
}

