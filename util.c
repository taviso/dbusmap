#define _GNU_SOURCE
#include <gio/gio.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>


#include "util.h"

static gchar* dump_property(xmlNodePtr node, const char* prop)
{
    xmlChar* value = xmlGetProp(node, (const xmlChar*)prop);
    char* ret = g_strdup((gchar*)value);
    if (value != NULL)
        xmlFree(value);
    return ret;
}


GVariant* build_invalid_body(const gchar* sig)
{
    if (sig == NULL || g_str_equal(sig, "s")) {
        return g_variant_new("(d)", 0);
    } else {
        return g_variant_new("(s)", "INVALID STRING");
    }
}

gchar* get_method_signature(xmlNodePtr node) {
    if (node == NULL) {
        return NULL;
    }
    xmlNodePtr cur = node->children;
    while (cur != NULL) {
        const gchar* name = (const gchar*)cur->name;
        if (name == NULL) {
            cur = cur->next;
            continue;
        }
        if (g_str_equal("arg", name)) {
            xmlChar* s = xmlGetProp(cur, (const xmlChar*)"direction");
            if (!g_str_equal(s, "out")) {
                xmlFree(s);
                return dump_property(cur, "type");
             }
            xmlFree(s);
        }
        cur = cur->next;
    }
    return NULL;
}

gchar* get_property_signature(xmlNodePtr node) {
    if (node == NULL) {
        return NULL;
    }
    return dump_property(node, "type");
}



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

