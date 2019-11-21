#define _GNU_SOURCE
#include <gio/gio.h>
#include <proc/readproc.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "polkitagent.h"
#include "actions.h"
#include "probes.h"
#include "util.h"
#include "introspect.h"

static gboolean enable_dump_methods;
static gboolean enable_dump_properties;
static gboolean enable_session_bus;
static gboolean enable_invalid_args;
static gboolean enable_null_agent;
static gconstpointer enable_dump_actions;
gint timeout = 500;

static gboolean handle_action_filter(const gchar *option_name, const gchar *value, gpointer data, GError **error);

static GOptionEntry entries[] = {
    { "dump-methods", 0, 0, G_OPTION_ARG_NONE, &enable_dump_methods, "Attempt to dump reported methods", NULL },
    { "dump-properties", 0, 0, G_OPTION_ARG_NONE, &enable_dump_properties, "Attempt to dump supported properties", NULL },
    { "session", 0, 0, G_OPTION_ARG_NONE, &enable_session_bus, "Use the session bus instead of the system bus", NULL },
    { "include-invalid", 0, 0, G_OPTION_ARG_NONE, &enable_invalid_args, "Include properties that cannot be probed", NULL },
    { "enable-probes", 0, 0, G_OPTION_ARG_NONE, &enable_access_probes, "Try to query which props/methods are accessible (dangerous)", NULL },
    { "null-agent", 0, 0, G_OPTION_ARG_NONE, &enable_null_agent, "Create a polkit agent to dismiss prompts", NULL },
    { "dump-actions", 0, G_OPTION_FLAG_OPTIONAL_ARG, G_OPTION_ARG_CALLBACK, &handle_action_filter, "Attempt to dump PolicyKit actions", "[all,none,whatever]" },
    { "print-actions", 0, 0, G_OPTION_ARG_NONE, &enable_action_print, "Print actions as they are received by the agent", NULL },
    { "timeout", 0, 0, G_OPTION_ARG_INT, &timeout, "timeout in milliseconds for sending dbus message, or -1 for infinite", "N" },
    { NULL },
};


typedef void (* introspect_cb_t) (xmlDocPtr doc, GDBusConnection *bus, const gchar *dest, const gchar *path, gpointer user);

static gboolean handle_action_filter(G_GNUC_UNUSED const gchar *option_name,
                                     const gchar *value,
                                     G_GNUC_UNUSED gpointer data,
                                     G_GNUC_UNUSED GError **error)
{
    enable_dump_actions = g_strdup(value ? value : "");
    return true;
}

// Return a procps structure for the owner of the specified DBus name. This is
// useful to query more information than DBus exposes (e.g. fsuid).
//
// Returns NULL on error, or a pointer that should be freed with freeproc().
proc_t * get_name_process(GDBusConnection *bus, gchar *name)
{
    PROCTAB      *proctab;
    GDBusMessage *request;
    GDBusMessage *reply;
    GVariant     *body;
    proc_t       *result;
    guint32       pidlist[] = { 0, 0 };

    request = g_dbus_message_new_method_call("org.freedesktop.DBus",
                                             "/org/freedesktop/DBus",
                                             "org.freedesktop.DBus",
                                             "GetConnectionUnixProcessID");

    g_dbus_message_set_body(request, g_variant_new ("(s)", name));

    reply = g_dbus_send(bus, request, G_DBUS_SEND_MESSAGE_FLAGS_NONE, timeout, NULL, NULL, NULL);

    body = g_dbus_message_get_body(reply);

    if (g_strcmp0(g_variant_type_peek_string(g_variant_get_type(body)), "(u)") != 0) {
        return NULL;
    }

    g_variant_get(body, "(u)", &pidlist[0]);

    proctab = openproc(PROC_FILLSTAT | PROC_FILLUSR | PROC_FILLGRP
                     | PROC_FILLSTATUS | PROC_FILLSUPGRP | PROC_PID
                     | PROC_FILLCOM | PROC_FILLENV, pidlist);
    result  = readproc(proctab, NULL);
    closeproc(proctab);

    g_object_unref(request);
    g_object_unref(reply);
    return result;
}

// For the specified D-Bus destination, get any available Introspection XML.
//
// Returns NULL, or a pointer you should free with g_free().
gchar * get_name_introspect(GDBusConnection *bus, const gchar *name, const gchar *path)
{
    GVariant     *data;
    gchar        *xml;

    if (!g_variant_is_object_path(path)) {
        return NULL;
    }

    data = g_dbus_simple_send(bus, g_dbus_method(name,
                                                 path,
                                                 "org.freedesktop.DBus.Introspectable",
                                                 "Introspect"),
                                   "(s)");

    if (data) {
        g_variant_get(data, "(s)", &xml);
        g_variant_unref(data);
        return xml;
    }

    return NULL;
}

// Return a list of D-Bus names that the server reports as an array of strings
// in a GVariant.
GVariant * get_service_list(GDBusConnection *bus)
{
    GHashTable *filter;
    GVariantIter *iter;
    GVariantBuilder builder;
    GVariant *names;
    GVariant *avail;
    gpointer value;

    filter = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);

    g_variant_builder_init(&builder, G_VARIANT_TYPE_ARRAY);

    names   = g_dbus_simple_send(bus,
                                 g_dbus_method("org.freedesktop.DBus",
                                               "/",
                                               "org.freedesktop.DBus",
                                               "ListNames"),
                                 "(as)");
    avail   = g_dbus_simple_send(bus,
                                 g_dbus_method("org.freedesktop.DBus",
                                               "/",
                                               "org.freedesktop.DBus",
                                               "ListActivatableNames"),
                                 "(as)");

    g_variant_get(avail, "(as)", &iter);

    while (g_variant_iter_loop(iter, "s", &value)) {
        if (!g_hash_table_contains(filter, value)) {
            g_hash_table_add(filter, value);
            g_variant_builder_add(&builder, "s", value);
        }
    }


    g_variant_get(names, "(as)", &iter);

    while (g_variant_iter_loop(iter, "s", &value)) {
        if (!g_hash_table_contains(filter, value)) {
            g_hash_table_add(filter, value);
            g_variant_builder_add(&builder, "s", value);
        }
    }

    g_hash_table_destroy(filter);
    return g_variant_builder_end(&builder);
}

void xml_node_callback(xmlDocPtr doc, GDBusConnection *bus, const gchar *dest, const gchar *path, gpointer user)
{
    if (enable_dump_methods) {
        list_dbus_methods(doc, bus, dest, path, user);
    }

    if (enable_dump_properties) {
        list_dbus_properties(doc, bus, dest, path, user);
    }
}

int main(int argc, char **argv)
{
    GHashTable *methods;
    GOptionContext *context;
    GDBusConnection *bus;
    GVariant *list;
    GVariantIter *iter;
    gchar *str;
    gchar *path;

    context = g_option_context_new("[NAME]");

    g_option_context_add_main_entries(context, entries, NULL);
    if (g_option_context_parse(context, &argc, &argv, NULL) == false) {
        g_option_context_free(context);
        g_message("failed to parse options");
        return 1;
    }

    bus     = g_bus_get_sync(enable_session_bus ? G_BUS_TYPE_SESSION : G_BUS_TYPE_SYSTEM, NULL, NULL);
    list    = get_service_list(bus);

    if (enable_dump_actions) {
        get_action_list(bus, enable_dump_actions);
        return 0;
    }

    if (enable_null_agent) {
        register_polkit_agent(bus);
    }

    g_option_context_free(context);
    g_variant_get(list, "as", &iter);

    g_print("%s\t%16s\t%40s\t%32s\n", "PID", "USER", "NAME", "CMDLINE");

    while (g_variant_iter_loop(iter, "s", &str)) {
        proc_t  *p = get_name_process(bus, str);

        // If a name is specified on the commandline, limit output to that service.
        if (argc > 1 && g_strcmp0(str, argv[1]) != 0) {
            continue;
        }

        if (p) {
            g_print("%d\t%16s\t%40s%c\t%32s", p->tid, p->euser, str, check_name_protected(bus, str) ? ' ' : '!', p->cmdline[0]);
            for (gint i = 1; p->cmdline[i]; i++)
                g_print(" %s", p->cmdline[i]);
            g_print("\n");
        } else {
            g_print("%d\t%16s\t%40s%c\t%32s\n", -1, "unknown", str, check_name_protected(bus, str) ? ' ' : '!', "");
        }

        path    = g_strdelimit(g_strdup_printf("/%s", str), ".", '/');
        methods = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

        // Call each method with invalid args and see if it gives AccessDenied. If it does, why list it, method_call is banned?
        descend_introspection_nodes(bus, str, "/", xml_node_callback, methods);

        // Skip unique names.
        if (*str != ':') {
            descend_introspection_nodes(bus, str, path, xml_node_callback, methods);
        }

        g_hash_table_destroy(methods);
        freeproc(p);
    }

    xmlCleanupParser();
    return 0;
}
