#define _GNU_SOURCE
#include <gio/gio.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "polkitagent.h"

// This code registers a polkit authentication agent, and simply cancels
// all authentication attempts. The purpose of this is to prevent noisy
// interactive authentication prompts when scanning for D-Bus endpoints.
//
// When debugging D-Bus messages, setting G_DBUS_DEBUG=all G_MESSAGES_DEBUG=all
// generates quite-nice human-readable traffic dumps.

static void BeginAuthentication(GDBusConnection *bus,
                                const gchar *sender,
                                const gchar *object_path,
                                const gchar *interface_name,
                                const gchar *method_name,
                                GVariant *parameters,
                                GDBusMethodInvocation *invocation,
                                gpointer userptr);

#define g_dbus_send g_dbus_connection_send_message_with_reply_sync

// This is the really verbose way GLib declares parameters. There is no way to
// compress this declaration, because the params must validate through
// g_variant_type_string_is_valid(), which require a single type (so you can't
// make param0 sssa{ss} etc.).
//
// There's also no way to handle all calls, GLib requires you to declare the
// ones you want in advance (that is not a requirement of the protocol, just GLib).
// At the time of writing, there are also no hooks or anything else that let
// you do this dynamically as you receive messages. Sigh.
static GDBusArgInfo BeginAuthenticationParams[] = {
    { -1, "actionid",   "s",          NULL },
    { -1, "message",    "s",          NULL },
    { -1, "icon",       "s",          NULL },
    { -1, "details",    "a{ss}",      NULL },
    { -1, "cookie",     "s",          NULL },
    { -1, "identities", "a(sa{sv})",  NULL },
}, *BeginAuthenticationParamsPtr[] = {
    &BeginAuthenticationParams[0],
    &BeginAuthenticationParams[1],
    &BeginAuthenticationParams[2],
    &BeginAuthenticationParams[3],
    &BeginAuthenticationParams[4],
    &BeginAuthenticationParams[5],
    NULL,
};

static GDBusMethodInfo PolkitAgentMethods[] = {
    { -1, "BeginAuthentication", BeginAuthenticationParamsPtr, NULL, NULL },
}, *PolkitAgentMethodsPtr[] = {
    &PolkitAgentMethods[0],
    NULL,
};

static GDBusInterfaceInfo PolkitAgentInterface = {
    .ref_count      = -1,
    .name           = "org.freedesktop.PolicyKit1.AuthenticationAgent",
    .methods        = PolkitAgentMethodsPtr,
    .signals        = NULL,
    .properties     = NULL,
    .annotations    = NULL,
};

static GDBusInterfaceVTable PolkitAgentVTable = {
    .method_call    = BeginAuthentication,
    .get_property   = NULL,
    .set_property   = NULL,
};

// Options
gboolean enable_action_print;

void BeginAuthentication(GDBusConnection *bus,
                         G_GNUC_UNUSED const gchar *sender,
                         G_GNUC_UNUSED const gchar *object_path,
                         G_GNUC_UNUSED const gchar *interface_name,
                         G_GNUC_UNUSED const gchar *method_name,
                         GVariant *parameters,
                         G_GNUC_UNUSED GDBusMethodInvocation *invocation,
                         G_GNUC_UNUSED gpointer userptr)
{
    gchar *actionid;
    gchar *message;
    gchar *icon;
    gchar *cookie;
    GVariant *details;
    GVariant *identities;
    GDBusMessage *response;

    // GLib will not call us unless the signature matches perfectly, so this
    // should always be true.
    g_assert_cmpstr(g_variant_get_type_string(parameters), ==, "(sssa{ss}sa(sa{sv}))");

    // Extract the parameters from the inpute GVariant.
    g_variant_get(parameters, "(sssa{ss}sa(sa{sv}))",
                  &actionid,
                  &message,
                  &icon,
                  &details,
                  &cookie,
                  &identities);

    g_debug("received authentication request for action %s", actionid);

    // Log the actionid.
    if (enable_action_print) {
        g_print("AUTH %s\n", actionid);
    }

    // Attempt to cancel the authentication.
    response = g_dbus_message_new_method_error(g_dbus_method_invocation_get_message(invocation),
                                               "org.freedesktop.PolicyKit1.Error.Cancelled",
                                               "Authentication Cancelled.");

    // Send the error message to polkit.
    if (!g_dbus_connection_send_message(bus, response, G_DBUS_SEND_MESSAGE_FLAGS_NONE, NULL, NULL)) {
        g_critical("g_dbus_connection_send_message returned failure");
    }

    g_object_unref(response);
    g_free(message);
    g_free(icon);
    g_free(cookie);
    g_free(actionid);
    return;
}

gpointer polkit_agent_thread(G_GNUC_UNUSED gpointer data)
{
    GMainLoop *dbusloop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(dbusloop);
    return NULL;
}

GThread *register_polkit_agent(GDBusConnection *bus)
{
    GDBusMessage *request;
    GDBusMessage *reply;
    GVariantBuilder session;
    GThread *agent;

    g_dbus_connection_register_object(bus, "/", &PolkitAgentInterface, &PolkitAgentVTable, NULL, NULL, NULL);

    request = g_dbus_message_new_method_call("org.freedesktop.PolicyKit1",
                                             "/org/freedesktop/PolicyKit1/Authority",
                                             "org.freedesktop.PolicyKit1.Authority",
                                             "RegisterAuthenticationAgent");

    g_variant_builder_init(&session, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&session, "{sv}", "pid", g_variant_new_uint32(getpid()));
    g_variant_builder_add(&session, "{sv}", "start-time", g_variant_new_uint64(0));
    g_dbus_message_set_body(request, g_variant_new("((sa{sv})ss)", "unix-process", &session, "C", "/"));

    reply = g_dbus_send(bus, request, G_DBUS_SEND_MESSAGE_FLAGS_NONE, -1, NULL, NULL, NULL);
    agent = g_thread_new("polkit-agent", polkit_agent_thread, NULL);
    g_object_unref(reply);
    g_variant_builder_clear(&session);
    return agent;
}
