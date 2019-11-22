#define _GNU_SOURCE
#include <gio/gio.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

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
gchar *polkit_auth_password;

void InvokePolkitHelper(gchar *cookie)
{
    GPid child;
    int pkhinfd;
    int status;
    GError *error = NULL;
    char *agentname;
    gchar *argv[4] = {0};
    gchar *polkit_agent_locations[] = {
        "/usr/lib/policykit-1/polkit-agent-helper-1",
        "/usr/lib/polkit-1/polkit-agent-helper-1",
        NULL,
    };

    // Distributions put this file in different places.
    for (int i = 0; polkit_agent_locations[i]; i++) {
        if (g_file_test(polkit_agent_locations[i], G_FILE_TEST_EXISTS)) {
            agentname = polkit_agent_locations[i];
        }
    }

    if (agentname == NULL) {
        g_warning("unable to find polkit-agent-helper utility");
        return;
    }

    argv[0] = agentname;
    argv[1] = g_get_user_name();
    argv[2] = cookie;

    if (g_spawn_async_with_pipes(
            NULL,
            argv,
            NULL,
            G_SPAWN_DO_NOT_REAP_CHILD
                | G_SPAWN_STDOUT_TO_DEV_NULL
                | G_SPAWN_STDERR_TO_DEV_NULL
            ,
            NULL,
            NULL,
            &child,
            &pkhinfd,
            NULL,
            NULL,
            &error) == false) {
        g_assert_nonnull(error);
        g_warning("failed to invoke polkit-agent-helper, %s", error->message);
        g_error_free(error);
        return;
    }

    write(pkhinfd, polkit_auth_password, strlen(polkit_auth_password));
    write(pkhinfd, "\n", 1);
    close(pkhinfd);

    if (waitpid(child, &status, 0) != child) {
        g_warning("failed to wait for polkit-agent-helper");
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status)) {
        g_warning("unexpected result from polkit-agent-helper");
    }

    g_spawn_close_pid(child);
    g_message("Auth appears to be successful");
    return;
}

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
    gchar *key;
    gchar *value;
    gchar *idtype;
    GVariantIter *details;
    GVariantIter *identities;
    GVariantIter *identity;
    GDBusMessage *response;
    gboolean authenticate = false;

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

    while (g_variant_iter_loop(details, "{ss}", &key, &value)) {
        g_debug("detail key %s, value %s", key, value);
    }

    // This variant contains the userid we have to authenticate as.
    while (g_variant_iter_loop(identities, "(sa{sv})", &idtype, &identity)) {
        GVariant *value;

        g_debug("identity type: %s", idtype);

        // Only care about unix-user for now.
        if (g_strcmp0(idtype, "unix-user") != 0) {
            g_warning("unhandled identity type %s", idtype);
            continue;
        }

        while (g_variant_iter_loop(identity, "{sv}", &key, &value)) {
            guint32 uid;

            g_debug("identity type %s, key %s", idtype, key);

            if (g_strcmp0(key, "uid") == 0) {
                g_variant_get(value, "u", &uid);

                // We can authenticate as this user.
                if (uid == getuid() && polkit_auth_password) {
                    InvokePolkitHelper(cookie);
                    authenticate = true;
                    break;
                }
            }
        }
    }

    // Log the actionid.
    if (enable_action_print) {
        g_print("AUTH %s\n", actionid);
    }

    // Attempt to cancel the authentication.
    if (authenticate == false) {
        response = g_dbus_message_new_method_error(
                        g_dbus_method_invocation_get_message(invocation),
                        "org.freedesktop.PolicyKit1.Error.Cancelled",
                        "Authentication Cancelled.");

        // Send the error message to polkit.
        if (!g_dbus_connection_send_message(
                bus,
                response,
                G_DBUS_SEND_MESSAGE_FLAGS_NONE,
                NULL,
                NULL)) {
        g_critical("g_dbus_connection_send_message returned failure");
        }

        g_object_unref(response);
    }

    g_variant_iter_free(details);
    g_variant_iter_free(identities);
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

GThread *register_polkit_agent(GDBusConnection *bus, GPid pid)
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
    g_variant_builder_add(&session, "{sv}", "pid", g_variant_new_uint32(pid));
    g_variant_builder_add(&session, "{sv}", "start-time", g_variant_new_uint64(0));
    g_dbus_message_set_body(request, g_variant_new("((sa{sv})ss)", "unix-process", &session, "C", "/"));

    reply = g_dbus_send(bus, request, G_DBUS_SEND_MESSAGE_FLAGS_NONE, -1, NULL, NULL, NULL);
    agent = g_thread_new("polkit-agent", polkit_agent_thread, NULL);
    g_object_unref(reply);
    g_variant_builder_clear(&session);
    g_message("polkit agent registered for %d", pid);
    return agent;
}
