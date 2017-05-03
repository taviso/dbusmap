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
#include "util.h"

// --filter-actions=auth,yes,admin,no,NotAuthorized
//
// This is an implementation of pkaction/pkcheck that supports more
// filtering/options/etc to allow for detailed auditing.

typedef enum {
    NotAuthorized                               = 0,
    AuthenticationRequired                      = 1,
    AdministratorAuthenticationRequired         = 2,
    AuthenticationRequiredRetained              = 3,
    AdministratorAuthenticationRequiredRetained = 4,
    Authorized                                  = 5,
    AuthorizationMax,
} impauth_t;

static const gchar * impauth_to_str(impauth_t authorization)
{
    static const gchar * names[] = {
        [NotAuthorized]                                 = "NotAuthorized",
        [AuthenticationRequired]                        = "AuthenticationRequired",
        [AdministratorAuthenticationRequired]           = "AdministratorAuthenticationRequired",
        [AuthenticationRequiredRetained]                = "AuthenticationRequiredRetained",
        [AdministratorAuthenticationRequiredRetained]   = "AdministratorAuthenticationRequiredRetained",
        [Authorized]                                    = "Authorized",
    };

    g_return_val_if_fail(authorization < AuthorizationMax, NULL);

    return names[authorization];
}

static const gchar * impauth_to_shortstr(impauth_t authorization)
{
    static const gchar * names[] = {
        [NotAuthorized]                                 = "No",
        [AuthenticationRequired]                        = "Auth",
        [AdministratorAuthenticationRequired]           = "Admin",
        [AuthenticationRequiredRetained]                = "Auth",
        [AdministratorAuthenticationRequiredRetained]   = "Admin",
        [Authorized]                                    = "Yes",
    };

    g_return_val_if_fail(authorization < AuthorizationMax, NULL);

    return names[authorization];
}

G_GNUC_UNUSED static impauth_t str_to_impauth(const gchar *authorization)
{
    for (gint i = 0; i < AuthorizationMax; i++) {
        if (g_strcmp0(authorization, impauth_to_str(i)) == 0)
            return i;
    }
    g_assert_not_reached();
}

// Return a list of D-Bus names that the server reports as an array of strings
// in a GVariant.
void get_action_list(GDBusConnection *bus, const gchar *filter)
{
    GVariantIter *iter;
    GVariant *actions;
    GVariant *annotations;
    GDBusMessage *request;
    GDBusMessage *reply;
    gchar **filters;
    gchar *action;
    gchar *description;
    gchar *message;
    gchar *vendor;
    gchar *vendorurl;
    gchar *icon;
    guint  implicit_any;
    guint  implicit_inactive;
    guint  implicit_active;

    request = g_dbus_method("org.freedesktop.PolicyKit1",
                            "/org/freedesktop/PolicyKit1/Authority",
                            "org.freedesktop.PolicyKit1.Authority",
                            "EnumerateActions");

    g_dbus_message_set_body(request, g_variant_new ("(s)", "C"));

    filters = g_strsplit(filter, ",", 0);
    reply   = g_dbus_send(bus, request, G_DBUS_SEND_MESSAGE_FLAGS_NONE, timeout, NULL, NULL, NULL);
    actions = g_dbus_message_get_body(reply);

    // Get an iterator for each ActionDescription structure.
    g_variant_get(actions, "(a(ssssssuuua{ss}))", &iter);

    g_print("%-64s Any/Inactive/Active\n", "Action");

nomatch:
    while (g_variant_iter_loop(iter, "(ssssssuuua{ss})",
                                     &action,
                                     &description,
                                     &message,
                                     &vendor,
                                     &vendorurl,
                                     &icon,
                                     &implicit_any,
                                     &implicit_inactive,
                                     &implicit_active,
                                     &annotations)) {

        for (gchar **p = filters; *p; p++) {
            if (g_str_has_prefix(*p, "active=")) {
                if (g_ascii_strcasecmp(*p + strlen("active="), impauth_to_shortstr(implicit_active)) == 0)
                    break;
            }
            if (g_str_has_prefix(*p, "inactive=")) {
                if (g_ascii_strcasecmp(*p + strlen("inactive="), impauth_to_shortstr(implicit_inactive)) == 0)
                    break;
            }
            if (g_str_has_prefix(*p, "any=")) {
                if (g_ascii_strcasecmp(*p + strlen("any="), impauth_to_shortstr(implicit_any)) == 0)
                    break;
            }
            goto nomatch;
        }

        g_print("%-64s %s/%s/%s\n", action, impauth_to_shortstr(implicit_any),
                                            impauth_to_shortstr(implicit_inactive),
                                            impauth_to_shortstr(implicit_active));
    }

    g_object_unref(reply);
    g_object_unref(request);
    return;
}

