#ifndef __UTIL_H
#define __UTIL_H

#define g_dbus_method g_dbus_message_new_method_call
#define g_dbus_send g_dbus_connection_send_message_with_reply_sync

extern gint timeout;

#include <libxml/xpath.h>
gchar* get_method_signature(xmlNodePtr node);
gchar* get_property_signature(xmlNodePtr node);

GVariant* build_invalid_body(const gchar* sig);

GVariant * g_dbus_simple_send(GDBusConnection *bus, GDBusMessage *msg, const gchar *type);

#endif
