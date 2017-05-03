#ifndef __UTIL_H
#define __UTIL_H

#define g_dbus_method g_dbus_message_new_method_call
#define g_dbus_send g_dbus_connection_send_message_with_reply_sync

extern gint timeout;

GVariant * g_dbus_simple_send(GDBusConnection *bus, GDBusMessage *msg, const gchar *type);

#endif
