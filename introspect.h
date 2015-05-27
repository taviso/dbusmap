#ifndef __INTROSPECT_H
#define __INTROSPECT_H

typedef void (* introspect_cb_t)(xmlDocPtr doc, GDBusConnection *bus, const gchar *dest, const gchar *path, gpointer user);

void descend_introspection_nodes(GDBusConnection *bus, gchar *name, const gchar *root, introspect_cb_t callback, gpointer user);
void list_dbus_methods(xmlDocPtr doc, GDBusConnection *bus, const gchar *dest, const gchar *path, gpointer user);
void list_dbus_properties(xmlDocPtr doc, GDBusConnection *bus, const gchar *dest, const gchar *path, gpointer user);

#endif
