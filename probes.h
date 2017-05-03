#ifndef __PROBES_H
#define __PROBES_H

gboolean check_access_method(GDBusConnection *bus, const gchar *dest, const gchar *path, const gchar *instance, const gchar *method, const gchar* sig);
gboolean check_name_protected(GDBusConnection *bus, const gchar *name);
gboolean check_access_property(GDBusConnection *bus, const gchar *dest, const gchar *path, const gchar *instance, const gchar *property, const gchar* sig);

// Options
extern gboolean enable_access_probes;
extern gboolean enable_action_print;

#endif
