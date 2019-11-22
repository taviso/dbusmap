#ifndef __POLKITAGENT_H
#define __POLKITAGENT_H

GThread *register_polkit_agent(GDBusConnection *bus, GPid pid);

// Options
extern gboolean enable_action_print;
extern gchar *polkit_auth_password;

#endif
