#ifndef __POLKITAGENT_H
#define __POLKITAGENT_H

GThread *register_polkit_agent(GDBusConnection *bus);

// Options
extern gboolean enable_action_print;

#endif
