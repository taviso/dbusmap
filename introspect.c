#define _GNU_SOURCE
#include <gio/gio.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "polkitagent.h"
#include "actions.h"
#include "util.h"
#include "introspect.h"
#include "probes.h"

// I'm not particularly concerned about xmlChar vs char.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-sign"

typedef void (* introspect_cb_t) (xmlDocPtr doc, GDBusConnection *bus, const gchar *dest, const gchar *path, gpointer user);

// For the specified D-Bus destination, get any available Introspection XML.
//
// Returns NULL, or a pointer you should free with g_free().
static gchar * get_name_introspect(GDBusConnection *bus, const gchar *name, const gchar *path)
{
    GVariant     *data;
    gchar        *xml;

    g_return_val_if_fail(g_variant_is_object_path(path), NULL);

    data = g_dbus_simple_send(bus, g_dbus_method(name, path, "org.freedesktop.DBus.Introspectable", "Introspect"), "(s)");

    if (data) {
        g_variant_get(data, "(s)", &xml);
        g_variant_unref(data);
        return xml;
    }

    g_warn_if_reached();
    return NULL;
}

void list_dbus_methods(xmlDocPtr doc, GDBusConnection *bus, const gchar *dest, const gchar *path, gpointer user)
{
    GHashTable *methods = user;
    xmlXPathContextPtr context;
    xmlXPathObjectPtr result;
    xmlNodeSetPtr nodes;

    context = xmlXPathNewContext(doc);

    result = xmlXPathEvalExpression("/node/interface/method[@name]", context);

    xmlXPathFreeContext(context);

    if (!result) {
        g_debug("xpath query failed for method declarations");
        return;
    }

    if (!result->nodesetval) {
        g_debug("no results for xpath query");
        xmlXPathFreeObject(result);
        return;
    }

    nodes = result->nodesetval;

    for (gint i = 0; i < nodes->nodeNr; i++) {
        xmlAttrPtr attrib = nodes->nodeTab[i]->properties;
        gchar *method;

        method = g_strdup_printf("m:%s.%s", nodes->nodeTab[i]->parent->properties->children->content, attrib->children->content);

        if (!g_hash_table_contains(methods, method)) {
            g_hash_table_add(methods, method);
            gchar* sig = get_method_signature(nodes->nodeTab[i]);
            if (check_access_method(bus,
                                    dest,
                                    path,
                                    nodes->nodeTab[i]->parent->properties->children->content,
                                    attrib->children->content,
                                    sig)) {
                g_print("\t%s %s\n", method, path);
            }
            g_free(sig);
        }
    }

    xmlXPathFreeObject(result);
    return;
}

void list_dbus_properties(xmlDocPtr doc, GDBusConnection *bus, const gchar *dest, const gchar *path, gpointer user)
{
    GHashTable *methods = user;
    xmlXPathContextPtr context;
    xmlXPathObjectPtr result;
    xmlNodeSetPtr nodes;

    context = xmlXPathNewContext(doc);

    result = xmlXPathEvalExpression("/node/interface/property[@name]", context);

    xmlXPathFreeContext(context);

    if (!result) {
        g_debug("xpath query failed for property declarations");
        return;
    }

    if (!result->nodesetval) {
        g_debug("no results for xpath query");
        xmlXPathFreeObject(result);
        return;
    }

    nodes = result->nodesetval;

    for (gint i = 0; i < nodes->nodeNr; i++) {
        xmlAttrPtr attrib = nodes->nodeTab[i]->properties;
        gchar *property;

        // Find the attribute name
        while (g_strcmp0(attrib->name, "name") != 0) {
            attrib = attrib->next;
            g_assert(attrib);
        }

        property = g_strdup_printf("p:%s.%s", nodes->nodeTab[i]->parent->properties->children->content, attrib->children->content);

        if (!g_hash_table_contains(methods, property)) {
            g_hash_table_add(methods, property);
            gchar* sig = get_property_signature(nodes->nodeTab[i]);
            if (check_access_property(bus, dest, path, nodes->nodeTab[i]->parent->properties->children->content, attrib->children->content, sig))
                g_print("\t%s %s\n", property, path);
            g_free(sig);
        }
    }

    xmlXPathFreeObject(result);
    return;
}

void descend_introspection_nodes(GDBusConnection *bus, gchar *name, const gchar *root, introspect_cb_t callback, gpointer user)
{
    xmlXPathContextPtr context;
    xmlXPathObjectPtr result;
    xmlNodeSetPtr nodes;
    xmlDocPtr doc;
    gchar *xml;

    g_debug("searching for object paths in %s @%s", name, root);

    if (!(xml = get_name_introspect(bus, name, root))) {
        g_debug("failed to introspect %s", name);
        return;
    }

    if (!(doc = xmlReadMemory(xml,
                              strlen(xml),
                              "noname.xml",
                              NULL,
                              XML_PARSE_NOERROR | XML_PARSE_NONET | XML_PARSE_NOWARNING))) {
        g_debug("failed to parse introspect response as xml from %s", name);
        return;
    }

    // Call user callback
    callback(doc, bus, name, root, user);

    // Query parsed xml for any subnodes
    context = xmlXPathNewContext(doc);
    result  = xmlXPathEvalExpression("/node/node[@name]", context);
    nodes   = result->nodesetval;

    g_debug("discovered %u subnodes matching xpath expression", nodes->nodeNr);

    for (gint i = 0; i < nodes->nodeNr; i++) {
        gchar *subpath = g_strdup_printf("%s%s%s", root, g_str_has_suffix(root, "/") ? "" : "/", nodes->nodeTab[i]->properties->children->content);

        // This is hacky trick to get the node name
        g_debug("discovered sub-path name %s", subpath);

        descend_introspection_nodes(bus, name, subpath, callback, user);

        g_free(subpath);
    }

    xmlXPathFreeObject(result);
    xmlXPathFreeContext(context);
    xmlFree(doc);
    g_free(xml);
    return;
}

#pragma GCC diagnostic pop
