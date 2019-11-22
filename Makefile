CFLAGS      = -Wall -Wextra -std=gnu99 -ggdb3 -O0
CPPFLAGS    = $(shell pkg-config --cflags glib-2.0,gio-2.0,libprocps,libxml-2.0)
LDLIBS      = $(shell pkg-config --libs glib-2.0,gio-2.0,libprocps,libxml-2.0)

all: dbus-map pkwrapper

dbus-map: dbus-map.o polkitagent.o actions.o util.o probes.o introspect.o

pkwrapper: pkwrapper.o polkitagent.o

clean:
	rm -f dbus-map pkwrapper core *.o
