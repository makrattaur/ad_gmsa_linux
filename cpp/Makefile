
PKG_CONFIG_LIBS = krb5

CXXFLAGS = -g -MMD -Wall -std=c++11 $(shell pkg-config --cflags $(PKG_CONFIG_LIBS))
LDFLAGS = $(shell pkg-config --libs-only-L --libs-only-other $(PKG_CONFIG_LIBS))
LDLIBS = -lstdc++ $(shell pkg-config --libs-only-l $(PKG_CONFIG_LIBS))

SOURCES = krb_objects.cpp make_keytab_entry.cpp cleanup_keytab.cpp highest_kvno.cpp
PROGS = make_keytab_entry cleanup_keytab highest_kvno


.PHONY: all
all: $(PROGS)

.PHONY: build
build: all

make_keytab_entry: make_keytab_entry.o krb_objects.o

cleanup_keytab: cleanup_keytab.o krb_objects.o

highest_kvno: highest_kvno.o krb_objects.o

-include $(SOURCES:.cpp=.d)

.PHONY: clean
clean:
	rm -f $(PROGS) $(SOURCES:.cpp=.o) $(SOURCES:.cpp=.d)

.PHONY: install
install:
	install -d "$(DESTDIR)$(prefix)/bin"
	install make_keytab_entry "$(DESTDIR)$(prefix)/bin/ad-gmsa-make-keytab-entry"
	install cleanup_keytab "$(DESTDIR)$(prefix)/bin/ad-gmsa-cleanup-keytab"
	install highest_kvno "$(DESTDIR)$(prefix)/bin/ad-gmsa-highest-kvno"

