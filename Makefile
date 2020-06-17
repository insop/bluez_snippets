ALLTARGETS = profile-server profile-client

CFLAGS = -Wall -Werror $(shell pkg-config --cflags --libs gio-unix-2.0)

all: $(ALLTARGETS)

$(ALLTARGETS): %: %.c
	gcc $< -o $@ $(CFLAGS)

clean:
	rm -f $(ALLTARGETS)

.PHONY: clean all