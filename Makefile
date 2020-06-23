ALLTARGETS = profile-server profile-client hfp-ag-sine-out

CFLAGS = -Wall -Werror $(shell pkg-config --cflags --libs gio-unix-2.0) -lbluetooth -lm

all: $(ALLTARGETS)

$(ALLTARGETS): %: %.c
	gcc $< -o $@ $(CFLAGS)

clean:
	rm -f $(ALLTARGETS)

.PHONY: clean all