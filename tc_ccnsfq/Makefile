CFLAGS += -DCONFIG_GACT -DCONFIG_GACT_PROB
TCSO = q_ccnsfq.so

q_ccnsfq.so: q_ccnsfq.c
	$(CC) $(CFLAGS)  -shared -fpic -o q_ccnsfq.so q_ccnsfq.c

LDLIBS += -L. -ltc -lm -ldl

LDFLAGS += -Wl,-export-dynamic

%.so: %.c
	$(CC) $(CFLAGS) -shared -fpic $< -o $@

all: $(TCSO)

install: all
	mkdir -p $(DESTDIR)/usr/lib/tc
	for i in $(TCSO); \
	do install -m 755 $$i $(DESTDIR)/usr/lib/tc; \
	done

clean:
	rm -f $(TCOBJ) $(TCLIB) *.so ;


