
include $(XEN_ROOT)/Config.mk

.PHONY: default
default: symbols

.PHONY: clean
clean:
	rm -f *.o symbols

symbols: symbols.c
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $<
