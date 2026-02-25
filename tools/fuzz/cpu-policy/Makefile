XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: all
all: afl-policy-fuzzer

.PHONY: clean
clean:
	$(RM) -f -- *.o .*.d .*.d2 afl-policy-fuzzer

.PHONY: distclean
distclean: clean
	$(RM) -f -- *~

.PHONY: install
install: all

.PHONY: uninstall

CFLAGS += $(CFLAGS_xeninclude) -D__XEN_TOOLS__
CFLAGS += $(APPEND_CFLAGS) -Og

vpath %.c $(XEN_ROOT)/xen/arch/x86/lib/cpu-policy

lib-y :=
include $(XEN_ROOT)/xen/arch/x86/lib/cpu-policy/Makefile.common

afl-policy-fuzzer: afl-policy-fuzzer.o $(lib-y)
	$(CC) $(CFLAGS) $^ -o $@

-include $(DEPS_INCLUDE)
