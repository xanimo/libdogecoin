# Constant-time tests (dudect). Standalone: these compile a local copy of the
# function under test at -O2, independent of the autotools build, because the
# library targets are static and the point is to measure the algorithm as the
# release compiler emits it.
#
# Usage:
#   make -f ct.mk         # build all ct_* tests
#   make -f ct.mk run     # build and run each (bounded by RUN_TIMEOUT seconds)
#   make clean

CC      ?= clang
CFLAGS  ?= -O2 -g -Wall
LDLIBS  := -lm
RUN_TIMEOUT ?= 120

TESTS := ct_bip38_mem_eq

all: $(TESTS)

ct_%: ct_%.c dudect.h
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

# Bounded run for CI: "no leak within the time budget" exits 0 (pass).
# A detected leak makes the test exit non-zero before the timeout.
run: $(TESTS)
	@for t in $(TESTS); do \
	  echo "== $$t =="; \
	  timeout $(RUN_TIMEOUT) ./$$t; \
	  rc=$$?; \
	  if [ $$rc -eq 124 ]; then echo "  no leak within $(RUN_TIMEOUT)s budget (pass)"; \
	  elif [ $$rc -ne 0 ]; then echo "  LEAK DETECTED (exit $$rc)"; exit 1; \
	  else echo "  completed clean"; fi; \
	done

clean:
	rm -f $(TESTS)

.PHONY: all run clean
