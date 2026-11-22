# jenc_c Makefile - C99 libjenc + jenc CLI + tests (V001 only)
#
#   make            build jenc (CLI) and libjenc.a
#   make test       build and run tests/test_vectors (run from jenc_c/)
#   make debug      build jenc with -DJENC_DEBUG_SKIP_MAC (skip-MAC, unsafe)
#   make clean
#
# Windows: use gcc from MinGW / strawberry-perl, or see build.bat.

CC      ?= gcc
CFLAGS  ?= -O2
CSTD    := -std=c99 -Wall -Wextra -pedantic -Wno-attributes -D_POSIX_C_SOURCE=200809L
CPPFLAGS := -Isrc/openssh_shim -Isrc -Isrc/openssh-portable

VENDOR_SRC := src/openssh-portable/rijndael.c \
              src/openssh-portable/openbsd-compat/sha2.c \
              src/openssh-portable/openbsd-compat/timingsafe_bcmp.c
LIB_SRC    := src/jenc.c src/jenc_crypto.c
LIB_OBJ    := $(LIB_SRC:.c=.o) $(VENDOR_SRC:.c=.o)

ifeq ($(OS),Windows_NT)
  EXE     := .exe
  SYSLIBS := -lbcrypt
else
  EXE     :=
  SYSLIBS :=
endif

JENC    := jenc$(EXE)
TEST    := test_vectors$(EXE)

.PHONY: all test debug clean

all: $(JENC)

libjenc.a: $(LIB_OBJ)
	$(AR) rcs $@ $^

$(JENC): src/jenc_crypt.c libjenc.a
	$(CC) $(CSTD) $(CFLAGS) $(CPPFLAGS) -o $@ $< libjenc.a $(SYSLIBS)

$(TEST): tests/test_vectors.c libjenc.a
	$(CC) $(CSTD) $(CFLAGS) $(CPPFLAGS) -o $@ $< libjenc.a $(SYSLIBS)

test: $(TEST)
	./$(TEST)

# Debug build: skip-MAC decrypt compiled in. Not for release binaries.
debug: CFLAGS += -DJENC_DEBUG_SKIP_MAC
debug: clean $(JENC)

# Vendored sources: compiled with the shim on the path; warnings from
# upstream code are not ours to fix, so -w silences them for those files only.
src/openssh-portable/rijndael.o: src/openssh-portable/rijndael.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -w -c -o $@ $<

src/openssh-portable/openbsd-compat/sha2.o: src/openssh-portable/openbsd-compat/sha2.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -w -c -o $@ $<

src/openssh-portable/openbsd-compat/timingsafe_bcmp.o: src/openssh-portable/openbsd-compat/timingsafe_bcmp.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -w -c -o $@ $<

%.o: %.c src/jenc.h src/jenc_crypto.h
	$(CC) $(CSTD) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

clean:
	rm -f $(LIB_OBJ) libjenc.a $(JENC) $(TEST)
