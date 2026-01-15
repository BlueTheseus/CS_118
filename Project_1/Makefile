CC=gcc
CFLAGS=-Wall
LDFLAGS=-lssl -lcrypto

# Detect OS
UNAME_S := $(shell uname -s)

# Check if OpenSSL is available
ifeq ($(UNAME_S),Darwin)
    # macOS with Homebrew
    OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null)
    ifneq ($(OPENSSL_PREFIX),)
        CFLAGS += -I$(OPENSSL_PREFIX)/include
        LDFLAGS += -L$(OPENSSL_PREFIX)/lib
    else
        $(error OpenSSL not found. Install with: brew install openssl)
    endif
    # Verify header exists
    OPENSSL_CHECK := $(shell test -f $(OPENSSL_PREFIX)/include/openssl/ssl.h && echo "OK")
    ifneq ($(OPENSSL_CHECK),OK)
        $(error OpenSSL headers not found at $(OPENSSL_PREFIX)/include)
    endif
else
    # Linux - check for OpenSSL headers
    OPENSSL_CHECK := $(shell echo '\#include <openssl/ssl.h>' | $(CC) -E - >/dev/null 2>&1 && echo "OK")
    ifneq ($(OPENSSL_CHECK),OK)
        $(error OpenSSL not found. Install with: sudo apt-get install libssl-dev)
    endif
endif

all: clean server

server:
	$(CC) $(CFLAGS) proxy.c -o server $(LDFLAGS)

clean:
	rm -rf server

.PHONY: all clean
