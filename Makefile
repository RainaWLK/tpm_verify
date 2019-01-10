CFLAGS +=
LDLIBS += -lcrypto

all: verify_quote

verify_quote: verify_quote.o

verify_quote.o: verify_quote.c

clean:
	rm -rf \
		*.o \
		verify_quote

