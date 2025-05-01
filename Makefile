CC = gcc
CFLAGS = -Wall -g

OBJS = fuzzer.o help.o

all: fuzzer

fuzzer: $(OBJS)
	$(CC) $(CFLAGS) -o fuzzer $(OBJS)

fuzzer.o: src/fuzzer.c src/help.h
	$(CC) $(CFLAGS) -c src/fuzzer.c

help.o: src/help.c src/help.h
	$(CC) $(CFLAGS) -c src/help.c

clean:
	rm -f $(OBJS) fuzzer *.tar *.txt
