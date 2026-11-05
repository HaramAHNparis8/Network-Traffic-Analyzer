CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -g
CPPFLAGS = -I.

TARGET = analyzer
OBJS = main.o queue.o parser.o pcap_reader.o security.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

main.o: main.c pcap_reader.h parser.h queue.h security.h packet.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

queue.o: queue.c queue.h packet.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

parser.o: parser.c parser.h packet.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

pcap_reader.o: pcap_reader.c pcap_reader.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

security.o: security.c security.h packet.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

test_security: tests/test_security.c security.o parser.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^

test: test_security
	./test_security

clean:
	rm -f $(TARGET) $(OBJS) test_security

.PHONY: all test clean
