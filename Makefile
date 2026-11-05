CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -g
CPPFLAGS = -I.

TARGET = analyzer

OBJS = main.o queue.o parser.o pcap_reader.o security.o conntrack.o

TEST_TARGETS = test_queue test_parser test_security test_conntrack

all: $(TARGET)

# Main executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# Object files
main.o: main.c pcap_reader.h parser.h queue.h security.h conntrack.h packet.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

queue.o: queue.c queue.h packet.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

parser.o: parser.c parser.h packet.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

pcap_reader.o: pcap_reader.c pcap_reader.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

security.o: security.c security.h packet.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

conntrack.o: conntrack.c conntrack.h packet.h security.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# Unit tests
test_queue: tests/test_queue.c tests/test_framework.h queue.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test_queue.c queue.o

test_parser: tests/test_parser.c tests/test_framework.h parser.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test_parser.c parser.o

test_security: tests/test_security.c security.o parser.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^

test_conntrack: tests/test_conntrack.c conntrack.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^

# Run all tests
test: $(TEST_TARGETS)
	./test_queue
	./test_parser
	./test_security
	./test_conntrack

# Cleanup
clean:
	rm -f $(TARGET) $(OBJS) $(TEST_TARGETS)

.PHONY: all test clean
