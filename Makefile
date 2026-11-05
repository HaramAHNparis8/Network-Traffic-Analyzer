CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g
CPPFLAGS = -I.

TARGET = analyzer
OBJS = main.o queue.o parser.o pcap_reader.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

main.o: main.c queue.h packet.h parser.h pcap_reader.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

queue.o: queue.c queue.h packet.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

parser.o: parser.c parser.h packet.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

pcap_reader.o: pcap_reader.c pcap_reader.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

test_queue: tests/test_queue.c tests/test_framework.h queue.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test_queue.c queue.o

test_parser: tests/test_parser.c tests/test_framework.h parser.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test_parser.c parser.o

test: test_queue test_parser
	./test_queue
	./test_parser

clean:
	rm -f $(TARGET) $(OBJS) test_queue test_parser

.PHONY: all test clean
