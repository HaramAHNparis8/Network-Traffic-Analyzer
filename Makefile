CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g
CPPFLAGS = -I.

TARGET = analyzer
TEST_TARGET = test_queue
PARSER_TEST = test_parser

OBJS = main.o queue.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

main.o: main.c queue.h packet.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

queue.o: queue.c queue.h packet.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

parser.o: parser.c parser.h packet.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(TEST_TARGET): tests/test_queue.c tests/test_framework.h queue.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test_queue.c queue.o

$(PARSER_TEST): tests/test_parser.c tests/test_framework.h parser.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test_parser.c parser.o

test: $(TEST_TARGET) $(PARSER_TEST)
	./$(TEST_TARGET)
	./$(PARSER_TEST)

clean:
	rm -f $(TARGET) $(OBJS) parser.o $(TEST_TARGET) $(PARSER_TEST)

.PHONY: all test clean
