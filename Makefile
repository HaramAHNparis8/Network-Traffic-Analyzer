CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g
CPPFLAGS = -I.

TARGET = analyzer
TEST_TARGET = test_queue

OBJS = main.o queue.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

main.o: main.c queue.h packet.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c main.c -o main.o

queue.o: queue.c queue.h packet.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c queue.c -o queue.o

$(TEST_TARGET): tests/test_queue.c tests/test_framework.h queue.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $(TEST_TARGET) tests/test_queue.c queue.o
test: $(TEST_TARGET)
	./$(TEST_TARGET)

clean:
	rm -f $(TARGET) $(OBJS) $(TEST_TARGET)

.PHONY: all test clean
