
CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g

TARGET = analyzer
OBJS = main.o queue.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

main.o: main.c queue.h packet.h
	$(CC) $(CFLAGS) -c main.c -o main.o

queue.o: queue.c queue.h packet.h
	$(CC) $(CFLAGS) -c queue.c -o queue.o

queue:
	$(CC) $(CFLAGS) -c queue.c -o queue.o

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all queue clean
