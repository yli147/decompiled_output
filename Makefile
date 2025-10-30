# Makefile for ubt_x64a64_al_mem49

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g
TARGET = ubt_x64a64_al_mem49
SOURCES = ubt_x64a64_al_mem49.c
HEADERS = ubt_x64a64_al_mem49.h

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES)

clean:
	rm -f $(TARGET)

.PHONY: clean
