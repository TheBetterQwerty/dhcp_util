cc = gcc

source = src/main.c src/packet.c
binary = starver

flags = -Wextra -Wall -O3
cflags = -lpcap -lpthread

all:
	$(cc) -o $(binary) $(source) $(flags) $(cflags)
