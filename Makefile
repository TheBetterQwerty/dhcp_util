cc = gcc

source = src/*
binary = build/starver

flags = -Wextra -Wall -O3
cflags = -lpcap -lpthread

all:
	$(cc) -o $(binary) $(source) $(flags) $(cflags)
