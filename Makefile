CC = gcc
CFLAGS = -Wall -O2

all: fast_scan

fast_scan: fast_scan.c
	$(CC) $(CFLAGS) -o fast_scan fast_scan.c

clean:
	rm -f fast_scan fast_scan.exe *.o
