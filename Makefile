all: greu

# greu makefile for linux

PROG=greu
SRCS=greu.c gre.c
CFLAGS+=-Wall -Werror -fdiagnostics-color -g -Wno-unused-function -Wno-unused-value
MAN=
LDADD=-levent
# strangely, on some new versions of linux (e.g. Debian 11 and onwards), only clang works in resolving libraries
CC=clang

greu: greu.c gre.h gre.c Makefile
	${CC} $(CFLAGS) $(LDADD) -o $(PROG) $(SRCS)

clean:
	rm greu
