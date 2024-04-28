all: greu

# greu makefile for linux

PROG=greu
SRCS=greu.c gre.c
CFLAGS+=-Wall -Werror -fdiagnostics-color -g -Wno-unused-function
MAN=
LDADD=-levent
CC=cc

greu: greu.c gre.h gre.c Makefile
	${CC} $(CFLAGS) $(LDADD) -o $(PROG) $(SRCS)

clean:
	rm greu
