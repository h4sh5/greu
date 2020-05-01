all: greu

	
PROG=greu
SRCS=greu.c gre.c
CFLAGS+=-Wall -Werror -fdiagnostics-color -g -Wno-unused-function
MAN=
LDADD=-levent

.include <bsd.prog.mk>

