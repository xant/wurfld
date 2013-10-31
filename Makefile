UNAME := $(shell uname)

LDFLAGS += -L. -pthread -lwurfl

ifeq ($(UNAME), Linux)
LDFLAGS +=
else
LDFLAGS +=
endif

ifeq ($(UNAME), Darwin)
SHAREDFLAGS = -dynamiclib
SHAREDEXT = dylib
else
SHAREDFLAGS = -shared
SHAREDEXT = so
endif


#CC = gcc
TARGETS = $(patsubst %.c, %.o, $(wildcard src/*.c))

all: objects wurfld

wurfld: objects
	gcc $(LDFLAGS) src/*.o -o wurfld

objects: CFLAGS += -fPIC -Isrc -Wall -Werror -Wno-parentheses -Wno-pointer-sign -O3
objects: $(TARGETS)

clean:
	rm -f src/*.o
	rm -f wurfld
