CC = gcc

CFLAGS = -O3 -Wall -g -std=gnu++11

INCLUDES= 

LFLAGS=-L/usr/lib/i386-linux-gnu

SRCS = HcEnginePrivate.cpp  HcLfsr.cpp 

OBJS = $(SRCS:.cpp=.o)

MAIN = libhypercrypt.a

.PHONY: depend clean

all:    $(MAIN)

$(MAIN):$(OBJS)
	$(AR) rcs $(MAIN) $(OBJS)

.cpp.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@

clean:
	$(RM) *.o *~ $(MAIN)

depend: $(SRCS)
	makedepend $(INCLUDES) $^
