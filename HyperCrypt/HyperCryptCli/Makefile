CC = gcc

CFLAGS = -O3 -Wall -g -std=gnu++11 -I../HyperCryptLib

INCLUDES= 

LFLAGS=-L/usr/lib/i386-linux-gnu -L../HyperCryptLib

LIBS = -lhypercrypt -lm -lstdc++ -lboost_system -lboost_filesystem -lssl -lcrypto

SRCS = HyperCryptCli.cpp 

OBJS = $(SRCS:.cpp=.o)

MAIN = hypercrypt

.PHONY: depend clean

all:    $(MAIN)

$(MAIN): $(OBJS) 
	$(CC) $(CFLAGS) $(INCLUDES) -o $(MAIN) $(OBJS) $(LFLAGS) $(LIBS)

.cpp.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@

clean:
	$(RM) *.o *~ $(MAIN)

depend: $(SRCS)
	makedepend $(INCLUDES) $^


