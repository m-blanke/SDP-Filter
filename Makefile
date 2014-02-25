FILES = sdp-filter parsing string

CC = gcc
LD = ld
CFLAGS = -std=gnu11 -Wall
LIBRARY = -lnetfilter_queue
debug: CFLAGS += -DDEBUG -g

all: $(FILES)
	@$(CC) $(addsuffix .o, $(FILES)) $(LIBRARY)  -o SDP-Filter

%: %.c
	@$(CC) $(CFLAGS) $(LIBRARY) $^ -c 
	

clean:
	@rm -f $(addsuffix .o,$(FILES)) SDP-Filter

debug: all


.PHONY: clean



