ALL   = plparse
FLAGS = -Wall -O3 -fblocks -framework CoreFoundation -framework IOKit -framework Security

.PHONY: all clean

all: $(ALL)

plparse: src/*.c
	$(CC) -o $@ $^ $(FLAGS)

clean:
	rm -f $(ALL)
