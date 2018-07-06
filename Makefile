BIN = memhack

.PHONY: build clean

build: $(BIN).c
	gcc -std=gnu99 -O1 -Wall -ggdb -o $(BIN) $(BIN).c

clean:
	rm $(BIN)