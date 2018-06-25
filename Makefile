# Do *NOT* modify the existing build rules.
# You may add your own rules, e.g., "make run" or "make test".

LAB = memhack

.PHONY: build

build: $(LAB).c
	gcc -std=gnu99 -O1 -Wall -ggdb -o $(LAB) $(LAB).c