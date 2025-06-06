all: compile

compile: build/cylock
debug: build/cylock.g

build/cylock: src/ui.c src/libspoof.c src/libspoof.h src/utils.c src/utils.h
	gcc src/ui.c src/libspoof.c src/utils.c -o build/cylock `pkg-config --cflags --libs gtk+-3.0` -lssl -lcrypto -lm

build/cylock.g:src/ui.c src/libspoof.c src/libspoof.h src/utils.c src/utils.h
	gcc src/ui.c src/libspoof.c src/utils.c -o build/cylock.g `pkg-config --cflags --libs gtk+-3.0` -lssl -lcrypto -lm -g

.PHONY: run
run: compile
	sudo ./build/cylock

.PHONY: debug-run
debug-run: debug
	sudo gdb ./build/cylock.g

.PHONY: clean
clean:
	rm ./build/*
