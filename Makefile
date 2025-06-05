all: build/cylock

build/cylock: src/ui.c src/libspoof.c src/libspoof.h src/utils.c src/utils.h
	gcc src/ui.c src/libspoof.c src/utils.c -o build/cylock `pkg-config --cflags --libs gtk+-3.0` -lssl -lcrypto

.PHONY:debug
debug:src/ui.c src/libspoof.c src/libspoof.h src/utils.c src/utils.h
	gcc src/ui.c src/libspoof.c src/utils.c -o build/cylock `pkg-config --cflags --libs gtk+-3.0` -lssl -lcrypto -g

.PHONY: run
run: build/cylock
	sudo ./build/cylock

.PHONY: debug-run
debug-run: build/cylock
	sudo gdb ./build/cylock

.PHONY: clean
clean:
	rm ./build/*
