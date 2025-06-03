cylock: src/ui.c src/libspoof.c src/libspoof.h src/utils.c src/utils.h
	gcc src/ui.c src/libspoof.c src/utils.c -o build/cylock `pkg-config --cflags --libs gtk+-3.0` -lssl -lcrypto

debug:src/ui.c src/libspoof.c src/libspoof.h src/utils.c src/utils.h
	gcc src/ui.c src/libspoof.c src/utils.c -o build/cylock `pkg-config --cflags --libs gtk+-3.0` -lssl -lcrypto -g

run: cylock
	sudo ./build/cylock

debug-run: debug
	sudo gdb ./build/cylock

clean:
	rm ./build/* *.o
