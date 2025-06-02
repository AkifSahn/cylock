cylock.o: src/ui.c src/libspoof.c src/libspoof.h src/utils.c src/utils.h
	gcc src/ui.c src/libspoof.c src/utils.c -o cylock.o `pkg-config --cflags --libs gtk+-3.0` # -Wall -O2

debug:src/ui.c src/libspoof.c src/libspoof.h src/utils.c src/utils.h
	gcc src/ui.c src/libspoof.c src/utils.c -o cylock.o `pkg-config --cflags --libs gtk+-3.0` -g # -Wall -O2

clean:
	rm *.o

