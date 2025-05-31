cylock.o: libspoof.c gui.c libspoof.h
	gcc gui.c libspoof.c -o cylock.o `pkg-config --cflags --libs gtk+-3.0` -Wall -O2

clean:
	rm *.o

