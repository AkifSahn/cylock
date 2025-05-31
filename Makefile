chat_gui: libspoof.c gui.c libspoof.h
	gcc gui.c libspoof.c -o chat_gui.o `pkg-config --cflags --libs gtk+-3.0` -Wall -O2

clean:
	rm *.o

