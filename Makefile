OBJ = main.o rtp.o
exe = cmmb2rtp
CC = gcc -g
CCOPT = -Wall

$(exe):$(OBJ)
	$(CC) $(CCOPT) -D_FILE_OFFSET_BITS=64 -o $(exe) $(OBJ) -lpthread -lmp4v2

clean:
	rm -f *.o $(exe)
