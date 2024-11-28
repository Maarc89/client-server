all:
	gcc servidor.c -std=c99 -ansi -pedantic -Wall -pthread -o servidor
	./servidor -c server.cfg -u controllers.dat
