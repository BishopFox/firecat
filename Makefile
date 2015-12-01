CC=gcc
#CC=clang

make:
	$(CC) -Wall -Werror -ansi -pedantic -g firecat.c -o firecat
prod:
	$(CC) -Wall -Werror -ansi -pedantic -Os firecat.c -o firecat
clean:
	rm -f firecat
