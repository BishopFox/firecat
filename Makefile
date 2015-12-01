CC=gcc
#CC=clang

make:
	$(CC) -Wall -Werror -ansi -pedantic -g firecat.c -o firecat
prod:
	$(CC) -Os firecat.c -o firecat

# from http://www.bishopfox.com/resources/tools/other-free-tools/firecat/
windows:
	gcc -lwsock32 -Os firecat.c -o firecat.exe
clean:
	rm -f firecat
