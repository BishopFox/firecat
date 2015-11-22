all:
	gcc -Wall -Werror -ansi -pedantic firecat.c -o firecat

clean:
	rm -f firecat
