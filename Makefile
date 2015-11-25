dev:
	gcc -Wall -Werror -ansi -pedantic -g firecat.c -o dev_firecat

clean:
	rm -f firecat dev_firecat
prod:
	gcc -Wall -Werror -ansi -pedantic -Os firecat.c -o firecat
