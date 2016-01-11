NAME=firecat
CC=gcc
#CC=clang

ifneq ($(shell which strip 2>/dev/null),)
STRIP = strip
else
STRIP = @echo "ERROR: 'strip' command not found but is required to build prod" && exit 1
endif


# With -Os, gcc makes a slightly smaller binary (18K vs 19K)
# with --strip-all binary is 15k

make:
	$(CC) -Wall -Werror -ansi -pedantic -ggdb3 $(NAME).c -o $(NAME)
prod:
	$(CC) -Os $(NAME).c -o $(NAME)
	$(STRIP) --strip-all $(NAME)

# from http://www.bishopfox.com/resources/tools/other-free-tools/firecat/
windows:
	gcc -lwsock32 -Os $(NAME).c -o $(NAME).exe
clean:
	rm -f $(NAME)
