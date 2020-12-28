
all: test

test: test.c
	gcc -mindirect-branch=thunk test.c -o test
