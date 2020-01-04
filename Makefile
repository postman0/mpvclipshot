
clipshot.so: main.c
	gcc --std=c11 -Wall -Wextra -O2 -g -o clipshot.so main.c -Iinclude -shared -fPIC
