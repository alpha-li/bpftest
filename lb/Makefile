all: lb.o

lb.o: lb.c
	clang -O2 -g -target bpf -I../util -c lb.c -o lb.o

clean:
	rm -rf *.o