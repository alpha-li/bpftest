all: bpf-lb

bpf-lb: bpf_lb.o

bpf_lb.o: bpf_lb.c
	clang -O2 -target bpf -I../util -c bpf_lb.c -o bpf_lb.o


clean:
	rm *.o -rf