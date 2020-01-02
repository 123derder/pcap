all:
	gcc hw3.c -lpcap
clean:
	rm a.out
run:
	sudo ./a.out
