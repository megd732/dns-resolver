TARGETS=hw3

hw3: hw3.c
	gcc -g -o hw3 hw3.c

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

