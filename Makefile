.PHONY: clean all

all:
	clang -O2 -lusb-1.0 usbtool.c -o usbtool

clean:
	rm -f usbtool
