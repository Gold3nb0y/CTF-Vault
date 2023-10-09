CFLAGS=-gdwarf-4 -Wall -Wextra -Wno-unused-parameter -Isrc

all: build build/db

build/db: src/db.c build/lex.yy.c build/parser.tab.c src/db.h
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) src/db.c build/lex.yy.c build/parser.tab.c $(LDLIBS)

build/parser.tab.c build/parser.tab.h: src/parser.y src/db.h
	bison -o build/parser.tab.c -d $<

build/lex.yy.c: src/scan.l src/db.h build/parser.tab.h
	flex --always-interactive -o $@ $<

build:
	mkdir -p build

.PHONY: clean
clean:
	rm -rf build
