CC := gcc
FLAG ?= flag{thats_a_pretty_huge_decrement}

dist: out.tar.gz main flag.txt
	mv $< handout_$(shell sha256sum $< | awk '{print $$1}').tar.gz

main: main.c elk/elk.c
	$(CC) -o $@ -O2 $^ -Ielk/

handout/main.c: main.c
	clang-format -style=Google < $^ > $@
	! grep -q "$(FLAG)" $@

handout/main: main
	cp $^ $@
	! grep -q "$(FLAG)" handout/flag.txt

handout/flag.txt:
	echo 'flag{fake}' > $@

flag.txt:
	echo "$(FLAG)" > $@

out.tar.gz: handout/main handout/main.c elk/ handout/Makefile handout/flag.txt
	tar -czf $@ --transform "s;handout/;;" $^

clean:
	rm -f handout/main.c main flag.txt handout_*.tar.gz

.PHONY: dist clean
