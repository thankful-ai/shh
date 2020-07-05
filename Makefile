BINDIR?=/usr/local/bin
MANDIR?=/usr/local/man

shh:
	go build .

install: shh
	mkdir -m755 -p $(BINDIR) $(MANDIR)/man1
	cp man/man1/shh.1 $(MANDIR)/man1/
	mv shh /usr/local/bin/shh
.PHONY: install

clean:
	rm -f shh
.PHONY: clean

uninstall:
	rm -f $(BINDIR)/shh
	rm -f $(MANDIR)/man1/shh.1
.PHONY: uninstall
