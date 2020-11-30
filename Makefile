GOPATH?=$(USER)/go
BINDIR?=$(GOPATH)/bin
MANDIR?=/usr/local/man

$(BINDIR)/shh:
	go get -u github.com/thankful-ai/shh

install: $(BINDIR)/shh
	mkdir -m755 -p $(MANDIR)/man1
	cp man/man1/shh.1 $(MANDIR)/man1/
.PHONY: install

uninstall:
	rm -f $(BINDIR)/shh
	rm -f $(MANDIR)/man1/shh.1
.PHONY: uninstall
