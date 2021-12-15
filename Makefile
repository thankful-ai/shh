GOPATH?=$(USER)/go
BINDIR?=$(GOPATH)/bin
MANDIR?=/usr/local/man

install:
	go install .
.PHONY: install

uninstall:
	rm -f $(BINDIR)/shh
.PHONY: uninstall

install-docs:
	mkdir -m755 -p $(MANDIR)/man1
	cp man/man1/shh.1 $(MANDIR)/man1/
.PHONY: install-docs

uninstall-docs:
	rm -f $(MANDIR)/man1/shh.1
.PHONY: uninstall-docs
