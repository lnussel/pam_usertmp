XGETTEXT = xgettext
MSGMERGE = msgmerge
NAME = pam_usertmp
top_srcdir = ..
DESTDIR =
prefix = /usr
localedir = $(prefix)/share/locale
mkinstalldirs = mkdir -p
INSTALL_DATA = install -m644

POTFILES =			\
	pam_usertmp.c

POFILES = \
	

MOFILES= $(POFILES:.po=.mo)

all: $(MOFILES)

%.mo: %.po
	msgfmt -v -o $@ $<

$(NAME).pot: $(POTFILES:%=$(top_srcdir)/%)
	$(XGETTEXT) --language=C --keyword=_ -o $@ $^

update-po: $(NAME).pot
	for i in $(POFILES); do \
		echo -n "$$i: "; \
		$(MSGMERGE) -v -U $$i $(NAME).pot; \
	done

install:
	@for i in $(MOFILES:.mo=); do \
		$(mkinstalldirs) $(DESTDIR)$(localedir)/$$i/LC_MESSAGES; \
		$(INSTALL_DATA) $$i.mo $(DESTDIR)$(localedir)/$$i/LC_MESSAGES/$(NAME).mo; \
	done

uninstall:
	@for i in $(MOFILES:.mo=); do \
		rm -f $(DESTDIR)$(localedir)/$$i/LC_MESSAGES/$(NAME).mo; \
	done

EXTRA_DIST = $(POFILES)

DISTCLEANFILES = $(MOFILES)
