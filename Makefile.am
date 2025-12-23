bin_PROGRAMS = snapraidd

AM_CPPFLAGS = -DSYSCONFDIR="\"${sysconfdir}\""

snapraidd_CPPFLAGS = -DSYSCONFDIR="\"${sysconfdir}\"" \
	-DNO_SSL -DNO_SSL_DL -DNO_CGI -DNO_FILES -DNO_FILESYSTEMS -DNO_THREAD_NAME \
	-DMG_EXTERNAL_FUNCTION_mg_cry_internal_impl \
	-DMG_EXTERNAL_FUNCTION_log_access

snapraidd_SOURCES = \
	daemon/daemon.c \
	daemon/runner.c \
	daemon/support.c \
	civetweb/civetweb.c

noinst_HEADERS = \
	tommyds/tommychain.h \
	tommyds/tommyhash.h \
	tommyds/tommylist.h \
	tommyds/tommytypes.h \
	tommyds/tommyhash.c \
	tommyds/tommylist.c \
	civetweb/civetweb.h \
	civetweb/external_log_access.inl \
	civetweb/external_mg_cry_internal_impl.inl \
	civetweb/handle_form.inl \
	civetweb/match.inl \
	civetweb/md5.inl \
	civetweb/response.inl \
	civetweb/sort.inl \
	daemon/portable.h \
	daemon/state.h \
	daemon/support.h

# Add the .version file in the distribution
dist-hook:
	$(srcdir)/autover.sh > $(distdir)/.version

LANG_CODES =

LIST_D = doc/snapraidd.d $(patsubst %, doc/snapraidd-%.d, $(LANG_CODES))

LIST_MAN = doc/snapraidd.1 $(patsubst %, doc/snapraidd-%.1, $(LANG_CODES))

LIST_TXT = doc/snapraidd.txt $(patsubst %, doc/snapraidd-%.txt, $(LANG_CODES))

LIST_HH = doc/snapraidd.hh $(patsubst %, doc/snapraidd-%.hh, $(LANG_CODES))

EXTRA_DIST = \
	autogen.sh autover.sh \
	README COPYING \
	$(LIST_D) \
	$(LIST_MAN) \
	$(LIST_TXT) \
	acinclude.m4 \
	tommyds/LICENSE

man1_MANS = doc/snapraidd.1

clean-local:
	rm -f valgrind.log callgrind.log cachegrind.log

maintainer-clean-local:
	rm -f $(LIST_MAN)
	rm -f $(LIST_TXT)
	rm -f $(LIST_HH)

# Install localized manpages
install-data-hook:
	for lang in $(LANG_CODES); do \
		mkdir -p $(DESTDIR)$(mandir)/$$lang/man1; \
		$(INSTALL_DATA) $(srcdir)/doc/snapraidd-$$lang.1 $(DESTDIR)$(mandir)/$$lang/man1/snapraidd.1; \
	done

# Uninstall localized manpages
uninstall-hook:
	for lang in $(LANG_CODES); do \
		rm -f $(DESTDIR)$(mandir)/$$lang/man1/snapraidd.1; \
		rmdir --ignore-fail-on-non-empty $(DESTDIR)$(mandir)/$$lang/man1 2>/dev/null || true; \
		rmdir --ignore-fail-on-non-empty $(DESTDIR)$(mandir)/$$lang 2>/dev/null || true; \
	done

# Rules for documentation
if HAVE_ADVD2
%.1 : %.d
	advd2 man < $(srcdir)/$< > $@

%.txt : %.d
	advd2 txt < $(srcdir)/$< | todos > $@

%.html : %.d
	advd2 html < $(srcdir)/$< > $@

%.hh : %.d
	advd2 frame < $(srcdir)/$< > $@
endif

# Web distribution

web: $(LIST_HH)
