bin_PROGRAMS = snapraidd

# flags
AM_CPPFLAGS = -DSYSCONFDIR="\"${sysconfdir}\"" -DDATADIR="\"${datadir}\""

snapraidd_CPPFLAGS = -DSYSCONFDIR="\"${sysconfdir}\"" -DDATADIR="\"${datadir}\"" \
	-DNO_SSL -DNO_SSL_DL -DNO_CGI -DNO_FILES -DNO_FILESYSTEMS -DNO_THREAD_NAME \
	-DMG_EXTERNAL_FUNCTION_mg_cry_internal_impl \
	-DMG_EXTERNAL_FUNCTION_log_access

snapraidd_CFLAGS = $(ZLIB_CFLAGS) $(ZSTD_CFLAGS)
snapraidd_LDADD = $(ZLIB_LIBS) $(ZSTD_LIBS)

# init system
if INSTALL_SYSTEMD
systemdsystemunitdir = @systemdsystemunitdir@
systemdsystemunit_DATA = snapraidd.service
endif

if INSTALL_BSD_INIT
rcdir = /etc/rc.d
rc_SCRIPTS = rc.snapraidd
endif

# Web UI
if HAVE_ZIP
COMMANDER_DIST = \
	index.html \
	css/style.css \
	js/api.js \
	js/app.js \
	js/ui.js \
	js/utils.js

pkgdata_DATA = commander.zip

commander.zip: $(patsubst %, $(srcdir)/commander/%, $(COMMANDER_DIST))
	cd $(srcdir)/commander && $(ZIP) -r -q $(abs_builddir)/commander.zip $(COMMANDER_DIST)
endif

snapraidd_SOURCES = \
	daemon/daemon.c \
	daemon/state.c \
	daemon/runner.c \
	daemon/parser.c \
	daemon/scheduler.c \
	daemon/support.c \
	daemon/rest.c \
	daemon/web.c \
	daemon/zip.c \
	daemon/conf.c \
	daemon/log.c \
	daemon/elem.c \
	daemon/report.c \
	daemon/unix.c \
	civetweb/civetweb.c \
	tommyds/tommy.c

noinst_HEADERS = \
	tommyds/tommychain.h \
	tommyds/tommyhash.h \
	tommyds/tommylist.h \
	tommyds/tommytypes.h \
	tommyds/tommyhash.c \
	tommyds/tommylist.c \
	jsmn/jsmn.h \
	civetweb/civetweb.h \
	civetweb/external_log_access.inl \
	civetweb/external_mg_cry_internal_impl.inl \
	civetweb/handle_form.inl \
	civetweb/match.inl \
	civetweb/md5.inl \
	civetweb/response.inl \
	civetweb/sort.inl \
	daemon/portable.h \
	daemon/daemon.h \
	daemon/state.h \
	daemon/runner.h \
	daemon/parser.h \
	daemon/scheduler.h \
	daemon/support.h \
	daemon/rest.h \
	daemon/web.h \
	daemon/zip.h \
	daemon/conf.h \
	daemon/log.h \
	daemon/elem.h \
	daemon/report.h \
	snapraidd.yaml \
	snapraidd.service.in \
	rc.snapraidd.in \
	snapraidd.conf.example \
	commander/index.html \
	commander/css/style.css \
	commander/js/ui.js \
	commander/js/api.js \
	commander/js/app.js \
	commander/js/utils.js \
	commander/metadata.json

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
	README COPYING HISTORY INSTALL \
	$(LIST_D) \
	$(LIST_MAN) \
	$(LIST_TXT) \
	acinclude.m4 \
	tommyds/LICENSE \
	jsmn/LICENSE \
	civetweb/LICENSE.md \
	snapraidd.service.in rc.snapraidd.in

man1_MANS = doc/snapraidd.1

clean-local:
	rm -f valgrind.log callgrind.log cachegrind.log
	rm -f commander.zip

maintainer-clean-local:
	rm -f $(LIST_MAN)
	rm -f $(LIST_TXT)
	rm -f $(LIST_HH)

install-data-hook:
# Install localized manpages
	for lang in $(LANG_CODES); do \
		mkdir -p $(DESTDIR)$(mandir)/$$lang/man1; \
		$(INSTALL_DATA) $(srcdir)/doc/snapraidd-$$lang.1 $(DESTDIR)$(mandir)/$$lang/man1/snapraidd.1; \
	done
	@echo ""
	@echo "=================================================================="
	@echo " $(PACKAGE_NAME) installation complete!"
	@echo "=================================================================="
# Install service/rc.d
if INSTALL_SYSTEMD
	@echo ""
	@echo " Detected systemd. To start the daemon now and at boot:"
	@echo "   sudo systemctl daemon-reload"
	@echo "   sudo systemctl enable --now $(PACKAGE_NAME)"
	@echo ""
	@echo " To check status:"
	@echo "   systemctl status $(PACKAGE_NAME)"
	@echo "=================================================================="
	@echo ""
endif
if INSTALL_BSD_INIT
	@echo ""
	@echo " Detected BSD-style init. To enable the daemon:"
	@echo "   sudo chmod +x /etc/rc.d/rc.$(PACKAGE_NAME)"
	@echo ""
	@echo " To start it now, add this to /etc/rc.d/rc.local:"
	@echo "   if [ -x /etc/rc.d/rc.$(PACKAGE_NAME) ]; then"
	@echo "     /etc/rc.d/rc.$(PACKAGE_NAME) start"
	@echo "   fi"
	@echo ""
	@echo " Or run manually: sudo /etc/rc.d/rc.$(PACKAGE_NAME) start"
	@echo "=================================================================="
	@echo ""
endif

uninstall-hook:
# Uninstall localized manpages
	for lang in $(LANG_CODES); do \
		rm -f $(DESTDIR)$(mandir)/$$lang/man1/snapraidd.1; \
		rmdir --ignore-fail-on-non-empty $(DESTDIR)$(mandir)/$$lang/man1 2>/dev/null || true; \
		rmdir --ignore-fail-on-non-empty $(DESTDIR)$(mandir)/$$lang 2>/dev/null || true; \
	done
# Uninstall service/rc.d
if INSTALL_SYSTEMD
	@echo ""
	@echo "=================================================================="
	@echo "Stopping and disabling systemd service..."
	systemctl disable --now $(PACKAGE_NAME) 2>/dev/null || true
	systemctl daemon-reload 2>/dev/null || true
	@echo "Cleaning up runtime files..."
	rm -f /run/$(PACKAGE_NAME).pid
endif
	@echo ""
	@echo "=================================================================="
	@echo " $(PACKAGE_NAME) has been uninstalled."
	@echo " Note: Configuration files and logs were preserved."
	@echo "=================================================================="
	@echo ""

# Basic dependencies
DAEMON_PREFIX=daemon/snapraidd-
$(DAEMON_PREFIX)state.$(OBJEXT): $(srcdir)/daemon/state.h
$(DAEMON_PREFIX)conf.$(OBJEXT): $(srcdir)/daemon/conf.h $(srcdir)/daemon/state.h
$(DAEMON_PREFIX)daemon.$(OBJEXT): $(srcdir)/daemon/daemon.h $(srcdir)/daemon/state.h
$(DAEMON_PREFIX)elem.$(OBJEXT): $(srcdir)/daemon/elem.h $(srcdir)/daemon/state.h
$(DAEMON_PREFIX)log.$(OBJEXT): $(srcdir)/daemon/log.h $(srcdir)/daemon/state.h
$(DAEMON_PREFIX)parser.$(OBJEXT): $(srcdir)/daemon/parser.h $(srcdir)/daemon/state.h
$(DAEMON_PREFIX)report.$(OBJEXT): $(srcdir)/daemon/report.h $(srcdir)/daemon/state.h
$(DAEMON_PREFIX)rest.$(OBJEXT): $(srcdir)/daemon/rest.h $(srcdir)/daemon/state.h
$(DAEMON_PREFIX)web.$(OBJEXT): $(srcdir)/daemon/rest.h $(srcdir)/daemon/web.h
$(DAEMON_PREFIX)runner.$(OBJEXT): $(srcdir)/daemon/runner.h $(srcdir)/daemon/state.h
$(DAEMON_PREFIX)scheduler.$(OBJEXT):$(srcdir)/daemon/scheduler.h $(srcdir)/daemon/state.h
$(DAEMON_PREFIX)support.$(OBJEXT): $(srcdir)/daemon/support.h $(srcdir)/daemon/state.h

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

MANUAL=./snapraidd -f -N

valgrind:
	valgrind \
		--tool=memcheck \
		--suppressions=valgrind.supp \
		--track-origins=yes \
		--read-var-info=yes \
		--leak-check=full \
		-v $(MANUAL) \
		2> valgrind.log
		tail valgrind.log

helgrind:
	valgrind \
		--tool=helgrind \
		--fair-sched=try \
		--suppressions=valgrind.supp \
		--gen-suppressions=all \
		-v $(MANUAL) \
		2> helgrind.log
		tail helgrind.log


# Web distribution

web: $(LIST_HH)
