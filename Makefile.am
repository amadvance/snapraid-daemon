bin_PROGRAMS = snapraidd

# Avoid the installation of BSD/SystemD script with make distcheck
AM_DISTCHECK_CONFIGURE_FLAGS = --with-init-type=none

snapraidd_CPPFLAGS = -DSYSCONFDIR="\"${sysconfdir}\"" -DDATADIR="\"${datadir}\"" \
	-DUSE_IPV6 -DNO_SSL -DNO_SSL_DL -DNO_CGI -DNO_FILES -DNO_FILESYSTEMS -DNO_THREAD_NAME \
	-DMG_EXTERNAL_FUNCTION_mg_cry_internal_impl \
	-DMG_EXTERNAL_FUNCTION_log_access

snapraidd_CFLAGS = $(ZLIB_CFLAGS) $(ZSTD_CFLAGS)
snapraidd_LDADD = $(ZLIB_LIBS) $(ZSTD_LIBS)

# init system
if INSTALL_SYSTEMD
systemdsystemunitdir = @SERVICEDIR@
systemdsystemunit_DATA = snapraidd.service
endif

if INSTALL_BSD_INIT
rcdir = @RCDIR@
rc_SCRIPTS = rc.snapraidd
endif

noinst_DATA = rc.snapraidd snapraidd.service
CLEANFILES = rc.snapraidd snapraidd.service

# Web UI
COMMANDER_DIST = \
	index.html \
	site.webmanifest \
	image/favicon-16x16.png \
	image/android-chrome-512x512.png \
	image/apple-touch-icon.png \
	image/android-chrome-192x192.png \
	image/favicon-32x32.png \
	favicon.ico \
	css/style.css \
	js/api.js \
	js/app.js \
	js/ui.js \
	js/utils.js

data_DATA = commander.zip

commander.zip: $(patsubst %, $(srcdir)/commander/%, $(COMMANDER_DIST))
	cd $(srcdir)/commander && $(ZIP) -0 -r -q $(abs_builddir)/commander.zip $(COMMANDER_DIST)

# Windows
if HOST_WINDOWS
snapraidd_LDADD += resource_res.o messages_res.o -ladvapi32 -luserenv

messages.h messages.rc: daemon/messages.mc
	$(WINDMC) $<

messages_res.o: messages.rc
	$(WINDRES) $< -o $@

resource_res.o: daemon/resource.rc daemon/resource.manifest
	$(WINDRES) --include-dir=. --include-dir=$(srcdir) $< -o $@

daemon/snapraidd-mingwapp.$(OBJEXT): messages.h

CLEANFILES += resource_res.o messages.h messages.rc messages_res.o MSG00401.bin
endif

snapraidd_SOURCES = \
	daemon/daemon.c \
	daemon/state.c \
	daemon/runner.c \
	daemon/parser.c \
	daemon/scheduler.c \
	daemon/version.c \
	daemon/support.c \
	daemon/rest.c \
	daemon/web.c \
	daemon/zip.c \
	daemon/conf.c \
	daemon/log.c \
	daemon/elem.c \
	daemon/report.c \
	daemon/notify.c \
	daemon/smart.c \
	daemon/unix.c \
	daemon/unixapp.c \
	daemon/mingw.c \
	daemon/mingwapp.c \
	civetweb/civetweb.c \
	tommyds/tommy.c \
	monocypher/monocypher.c

noinst_HEADERS = \
	monocypher/monocypher.h \
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
	daemon/unix.h \
	daemon/mingw.h \
	daemon/os.h \
	daemon/app.h \
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
	daemon/notify.h \
	daemon/smart.h \
	daemon/version.h

# Add the .version file in the distribution
dist-hook:
	$(srcdir)/autover.sh > $(distdir)/.version

LANG_CODES =

LIST_D = doc/snapraidd.d $(patsubst %, doc/snapraidd-%.d, $(LANG_CODES))

LIST_MAN = doc/snapraidd.1 $(patsubst %, doc/snapraidd-%.1, $(LANG_CODES))

LIST_TXT = doc/snapraidd.txt $(patsubst %, doc/snapraidd-%.txt, $(LANG_CODES))

LIST_XML = doc/snapraidd.xml $(patsubst %, doc/snapraidd-%.xml, $(LANG_CODES))

EXTRA_DIST = \
	autogen.sh autover.sh \
	README HISTORY INSTALL AUTHORS BLUEBOX \
	COPYING LICENSES/GPL-3.0 LICENSES/BSD-2-Clause LICENSES/MIT \
	$(LIST_D) \
	$(LIST_MAN) \
	$(LIST_TXT) \
	m4/ax_pthread.m4 \
	m4/m4_ax_check_compile_flag.m4 \
	jsmn/LICENSE \
	civetweb/LICENSE.md \
	daemon/messages.mc \
	daemon/resource.rc \
	daemon/resource.manifest \
	configure.windows-x64 \
	snapraidd.service.in rc.snapraidd.in \
	makeslackware.sh.in \
	makeslackdist.sh.in \
	pkg/snapraid-daemon.SlackBuild.in \
	pkg/snapraid-daemon.info.in \
	pkg/slack-desc \
	pkg/doinst.sh \
	makedeb.sh.in \
	pkg/control.in \
	pkg/conffiles \
	pkg/postinst \
	pkg/prerm \
	pkg/postrm \
	makerpm.sh.in \
	pkg/snapraid-daemon.spec.in \
	makearch.sh.in \
	makearchdist.sh.in \
	pkg/.INSTALL \
	pkg/.PKGINFO.in \
	pkg/PKGBUILD.in \
	pkg/.SRCINFO.in \
	makensis.sh.in \
	pkg/snapraid-daemon.nsis.in \
	pkg/snapraid-daemon.ico \
	snapraidd.yaml \
	snapraidd.service.in \
	rc.snapraidd.in \
	snapraidd.conf.example \
	commander/index.html \
	commander/site.webmanifest \
	commander/image/favicon-16x16.png \
	commander/image/android-chrome-512x512.png \
	commander/image/apple-touch-icon.png \
	commander/image/android-chrome-192x192.png \
	commander/image/favicon-32x32.png \
	commander/favicon.ico \
	commander/css/style.css \
	commander/js/ui.js \
	commander/js/api.js \
	commander/js/app.js \
	commander/js/utils.js

man1_MANS = doc/snapraidd.1

# Allow leftover .conf 
distuninstallcheck_listfiles = \
	find . -type f -print | grep -v 'etc/snapraidd.conf'

clean-local:
	rm -f valgrind.log callgrind.log cachegrind.log
	rm -f commander.zip
	rm -f makeslackware.sh makeslackdist.sh pkg/snapraid-daemon.SlackBuild pkg/snapraid-daemon.info makedeb.sh pkg/control makerpm.sh pkg/spec

maintainer-clean-local:
	rm -f $(LIST_MAN)
	rm -f $(LIST_TXT)
	rm -f $(LIST_XML)
	rm -f snapraid-daemon-*.rpm snapraid-daemon_*.deb snapraid-daemon-*.txz snapraid-daemon-*.exe snapraid-daemon-*.tar.gz snapraid-daemon-*.tar.zst
	rm -f snapraid-daemon.src.tar.gz snapraid-daemon.tar.gz

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
	@echo ""
	@if test -z "$(DESTDIR)"; then \
		echo " Configuration:"; \
		if test -f $(sysconfdir)/snapraidd.conf ; then \
			echo "  Existing configuration found at $(sysconfdir)/snapraidd.conf"; \
			echo "  Your settings have been preserved."; \
		elif test -f /etc/snapraidd.conf ; then \
			echo "  Existing configuration found at /etc/snapraidd.conf"; \
			echo "  Your settings have been preserved."; \
		else \
			echo "  No configuration found. Installing default to:"; \
			echo "  $(sysconfdir)/snapraidd.conf"; \
			$(INSTALL) -D -m 600 $(srcdir)/snapraidd.conf.example $(sysconfdir)/snapraidd.conf; \
		fi; \
	else \
		echo "DESTDIR is set ($(DESTDIR)), installing example only"; \
		echo "Real config should be created/managed by packaging script."; \
	fi
	@echo ""
	@echo "=================================================================="
# Install service/rc.d
if INSTALL_SYSTEMD
	@echo ""
	@echo " Detected systemd. To start the daemon now and at boot:"
	@echo "   sudo systemctl daemon-reload"
	@echo "   sudo systemctl enable --now snapraidd"
	@echo ""
	@echo " To check status:"
	@echo "   systemctl status snapraidd"
	@echo ""
	@echo " Once started, you can access the dashboard at:"
	@echo "    http://localhost:7627"
	@echo "=================================================================="
	@echo ""
endif
if INSTALL_BSD_INIT
	@echo ""
	@echo " Detected BSD-style init. To enable the daemon:"
	@echo "   sudo chmod +x $(rcdir)/rc.snapraidd"
	@echo ""
	@echo " To start it at boot, add this to /etc/rc.d/rc.local:"
	@echo "   if [ -x $(rcdir)/rc.snapraidd ]; then"
	@echo "     $(rcdir)/rc.snapraidd start"
	@echo "   fi"
	@echo ""
	@echo " Or run manually: sudo $(rcdir)/rc.snapraidd start"
	@echo ""
	@echo " Once started, you can access the dashboard at:"
	@echo "    http://localhost:7627"
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
	systemctl disable --now snapraidd 2>/dev/null || true
	systemctl daemon-reload 2>/dev/null || true
	@echo "Cleaning up runtime files..."
	rm -f /run/snapraidd.pid
endif
if INSTALL_BSD_INIT
	@echo ""
	@echo "=================================================================="
	@if test -f "$(rcdir)/rc.snapraidd"; then \
		echo " Stopping BSD-style service..."; \
		"$(rcdir)/rc.snapraidd" stop 2>/dev/null || true; \
	else \
		echo " Service script not found at $(rcdir)/rc.snapraidd, skipping stop."; \
	fi
	@echo ""
	@echo " Note: If you added snapraidd to /etc/rc.d/rc.local, please"
	@echo " remove those lines manually to prevent boot errors."
endif
	@echo ""
	@echo "=================================================================="
	@echo " $(PACKAGE_NAME) has been uninstalled."
	@echo " Note: Configuration files and logs were preserved."
	@echo "=================================================================="
	@echo ""

# Basic dependencies
DAEMON_PREFIX = daemon/snapraidd-
DAEMON_INCLUDES = \
	config.h \
	$(srcdir)/daemon/conf.h \
	$(srcdir)/daemon/app.h \
	$(srcdir)/daemon/elem.h \
	$(srcdir)/daemon/log.h \
	$(srcdir)/daemon/mingw.h \
	$(srcdir)/daemon/notify.h \
	$(srcdir)/daemon/os.h \
	$(srcdir)/daemon/parser.h \
	$(srcdir)/daemon/portable.h \
	$(srcdir)/daemon/report.h \
	$(srcdir)/daemon/rest.h \
	$(srcdir)/daemon/runner.h \
	$(srcdir)/daemon/scheduler.h \
	$(srcdir)/daemon/smart.h \
	$(srcdir)/daemon/state.h \
	$(srcdir)/daemon/support.h \
	$(srcdir)/daemon/unix.h \
	$(srcdir)/daemon/version.h \
	$(srcdir)/daemon/web.h \
	$(srcdir)/daemon/zip.h
$(DAEMON_PREFIX)conf.$(OBJEXT): $(DAEMON_INCLUDES)
$(DAEMON_PREFIX)daemon.$(OBJEXT): $(DAEMON_INCLUDES)
$(DAEMON_PREFIX)elem.$(OBJEXT): $(DAEMON_INCLUDES)
$(DAEMON_PREFIX)log.$(OBJEXT): $(DAEMON_INCLUDES)
$(DAEMON_PREFIX)mingw.$(OBJEXT): $(DAEMON_INCLUDES)
$(DAEMON_PREFIX)notify.$(OBJEXT): $(DAEMON_INCLUDES)
$(DAEMON_PREFIX)parser.$(OBJEXT): $(DAEMON_INCLUDES)
$(DAEMON_PREFIX)report.$(OBJEXT): $(DAEMON_INCLUDES)
$(DAEMON_PREFIX)rest.$(OBJEXT): $(DAEMON_INCLUDES)
$(DAEMON_PREFIX)runner.$(OBJEXT): $(DAEMON_INCLUDES)
$(DAEMON_PREFIX)scheduler.$(OBJEXT): $(DAEMON_INCLUDES)
$(DAEMON_PREFIX)version.$(OBJEXT): $(DAEMON_INCLUDES)
$(DAEMON_PREFIX)smart.$(OBJEXT): $(DAEMON_INCLUDES)
$(DAEMON_PREFIX)state.$(OBJEXT): $(DAEMON_INCLUDES)
$(DAEMON_PREFIX)support.$(OBJEXT): $(DAEMON_INCLUDES)
$(DAEMON_PREFIX)unix.$(OBJEXT): $(DAEMON_INCLUDES)
$(DAEMON_PREFIX)web.$(OBJEXT): $(DAEMON_INCLUDES)
$(DAEMON_PREFIX)zip.$(OBJEXT): $(DAEMON_INCLUDES)

# Rules for scripts
snapraidd.service: snapraidd.service.in
	sed \
		-e 's|@bindir[@]|$(bindir)|g' \
		-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
		< $< > $@-t && mv $@-t $@

rc.snapraidd: rc.snapraidd.in
	$(AM_V_GEN)sed \
		-e 's|@bindir[@]|$(bindir)|g' \
		-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
		< $< > $@-t && mv $@-t $@


# Rules for documentation
if HAVE_ADVD2
%.1 : %.d
	advd2 man < $(srcdir)/$< > $@

%.txt : %.d
	advd2 txt < $(srcdir)/$< | todos > $@

%.html : %.d
	advd2 html < $(srcdir)/$< > $@

%.xml : %.d
	advd2 xml < $(srcdir)/$< > $@
endif

MANUAL=./snapraidd -f -N

run:
	$(MANUAL)

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

heaptrack:
	/usr/local/heaptrack/bin/heaptrack $(MANUAL)

perf:
	@trap 'perf report; exit 1' INT; perf record -g -- $(MANUAL)

perfstat:
	perf stat -d -- $(MANUAL)
	
perfmem:
	@trap 'perf mem report; exit 1' INT; perf mem record -- $(MANUAL)

# Web distribution

web: $(LIST_XML)
