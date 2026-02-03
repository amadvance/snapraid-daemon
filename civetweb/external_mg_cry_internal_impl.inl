extern void civetweb_log_message(const struct mg_connection *conn, const char* str);

static void mg_cry_internal_impl(const struct mg_connection *conn,
                                 const char *func,
                                 unsigned line,
                                 const char *fmt,
                                 va_list ap)
{
	char buf[1024];

	(void)func;
	(void)line;

	vsnprintf_impl(buf, sizeof(buf), fmt, ap);

	buf[sizeof(buf) - 1] = 0;

	civetweb_log_message(conn, buf);
}
