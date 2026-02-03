extern void civetweb_log_access(const struct mg_connection *conn, int status_code, int num_bytes_sent);

static void log_access(const struct mg_connection* conn)
{
	civetweb_log_access(conn, conn->status_code, conn->num_bytes_sent);
}
