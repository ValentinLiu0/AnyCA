/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <libwebsockets.h>

#include <anyca/osal/log.h>
#include <anyca/osal/memory.h>
#include <anyca/osal/signal.h>
#include <anyca/utils.h>

#include "http_server.h"
#include "ocsp_responder.h"

static volatile sig_atomic_t g_interrupted = 0;

static const char ocsp_uri_prefix[] = "/ocsp/";
static const char acme_uri_prefix[] = "/acme/";

#define OCSP_ENDPOINT_MAX_SIZE 128

/*
 * Per-client token buckets.  A global bucket lets one client exhaust the
 * allowance for everyone else, so each peer address keeps its own bucket.
 * The table is touched only by the lws thread; a full table evicts the least
 * recently used client.
 */
#define HTTP_RATE_CLIENT_SLOTS 256
#define HTTP_RATE_CLIENT_ADDRESS_SIZE 64

struct http_rate_client {
	char address[HTTP_RATE_CLIENT_ADDRESS_SIZE];
	double tokens;
	time_t last;
	time_t warned;
	uint64_t used;
};

static struct http_rate_client g_rate_clients[HTTP_RATE_CLIENT_SLOTS];
static uint64_t g_rate_clock;
static double g_rate_per_second;
static double g_rate_burst;

/* Find the bucket for address, creating or evicting one when necessary. */
static struct http_rate_client *_http_rate_client(const char *address)
{
	struct http_rate_client *free_slot = nullptr;
	struct http_rate_client *oldest = nullptr;
	struct http_rate_client *client;

	for (size_t i = 0; i < HTTP_RATE_CLIENT_SLOTS; i++) {
		client = &g_rate_clients[i];
		if (client->address[0] == '\0') {
			if (free_slot == nullptr)
				free_slot = client;
			continue;
		}
		if (strcmp(client->address, address) == 0)
			return client;
		if (oldest == nullptr || client->used < oldest->used)
			oldest = client;
	}

	client = free_slot != nullptr ? free_slot : oldest;
	snprintf(client->address, sizeof client->address, "%s", address);
	client->tokens = g_rate_burst;
	client->last = 0;
	client->warned = 0;
	client->used = 0;
	return client;
}

/*
 * Take one token from the bucket of the requesting client.  The bucket starts
 * full and refills at g_rate_per_second, capped at g_rate_burst.  A clock that
 * moves backwards simply does not refill the bucket.
 */
static bool _http_rate_allow(struct lws *wsi)
{
	char address[HTTP_RATE_CLIENT_ADDRESS_SIZE];
	struct http_rate_client *client;
	time_t now;
	double elapsed;

	if (lws_get_peer_simple(wsi, address, sizeof address) == nullptr
	    || address[0] == '\0')
		snprintf(address, sizeof address, "%s", "unknown");

	client = _http_rate_client(address);
	client->used = ++g_rate_clock;

	now = time(nullptr);
	if (now == (time_t) -1)
		return true;

	if (client->last == 0) {
		client->last = now;
		client->tokens = g_rate_burst;
	} else if (now != client->last) {
		elapsed = difftime(now, client->last);
		if (elapsed > 0) {
			client->tokens += g_rate_per_second * elapsed;
			if (client->tokens > g_rate_burst)
				client->tokens = g_rate_burst;
		}
		client->last = now;
	}

	if (client->tokens < 1.0) {
		if (client->warned != now) {
			client->warned = now;
			LOGW("HTTP request rate limit exceeded for %s", address);
		}
		return false;
	}

	client->tokens -= 1.0;
	return true;
}

struct http_session_data {
	int method;
	/* Endpoint of a POST OCSP request, handled when its body completes. */
	bool ocsp_post;
	bool body_too_large;
	/* Rate limiting may already have run in the connection filter. */
	bool rate_checked;
	bool rate_allowed;
	char ocsp_endpoint[OCSP_ENDPOINT_MAX_SIZE];
	size_t ocsp_endpoint_len;
	unsigned char data[LWS_PRE + MAX_RECEIVED_PAYLOAD_SIZE];
	int size;
};

static const char *_http_method_to_string(int method)
{
	switch (method) {
		case LWSHUMETH_GET:	return "GET";
		case LWSHUMETH_POST:	return "POST";
		case LWSHUMETH_OPTIONS:	return "OPTIONS";
		case LWSHUMETH_PUT:	return "PUT";
		case LWSHUMETH_PATCH:	return "PATCH";
		case LWSHUMETH_DELETE:	return "DELETE";
		case LWSHUMETH_CONNECT:	return "CONNECT";
		case LWSHUMETH_HEAD:	return "HEAD";
		default:		return "UNKNOWN";
	}
}

static inline int _http_return_code(struct lws *wsi, int code)
{
	int result = lws_return_http_status(wsi, code, nullptr);

	if (result != 0)
		return result;
	return lws_http_transaction_completed(wsi);
}

/*
 * Send 400 Bad Request with an empty body; libwebsockets would otherwise
 * attach its default HTML page.
 */
static int _http_bad_request(struct lws *wsi)
{
	unsigned char header[LWS_PRE + 256];
	unsigned char *start = header + LWS_PRE;
	unsigned char *cursor = start;
	unsigned char *end = header + sizeof header;

	if (lws_add_http_common_headers(wsi, HTTP_STATUS_BAD_REQUEST,
					"text/html", 0, &cursor, end)
		    != 0
	    || lws_finalize_write_http_header(wsi, start, &cursor, end) != 0) {
		LOGE("Failed to build the HTTP 400 response");
		return -1;
	}

	return lws_http_transaction_completed(wsi);
}

/* Tell whether uri[0..uri_len) starts with prefix. */
static bool _http_uri_has_prefix(const char *uri, size_t uri_len,
				 const char *prefix)
{
	size_t prefix_len = strlen(prefix);

	return uri != nullptr && uri_len >= prefix_len
		&& memcmp(uri, prefix, prefix_len) == 0;
}

/*
 * Split /ocsp/<endpoint>[/<request>] into endpoint and request.  request is
 * NULL when absent; uri starts with ocsp_uri_prefix.  Returns HTTP_STATUS_OK
 * or an HTTP error status.
 */
static int _http_split_ocsp_uri(const char *uri, size_t uri_len,
				const char **endpoint, size_t *endpoint_len,
				const char **request, size_t *request_len)
{
	size_t prefix_len = sizeof ocsp_uri_prefix - 1;
	const char *endpoint_start = uri + prefix_len;
	const char *separator;

	separator = memchr(endpoint_start, '/', uri_len - prefix_len);
	*endpoint = endpoint_start;
	*endpoint_len = separator != nullptr
		? (size_t) (separator - endpoint_start)
		: uri_len - prefix_len;
	if (*endpoint_len == 0)
		return HTTP_STATUS_BAD_REQUEST;

	if (separator != nullptr) {
		*request = separator + 1;
		*request_len = uri_len - (size_t) (*request - uri);
	} else {
		*request = nullptr;
		*request_len = 0;
	}

	return HTTP_STATUS_OK;
}

/*
 * Decode the Base64 OCSP request of a GET URI into data->data and set
 * data->size.
 */
static int _http_decode_ocsp_request(struct http_session_data *data,
				     const char *request, size_t request_len)
{
	unsigned char *decoded = nullptr;
	char *normalized = nullptr;
	size_t decoded_len = 0;
	int status = HTTP_STATUS_BAD_REQUEST;

	if (request == nullptr || request_len == 0)
		goto invalid;

	/*
	 * libwebsockets form-decodes the query/path and turns '+' into ' '.
	 * A base64 request legitimately contains '+', so restore it before
	 * decoding; a raw space is never valid in this position.
	 */
	normalized = osal_malloc(request_len);
	if (normalized == nullptr)
		goto invalid;
	for (size_t i = 0; i < request_len; i++)
		normalized[i] = request[i] == ' ' ? '+' : request[i];

	if (!utils_base64_decode(normalized, request_len, &decoded, &decoded_len)
	    || decoded_len == 0 || decoded_len > MAX_RECEIVED_PAYLOAD_SIZE)
		goto invalid;

	memcpy(data->data + LWS_PRE, decoded, decoded_len);
	data->size = (int) decoded_len;

	LOGD("Decoded OCSP request from URI: %d bytes", data->size);
	status = HTTP_STATUS_OK;

invalid:
	if (status != HTTP_STATUS_OK)
		LOGW("Invalid Base64 OCSP request in URI");
	osal_free(normalized);
	osal_free(decoded);
	return status;
}

/* Send a DER OCSP response to the client. */
static int _http_send_ocsp_response(struct lws *wsi,
				    const unsigned char *body, size_t body_len)
{
	unsigned char header[LWS_PRE + 512];
	unsigned char *start = header + LWS_PRE;
	unsigned char *cursor = start;
	unsigned char *end = header + sizeof header;
	unsigned char *payload;
	int written;

	if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
					"application/ocsp-response",
					(lws_filepos_t) body_len, &cursor,
					end)
		    != 0
	    || lws_finalize_write_http_header(wsi, start, &cursor, end) != 0) {
		LOGE("Failed to build the OCSP response headers");
		return -1;
	}

	payload = osal_malloc(LWS_PRE + body_len);
	if (payload == nullptr) {
		LOGE("Failed to allocate the OCSP response buffer");
		return -1;
	}
	memcpy(payload + LWS_PRE, body, body_len);

	written = lws_write(wsi, payload + LWS_PRE, body_len, LWS_WRITE_HTTP);
	osal_free(payload);
	if (written < 0 || (size_t) written != body_len) {
		LOGE("Failed to send the OCSP response");
		return -1;
	}

	return lws_http_transaction_completed(wsi);
}

/* Send a DER OCSPResponse carrying only an error responseStatus. */
static int _http_send_ocsp_error(struct lws *wsi,
				 ocsp_responder_wire_error_t error)
{
	unsigned char *resp = nullptr;
	size_t resp_len = 0;
	int status;

	if (ocsp_responder_generate_error(error, &resp, &resp_len)
	    != OCSP_RESPONDER_OK) {
		osal_free(resp);
		LOGE("Failed to build the OCSP error response");
		return _http_return_code(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR);
	}

	status = _http_send_ocsp_response(wsi, resp, resp_len);
	osal_free(resp);
	return status;
}

/* Generate and send the OCSP response for the request held in data. */
static int _http_ocsp_respond(struct lws *wsi,
			      struct http_session_data *data,
			      const char *endpoint, size_t endpoint_len)
{
	unsigned char *resp = nullptr;
	size_t resp_len = 0;
	ocsp_responder_status_t responder_status;
	int status;

	responder_status =
		ocsp_responder_generate(endpoint, endpoint_len,
					data->data + LWS_PRE,
					(size_t) data->size, &resp, &resp_len);

	if (responder_status != OCSP_RESPONDER_OK) {
		osal_free(resp);
		switch (responder_status) {
		case OCSP_RESPONDER_ERR_REQUEST_DECODE:
			return _http_send_ocsp_error(
				wsi, OCSP_RESPONDER_WIRE_MALFORMED_REQUEST);
		case OCSP_RESPONDER_ERR_CA_NOT_FOUND:
			return _http_send_ocsp_error(
				wsi, OCSP_RESPONDER_WIRE_UNAUTHORIZED);
		case OCSP_RESPONDER_ERR_UNAUTHORIZED:
			return _http_send_ocsp_error(
				wsi, OCSP_RESPONDER_WIRE_UNAUTHORIZED);
		default:
			return _http_send_ocsp_error(
				wsi, OCSP_RESPONDER_WIRE_INTERNAL_ERROR);
		}
	}

	status = _http_send_ocsp_response(wsi, resp, resp_len);
	osal_free(resp);
	return status;
}

/*
 * Handle an OCSP request; uri starts with ocsp_uri_prefix and uri_len is the
 * full URI length.
 */
static int _http_ocsp_route(struct lws *wsi, struct http_session_data *data,
			     int method, const char *uri, size_t uri_len)
{
	const char *endpoint;
	const char *encoded_request;
	size_t endpoint_len;
	size_t encoded_request_len;
	int status;

	if (method != LWSHUMETH_GET && method != LWSHUMETH_POST) {
		LOGD("Unsupported OCSP method: %d", method);
		return _http_return_code(wsi, HTTP_STATUS_METHOD_NOT_ALLOWED);
	}

	LOGV("Hit OCSP endpoint");

	status = _http_split_ocsp_uri(uri, uri_len, &endpoint, &endpoint_len,
				      &encoded_request, &encoded_request_len);
	if (status != HTTP_STATUS_OK)
		return _http_send_ocsp_error(
			wsi, OCSP_RESPONDER_WIRE_MALFORMED_REQUEST);

	if (method == LWSHUMETH_POST) {
		/*
		 * lws only reports completion for a body with a known length;
		 * a chunked or length-less POST would otherwise hang the
		 * transaction with no response.
		 */
		if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_TRANSFER_ENCODING)
		    > 0) {
			LOGW("Chunked OCSP POST is not supported");
			return _http_return_code(wsi,
						 HTTP_STATUS_NOT_IMPLEMENTED);
		}
		if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH)
		    == 0) {
			LOGW("OCSP POST without Content-Length");
			return _http_return_code(wsi,
						 HTTP_STATUS_LENGTH_REQUIRED);
		}

		/* The request body arrives after this callback. */
		if (endpoint_len >= sizeof data->ocsp_endpoint)
			return _http_send_ocsp_error(
				wsi, OCSP_RESPONDER_WIRE_MALFORMED_REQUEST);
		memcpy(data->ocsp_endpoint, endpoint, endpoint_len);
		data->ocsp_endpoint[endpoint_len] = '\0';
		data->ocsp_endpoint_len = endpoint_len;
		data->ocsp_post = true;
		LOGD("Deferring OCSP POST for endpoint (%zu bytes)",
		     endpoint_len);
		return 0;
	}

	status = _http_decode_ocsp_request(data, encoded_request,
					   encoded_request_len);
	if (status != HTTP_STATUS_OK)
		return _http_send_ocsp_error(
			wsi, OCSP_RESPONDER_WIRE_MALFORMED_REQUEST);

	return _http_ocsp_respond(wsi, data, endpoint, endpoint_len);
}

/*
 * Handle an ACME request; the ACME server is not implemented yet.
 */
static int _http_handle_acme(struct lws *wsi, int method, const char *uri,
			     size_t uri_len)
{
	(void) method;
	(void) uri;
	LOGW("ACME request is not implemented (URI length: %zu)", uri_len);
	return _http_return_code(wsi, HTTP_STATUS_NOT_IMPLEMENTED);
}

static int _http_callback(
	struct lws *wsi,
	enum lws_callback_reasons reason,
	void *user,
	void *in,
	size_t len
)
{
	int method = LWSHUMETH_POST;
	struct http_session_data *data = (struct http_session_data *) user;
	switch (reason) {
	case LWS_CALLBACK_FILTER_HTTP_CONNECTION: {
		char content_type_buf[32];
		char *content_type = nullptr;
		int n = lws_hdr_copy(wsi, content_type_buf,
				     sizeof(content_type_buf),
				     WSI_TOKEN_HTTP_CONTENT_TYPE);
		if (n <= 0)
			content_type = "<null>";
		else
			content_type = content_type_buf;

		char *url = nullptr;
		int url_length = 0;
		method = lws_http_get_uri_and_method(wsi, &url, &url_length);
		if (method < 0 || url == nullptr || url_length < 0) {
			LOGE("Failed to read the HTTP method and URI");
		} else {
			/*
			 * Do not log the raw URL: it is attacker-controlled
			 * and may contain terminal escape sequences.
			 */
			LOGD("HTTP connection established: "
				   "{Method: %s, Content-Type: %s, "
				   "URL length: %d}",
				   _http_method_to_string(method),
				   content_type, url_length);
		}

		/*
		 * CONNECT asks libwebsockets to tunnel a connection, which never
		 * reaches LWS_CALLBACK_HTTP and would otherwise occupy a
		 * connection slot without consuming a rate-limit token.
		 */
		if (method == LWSHUMETH_CONNECT) {
			LOGW("Rejecting CONNECT request");
			return -1;
		}

		/* The filter may run before this protocol owns the session. */
		if (data != nullptr) {
			data->method = method;
			data->ocsp_post = false;
			data->body_too_large = false;
			data->ocsp_endpoint_len = 0;
			data->size = 0;
			/*
			 * Rate-limit here so every transaction is counted,
			 * including requests that libwebsockets rejects before
			 * LWS_CALLBACK_HTTP.  The HTTP callback consumes the
			 * decision instead of taking a second token.
			 */
			data->rate_allowed = _http_rate_allow(wsi);
			data->rate_checked = true;
		}

		break;
	}
	case LWS_CALLBACK_HTTP_BODY: {
		size_t margin;

		if (data == nullptr)
			return -1;

		LOGD("HTTP body chunk: %zu bytes", len);
		if (data->method != LWSHUMETH_POST || data->body_too_large)
			break;

		margin = MAX_RECEIVED_PAYLOAD_SIZE - (size_t) data->size;
		if (len > margin) {
			data->body_too_large = true;
			LOGW("HTTP body exceeds %d bytes",
				   MAX_RECEIVED_PAYLOAD_SIZE);
			break;
		}

		if (len != 0 && in != nullptr) {
			memcpy(data->data + LWS_PRE + data->size, in, len);
			data->size += (int) len;
		}
		break;
	}
	case LWS_CALLBACK_HTTP: {
		char *uri = nullptr;
		int uri_length = 0;
		int request_method;
		bool rate_allowed;

		if (data == nullptr)
			return -1;

		/*
		 * The filter may run before the session is bound to this
		 * protocol; read the method again.
		 */
		request_method =
			lws_http_get_uri_and_method(wsi, &uri, &uri_length);
		data->method = request_method;
		data->size = 0;
		data->ocsp_post = false;
		data->body_too_large = false;
		data->ocsp_endpoint_len = 0;

		if (request_method < 0 || uri == nullptr || uri_length < 0) {
			LOGE("Failed to read the HTTP method and URI");
			return _http_bad_request(wsi);
		}

		if (data->rate_checked) {
			rate_allowed = data->rate_allowed;
			data->rate_checked = false;
		} else {
			rate_allowed = _http_rate_allow(wsi);
		}
		if (!rate_allowed) {
			return _http_return_code(
				wsi, HTTP_STATUS_SERVICE_UNAVAILABLE);
		}

		/*
		 * Dispatch by URI prefix; other HTTP APIs route here, not
		 * inside the OCSP handler.
		 */
		if (_http_uri_has_prefix(uri, (size_t) uri_length,
					 ocsp_uri_prefix))
			return _http_ocsp_route(wsi, data, request_method,
						uri, (size_t) uri_length);

		if (_http_uri_has_prefix(uri, (size_t) uri_length,
					 acme_uri_prefix))
			return _http_handle_acme(wsi, request_method, uri,
						 (size_t) uri_length);

		/* The URI is attacker-controlled; log its length only. */
		LOGD("Unknown URI (length: %d)", uri_length);
		return _http_bad_request(wsi);
	}
	case LWS_CALLBACK_HTTP_BODY_COMPLETION: {
		if (data == nullptr)
			return -1;

		LOGD("HTTP body completion: method=%d ocsp_post=%d "
			   "size=%d",
			   data->method, data->ocsp_post, data->size);
		if (data->method != LWSHUMETH_POST || !data->ocsp_post)
			break;

		data->ocsp_post = false;
		if (data->body_too_large) {
			data->body_too_large = false;
			return _http_return_code(
				wsi, HTTP_STATUS_REQ_ENTITY_TOO_LARGE);
		}
		if (data->size == 0) {
			LOGD("Invalid HTTP POST body");
			return _http_send_ocsp_error(
				wsi, OCSP_RESPONDER_WIRE_MALFORMED_REQUEST);
		}

		return _http_ocsp_respond(wsi, data, data->ocsp_endpoint,
					  data->ocsp_endpoint_len);
	}
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{
		.name = "http",
		.callback = _http_callback,
		.per_session_data_size = sizeof(struct http_session_data),
		.rx_buffer_size = 0,
	},
	LWS_PROTOCOL_LIST_TERM
};

static void _http_signal_handler(int sig)
{
	(void) sig;
	g_interrupted = 1;
}

/* Install handlers that only set g_interrupted.  Logging is not
 * async-signal-safe, so it is left to the main loop. */
static bool _http_install_signal_handlers(void)
{
	if (!osal_signal_install(SIGINT, _http_signal_handler)
	    || !osal_signal_install(SIGTERM, _http_signal_handler)) {
		LOGE("Failed to install signal handlers: %s",
		     osal_signal_error());
		return false;
	}
	return true;
}

bool http_server_start(const http_server_t *config)
{
	struct lws_context_creation_info info = { 0 };
	struct lws_context *context;
	uint32_t max_connections;
	uint32_t requests_per_second;
	uint32_t request_burst;
	bool success = true;

	if (config == nullptr) {
		LOGE("Invalid HTTP server configuration");
		return false;
	}

	max_connections = config->max_connections != 0
		? config->max_connections
		: HTTP_DEFAULT_MAX_CONNECTIONS;
	requests_per_second = config->requests_per_second != 0
		? config->requests_per_second
		: HTTP_DEFAULT_REQUESTS_PER_SECOND;
	request_burst = config->request_burst != 0
		? config->request_burst
		: (requests_per_second > UINT32_MAX / 2
			   ? UINT32_MAX
			   : requests_per_second * 2);

	g_rate_per_second = (double) requests_per_second;
	g_rate_burst = (double) request_burst;
	memset(g_rate_clients, 0, sizeof g_rate_clients);
	g_rate_clock = 0;

	LOGD("Begin server at %s:%u",
	     config->ipv4_address != nullptr ? config->ipv4_address
					     : "<all interfaces>",
	     (unsigned) config->ipv4_port);

	if (!_http_install_signal_handlers())
		return false;

	lws_set_log_level(LLL_ERR | LLL_WARN, nullptr);

	info.iface = config->ipv4_address;
	info.protocols = protocols;
	info.server_string = "anyca_server";
	info.port = config->ipv4_port;
	/* -1 leaves the current ownership unchanged. */
	info.gid = (gid_t) -1;
	info.uid = (uid_t) -1;
	if (max_connections > UINT32_MAX - HTTP_FD_LIMIT_OVERHEAD)
		max_connections = UINT32_MAX - HTTP_FD_LIMIT_OVERHEAD;
	info.fd_limit_per_thread = max_connections + HTTP_FD_LIMIT_OVERHEAD;

	context = lws_create_context(&info);
	if (context == nullptr) {
		LOGE("Failed to create libwebsockets context");
		return false;
	}

	LOGI("HTTP server listening on port %u "
	     "(max %u connections, %u requests/s, burst %u)",
	     (unsigned) info.port, max_connections,
	     requests_per_second, request_burst);
	while (!g_interrupted) {
		if (lws_service(context, 0) < 0) {
			LOGE("HTTP service loop failed");
			success = false;
			break;
		}
	}

	lws_context_destroy(context);

	LOGI("HTTP server stopped");
	return success;
}
