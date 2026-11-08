/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_SERVER_HTTP_SERVER_H
#define ANYCA_SERVER_HTTP_SERVER_H

/**
 * @file http_server.h
 * @brief HTTP transport of the server application.
 *
 * Owns the listening socket and request parsing; OCSP requests are delegated
 * to ocsp_responder.  Not part of libanyca_core.
 */

#include <stdbool.h>
#include <stdint.h>

#define MAX_RECEIVED_PAYLOAD_SIZE (10 * 1024)

/** Max libwebsockets fds when max_connections is zero. */
#define HTTP_DEFAULT_MAX_CONNECTIONS 1024U
/** Per-client request rate when requests_per_second is zero. */
#define HTTP_DEFAULT_REQUESTS_PER_SECOND 1000U
/** Per-client request burst when request_burst is zero. */
#define HTTP_DEFAULT_REQUEST_BURST 2000U
/** Extra fds reserved for libwebsockets internal use. */
#define HTTP_FD_LIMIT_OVERHEAD 16U

#ifdef __cplusplus
extern "C" {
#endif

/** Listening address, port and availability limits for the HTTP server. */
typedef struct http_server {
	const char *ipv4_address;
	uint16_t ipv4_port;
	/** 0 selects HTTP_DEFAULT_MAX_CONNECTIONS. */
	uint32_t max_connections;
	/** 0 selects HTTP_DEFAULT_REQUESTS_PER_SECOND. */
	uint32_t requests_per_second;
	/** 0 selects HTTP_DEFAULT_REQUEST_BURST. */
	uint32_t request_burst;
} http_server_t;

/**
 * Run the HTTP server until SIGINT/SIGTERM.
 *
 * @param config listening address and availability limits.
 * @return true when the server stopped normally, false when it could not be
 *         started or the service loop failed.
 */
bool http_server_start(const http_server_t *config);

#ifdef __cplusplus
}
#endif

#endif // ANYCA_SERVER_HTTP_SERVER_H
