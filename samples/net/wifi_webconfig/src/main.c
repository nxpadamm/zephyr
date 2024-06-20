/**
 * Copyright 2023-2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @file main.c
 * Wifi webconfig sample application
 */

#include <stdio.h>
#include <stdbool.h>

#include <zephyr/kernel.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/net/http/server.h>
#include <zephyr/net/http/service.h>
#include <zephyr/net/http/status.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/socket.h>

#include <zephyr/net/wifi_mgmt.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_webconfig_sample, LOG_LEVEL_DBG);

/* JSON returned for /status route */
#define ROUTE_STATUS_JSON "{\"info\":{" \
	"\"name\":\"" CONFIG_BOARD "\"," \
	"\"ip\":\"%s\"," \
	"\"status\":\"%s\"" \
	"}}"

#define ROUTE_CONNECT_JSON "{" \
"\"status\":\"%s\"," \
"\"ssid\":\"%s\"," \
"\"new_ip\":\"%s\"" \
"}"

#define UAP_SSID "webconfig_access_point"
#define UAP_PSK "ap012345"

K_THREAD_STACK_DEFINE(webconfig_stack, 4096);

K_EVENT_DEFINE(webconfig_event);

struct app_data
{
	/* Saved credentials for current network. Empty strings if not connected.
	 * Pass is empty for open security network */
    char ssid[WIFI_SSID_MAX_LEN];
    char pass[WIFI_PSK_MAX_LEN];
	/* When connected to a network, active_ip will be station's IP address.
	 * otherwise it will be set to the default uAP address */
	char active_ip[INET_ADDRSTRLEN];
	/* True if connected to a network */
    bool connected;
	/* Contains the most recent wifi scan data in JSON format */
	char scan_json[2048];

	struct k_work_q webconfig_work_q;
	struct k_work_delayable disconnect_work;
	struct k_work_delayable start_ap_work;
	struct net_mgmt_event_callback webconfig_event_cb;
};
static struct app_data app;

/* HTTP port to listen on */
static uint16_t http_port = CONFIG_NET_SAMPLE_HTTP_PORT;

/* Webpage data to serve to the user's browser */
static uint8_t index_html_gz[] = {
#include "index.html.gz.inc"
};
static uint8_t recv_buffer[2048];

enum route_state {
	ROUTE_SENDING,
	ROUTE_IDLE
};

/* Function for GET request query string parameter parser
 */
struct param {
	char name[32];
	char value[64];
};
static int next_param(const uint8_t *buffer, size_t len, struct param *p) {
	int eq_index = -1;
	int end_index = -1;
	int i = 0;
	if (len == 0) {
		return 0;
	}
	while (i < len && buffer[i] != '&') {
		if (buffer[i] == '=') {
			eq_index = i;
		}
		i += 1;
	}
	end_index = i;
	int name_len = eq_index == -1 ? end_index : eq_index;
	int value_len = eq_index == -1 ? 0 : end_index - eq_index - 1;
	strncpy(p->name, buffer, name_len);
	p->name[name_len] = '\0';
	strncpy(p->value, buffer+eq_index+1, value_len);
	p->value[value_len] = '\0';

	return i + (i==len ? 0 : 1); // Number of chars processed
}

/* GET /status
 * returns JSON
*/
static int route_status(struct http_client_ctx *client, uint8_t *buffer, size_t len, void *user_data)
{
	static enum route_state state = ROUTE_IDLE;
	int ret = 0;
	if (state == ROUTE_IDLE) {
		state = ROUTE_SENDING;

		if (strlen(app.active_ip) == 0) {
			/* No active IP set, get uAP address */
			int wifi_uap_index = net_if_get_by_name("ua");
			struct net_if *_iface = net_if_get_by_index(wifi_uap_index);
			struct in_addr *addr = net_if_ipv4_get_global_addr(_iface, NET_ADDR_PREFERRED);
			inet_ntop(AF_INET, addr, app.active_ip, sizeof(app.active_ip));
		}
		ret = snprintk(recv_buffer, sizeof(recv_buffer), ROUTE_STATUS_JSON,
			app.active_ip,
		    app.connected ? "client" : "ap");
	}
	else if (state == ROUTE_SENDING){
		LOG_DBG("Finished route_status");
		state = ROUTE_IDLE;
		ret = 0;
	}

	/* Note: ret indicates how many bytes from buffer will be actually sent to client */
	return ret;
}

/* GET /scan
 * returns JSON
*/
static int route_scan(struct http_client_ctx *client, uint8_t *buffer, size_t len, void *user_data)
{
	static enum route_state state = ROUTE_IDLE;
	int ret = 0;
	if (state == ROUTE_IDLE) {
		state = ROUTE_SENDING;
		struct net_if *iface = net_if_get_first_wifi();
		struct wifi_scan_params params = { 0 };
		int failure = 0;

		if (net_mgmt(NET_REQUEST_WIFI_SCAN, iface, &params, sizeof(params))) {
			LOG_ERR("Scan request failed");
			failure = 1;
		}
		else {
			uint32_t events = k_event_wait(&webconfig_event, 0x001, true, K_FOREVER);
			if (events == 0) {
				failure = 1;
			}
		}

		if (failure) {
			ret = snprintk(recv_buffer, sizeof(recv_buffer), "{\"networks\":[]}");
		}
		else {
			ret = snprintk(recv_buffer, sizeof(recv_buffer), "{\"networks\":[%s]}", app.scan_json);
		}
	}
	else if (state == ROUTE_SENDING){
		state = ROUTE_IDLE;
		LOG_DBG("Finished route_scan");
		ret = 0;
	}

	return ret;
}

/* GET /connect?ssid=<ssid>&pass=<pass>
 * returns JSON
*/
static int route_connect(struct http_client_ctx *client, uint8_t *buffer, size_t len, void *user_data)
{
	/* FIXME: this route needs to be changed to POST request */
	static enum route_state state = ROUTE_IDLE;
	int ret = 0;

	if (state == ROUTE_IDLE) {
		state = ROUTE_SENDING;
		struct wifi_connect_req_params params = { 0 };
		app.ssid[0] = '\0';
		app.pass[0] = '\0';
		int processed = 1; // skip 0th byte as it is the '?' separator
		int bytes_read;
		struct param p;
		while ((bytes_read = next_param(buffer+processed, len-processed, &p))) {
			processed += bytes_read;
			if (strcmp(p.name, "ssid") == 0) {
				LOG_DBG("Got ssid=%s", p.value);
				strcpy(app.ssid, p.value);
			}
			else if (strcmp(p.name, "pass") == 0) {
				LOG_DBG("Got pass=%s", p.value);
				strcpy(app.pass, p.value);
			}
			else {
				LOG_DBG("Unknown GET param %s=%s", p.name, p.value);
			}
		}
		params.ssid = app.ssid;
		params.psk = app.pass;
		params.ssid_length = strlen(app.ssid);
		params.psk_length = strlen(app.pass);
		if (params.psk_length > 0) {
			params.security = WIFI_SECURITY_TYPE_PSK;
		}
		struct net_if *iface = net_if_get_first_wifi();
		ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &params, sizeof(struct wifi_connect_req_params));
		if (ret) {
			LOG_ERR("wifi connect request failed");
			ret = snprintk(recv_buffer, sizeof(recv_buffer), ROUTE_CONNECT_JSON, "failure", app.ssid, "");
		}
		else {
			/* Wait for connect to complete. This wait is needed because we need station's IP address, which
			 * gets sent back to the user. */
			k_event_wait(&webconfig_event, 0x002, true, K_FOREVER);
			ret = snprintk(recv_buffer, sizeof(recv_buffer), ROUTE_CONNECT_JSON, "success", app.ssid, app.active_ip);
			app.connected = true;
		}
	}
	else if (state == ROUTE_SENDING){
		LOG_DBG("Finished route_connect");
		state = ROUTE_IDLE;
	}

	return ret;
}

/* GET /reset
 * returns JSON
*/
static int route_reset(struct http_client_ctx *client, uint8_t *buffer, size_t len, void *user_data)
{
	static enum route_state state = ROUTE_IDLE;
	int ret = 0;

	if (state == ROUTE_IDLE) {
		state = ROUTE_SENDING;
		ret = snprintk(recv_buffer, sizeof(recv_buffer), ROUTE_CONNECT_JSON,
			"success", UAP_SSID, "192.168.10.1");
	}
	else if (state == ROUTE_SENDING){
		LOG_DBG("Finished route_reset");
		/* The route is done sending data, schedule wifi disconnect */
		k_work_schedule_for_queue(&app.webconfig_work_q, &app.disconnect_work, K_MSEC(1000));
		state = ROUTE_IDLE;
	}

	return ret;
}

/* HTTP resource detail definitions */
struct http_resource_detail_static index_resource_detail = {
	.common = {
		.type = HTTP_RESOURCE_TYPE_STATIC,
		.bitmask_of_supported_http_methods = BIT(HTTP_GET),
	},
	.static_data = index_html_gz,
	.static_data_len = sizeof(index_html_gz),
};

struct http_resource_detail_dynamic status_resource_detail = {
	.common = {
		.type = HTTP_RESOURCE_TYPE_DYNAMIC,
		.bitmask_of_supported_http_methods = BIT(HTTP_GET),
	},
	.cb = route_status,
	.data_buffer = recv_buffer, .data_buffer_len = sizeof(recv_buffer), .user_data = NULL,
};

struct http_resource_detail_dynamic scan_resource_detail = {
	.common = {
		.type = HTTP_RESOURCE_TYPE_DYNAMIC,
		.bitmask_of_supported_http_methods = BIT(HTTP_GET),
	},
	.cb = route_scan,
	.data_buffer = recv_buffer, .data_buffer_len = sizeof(recv_buffer), .user_data = NULL,
};

struct http_resource_detail_dynamic connect_resource_detail = {
	.common = {
		.type = HTTP_RESOURCE_TYPE_DYNAMIC,
		.bitmask_of_supported_http_methods = BIT(HTTP_GET),
	},
	.cb = route_connect,
	.data_buffer = recv_buffer, .data_buffer_len = sizeof(recv_buffer), .user_data = NULL,
};

struct http_resource_detail_dynamic reset_resource_detail = {
	.common = {
		.type = HTTP_RESOURCE_TYPE_DYNAMIC,
		.bitmask_of_supported_http_methods = BIT(HTTP_GET),
	},
	.cb = route_reset,
	.data_buffer = recv_buffer, .data_buffer_len = sizeof(recv_buffer), .user_data = NULL,
};

HTTP_SERVICE_DEFINE(test_http_service, "0.0.0.0", &http_port, 1, 10, NULL);

HTTP_RESOURCE_DEFINE(index_resource, test_http_service, "/", &index_resource_detail);
HTTP_RESOURCE_DEFINE(status_resource, test_http_service, "/status", &status_resource_detail);
HTTP_RESOURCE_DEFINE(scan_resource, test_http_service, "/scan", &scan_resource_detail);
HTTP_RESOURCE_DEFINE(connect_resource, test_http_service, "/connect", &connect_resource_detail);
HTTP_RESOURCE_DEFINE(reset_resource, test_http_service, "/reset", &reset_resource_detail);

/**
 * @brief Used to handle wifi events by this web server application.
 */
static void webconfig_event_handler(struct net_mgmt_event_callback *cb,
				    uint32_t mgmt_event, struct net_if *iface)
{
/* Scan entry JSON template */
#define ROUTE_SCAN_JSON \
"{" \
	"\"ssid\":\"%s\"," \
	"\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\"," \
	"\"channel\":\"%d\"," \
	"\"signal\":\"%d\"," \
	"\"security\":\"%s\"" \
"}"

	static int scan_n = 0;
	struct net_if *_iface;
	struct in_addr *addr;

	switch (mgmt_event) {
	case NET_EVENT_WIFI_SCAN_RESULT:
		const struct wifi_scan_result *e = (const struct wifi_scan_result *)cb->info;
		char entry_json[128];
		if (scan_n == 0) {
			app.scan_json[0] = '\0';
		}
		snprintk(entry_json, sizeof(entry_json), ROUTE_SCAN_JSON ",",
			e->ssid,
			e->mac[0], e->mac[1], e->mac[2], e->mac[3], e->mac[4], e->mac[5],
			e->channel,
			e->rssi,
			wifi_security_txt(e->security)
		);
		strcat(app.scan_json, entry_json);
		scan_n += 1;
		break;
	case NET_EVENT_WIFI_SCAN_DONE:
		scan_n = 0;
		int scan_json_len = strlen(app.scan_json);
		if (scan_json_len > 0) {
			app.scan_json[scan_json_len - 1] = '\0'; // To remove last ',' from JSON
		}
		k_event_set(&webconfig_event, 0x001);
		break;
	case NET_EVENT_WIFI_CONNECT_RESULT:
		app.connected = true;
		_iface = net_if_get_first_wifi();
		addr = net_if_ipv4_get_global_addr(_iface, NET_ADDR_PREFERRED);
		inet_ntop(AF_INET, addr, app.active_ip, sizeof(app.active_ip));
		LOG_WRN("The device has connected to \"%s\" and is reachable at %s", app.ssid, app.active_ip);
		k_event_set(&webconfig_event, 0x002);
		break;
	case NET_EVENT_WIFI_DISCONNECT_RESULT:
		app.connected = false;
		app.ssid[0] = '\0';
		app.pass[0] = '\0';
		int wifi_uap_index = net_if_get_by_name("ua");
		_iface = net_if_get_by_index(wifi_uap_index);
		addr = net_if_ipv4_get_global_addr(_iface, NET_ADDR_PREFERRED);
		inet_ntop(AF_INET, addr, app.active_ip, sizeof(app.active_ip));
		LOG_WRN("The device has disconnected from the network. Connect back" \
		" to this device's wifi network \"%s\" and browse to %s", UAP_SSID, app.active_ip);
		k_event_set(&webconfig_event, 0x002);
		break;
	default:
		break;
	}
}

static void defer_disconnect(struct k_work *item) {
	int ret;
	struct net_if *iface = net_if_get_first_wifi();
	ret = net_mgmt(NET_REQUEST_WIFI_DISCONNECT, iface, NULL, 0);
	if (ret) {
		LOG_ERR("wifi disconnect request failed");
	}
}

static void defer_start_ap(struct k_work *item) {
	int ret;
	int wifi_uap_index = net_if_get_by_name("ua");
	struct net_if *iface = net_if_get_by_index(wifi_uap_index);
	LOG_DBG("Starting uAP on iface: %d (%p)", wifi_uap_index, iface);
	if (iface == NULL) {
		LOG_ERR("\"ua\" wifi network interface not found. Please make sure" \
			"the wifi driver is initializing this netif before app starts.");
	}
	else {
		struct wifi_connect_req_params params = {
			.ssid = UAP_SSID,
			.ssid_length = sizeof(UAP_SSID),
			.psk = UAP_PSK,
			.psk_length = sizeof(UAP_PSK),
			.security = WIFI_SECURITY_TYPE_PSK,
		};
		ret = net_mgmt(NET_REQUEST_WIFI_AP_ENABLE, iface, &params, sizeof(params));
		if (ret) {
			LOG_ERR("Wi-fi uAP request failed");
		}
		else {
			LOG_INF("Wi-fi uAP started successfully");
		}
	}
	return;
}

int main(void) {
	/* Setup wifi callbacks for this application */
	net_mgmt_init_event_callback(&app.webconfig_event_cb,
				     webconfig_event_handler,
				     ( NET_EVENT_WIFI_SCAN_RESULT
					 | NET_EVENT_WIFI_SCAN_DONE
					 | NET_EVENT_WIFI_CONNECT_RESULT
					 | NET_EVENT_WIFI_DISCONNECT_RESULT));
	net_mgmt_add_event_callback(&app.webconfig_event_cb);

	k_work_queue_init(&app.webconfig_work_q);
	k_work_queue_start(&app.webconfig_work_q, webconfig_stack,
					K_THREAD_STACK_SIZEOF(webconfig_stack), 1,
					NULL);
	k_work_init_delayable(&app.disconnect_work, defer_disconnect);
	k_work_init_delayable(&app.start_ap_work, defer_start_ap);

	/* Schedule uAP start */
	k_work_schedule_for_queue(&app.webconfig_work_q, &app.start_ap_work, K_MSEC(2000));

	/* Init HTTP server */
	struct http_server_ctx ctx;
	int ret;
	ret = http_server_init(&ctx);
	if (ret < 0) {
		LOG_ERR("Failed to initialize HTTP2 server");
		return ret;
	}

	/* Start HTTP server (endless loop until server is stopped) */
	ret = http_server_start(&ctx);

	return ret;
}
