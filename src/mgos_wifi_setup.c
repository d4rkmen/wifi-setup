/*
 * Copyright (c) 2020 d4rkmen <darkmen@i.ua>
 * Copyright (c) 2018 Myles McNamara <https://smyl.es> (captive portal)
 * Copyright (c) 2014-2018 Cesanta Software Limited (Scan)
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the ""License"");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an ""AS IS"" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdlib.h>

#include "mgos.h"
#include "mgos_http_server.h"
#include "mgos_rpc.h"
#include "mgos_wifi.h"

#include "common/platform.h"

#if CS_PLATFORM == CS_P_ESP8266
#include "user_interface.h"
#endif
#if CS_PLATFORM == CS_P_ESP32
#include "esp_wifi.h"
#endif

static const char *s_our_ip;

static mg_event_handler_t http_event_handler = NULL;

static void swap(struct mgos_wifi_scan_result *a,
                 struct mgos_wifi_scan_result *b) {
  struct mgos_wifi_scan_result tmp;
  tmp = *a;
  *a = *b;
  *b = tmp;
  (void) a;
  (void) b;
}

static int wifi_scan_result_printer(struct json_out *out, va_list *ap) {
  int len = 0;
  int num_res = va_arg(*ap, int);

  struct mgos_wifi_scan_result *r = va_arg(*ap, struct mgos_wifi_scan_result *);
  // Sorting strongest first
  for (int i = 0; i < num_res; i++)
    for (int j = 1; j < num_res - i; j++)
      if (r[j].rssi > r[j - 1].rssi) swap(&r[j], &r[j - 1]);

  for (int i = 0; i < num_res; i++) {
    if (i) len += json_printf(out, ", ");

    len += json_printf(out,
                       "{ssid: %Q, bssid: \"%02x:%02x:%02x:%02x:%02x:%02x\", "
                       "auth: %d, channel: %d,"
                       " rssi: %d}",
                       r->ssid, r->bssid[0], r->bssid[1], r->bssid[2],
                       r->bssid[3], r->bssid[4], r->bssid[5], r->auth_mode,
                       r->channel, r->rssi);
    r++;
  }

  return len;
}

static void wifi_scan_cb(int n, struct mgos_wifi_scan_result *res, void *arg) {
  struct mg_rpc_request_info *ri = (struct mg_rpc_request_info *) arg;

  if (n < 0) {
    mg_rpc_send_errorf(ri, n, "wifi scan failed");
    return;
  }
  mg_rpc_send_responsef(ri, "[%M]", wifi_scan_result_printer, n, res);
}

static void wifi_scan_rpc_handler(struct mg_rpc_request_info *ri, void *cb_arg,
                                  struct mg_rpc_frame_info *fi,
                                  struct mg_str args) {
  mgos_wifi_scan(wifi_scan_cb, ri);

  (void) args;
  (void) cb_arg;
  (void) fi;
}

// DNS

static void wifi_dns_handler(struct mg_connection *c, int ev, void *ev_data,
                             void *user_data) {
  struct mg_dns_message *msg = (struct mg_dns_message *) ev_data;
  struct mbuf reply_buf;
  int i;

  if (ev != MG_DNS_MESSAGE) return;

  mbuf_init(&reply_buf, 512);
  struct mg_dns_reply reply = mg_dns_create_reply(&reply_buf, msg);
  for (i = 0; i < msg->num_questions; i++) {
    char rname[256];
    struct mg_dns_resource_record *rr = &msg->questions[i];
    mg_dns_uncompress_name(msg, &rr->name, rname, sizeof(rname) - 1);
    LOG(LL_VERBOSE_DEBUG, ("Q type %d name %s", rr->rtype, rname));
    if (rr->rtype == MG_DNS_A_RECORD) {
      uint32_t ip = inet_addr(s_our_ip);
      mg_dns_reply_record(&reply, rr, NULL, rr->rtype, 10, &ip, 4);
    }
  }
  mg_dns_send_reply(c, &reply);
  mbuf_free(&reply_buf);
  (void) user_data;
}

char *get_redirect_url(void) {
  static char redirect_url[256];
  // Set URI as HTTPS if ssl cert configured, otherwise use http
  c_snprintf(redirect_url, sizeof redirect_url, "%s://%s/wifi.html",
             (mgos_sys_config_get_http_ssl_cert() ? "https" : "http"),
             s_our_ip);
  return redirect_url;
}

static void http_msg_print(const struct http_message *msg) {
  LOG(LL_INFO,
      ("%.*s: %.*s", msg->method.len, msg->method.p, msg->uri.len, msg->uri.p));
}

static void http_handler(struct mg_connection *nc, int ev, void *p,
                         void *user_data) {
  (void) user_data;
  if (ev != MG_EV_HTTP_REQUEST) {
    http_event_handler(nc, ev, p, user_data);
    return;
  }

  struct http_message *msg = (struct http_message *) (p);
  http_msg_print(msg);

  // Bypass all RPC calls, need for captive portal
  struct mg_str rpc_pattern = mg_mk_str("/rpc/**");
  bool is_rpc = (mg_match_prefix_n(rpc_pattern, msg->uri) > 0);

  char uri[256];
  snprintf(uri, sizeof(uri), "%.*s", (int) msg->uri.len, msg->uri.p);

  cs_stat_t st;
  bool is_file = (mg_stat(uri, &st) == 0);
  bool is_dir = is_file && S_ISDIR(st.st_mode);
  LOG(LL_INFO,
      ("is_rpc: %s, is_file: %s, is_dir: %s", is_rpc ? "true" : "false",
       is_file ? "true" : "false", is_dir ? "true" : "false"));
  if (is_rpc || is_file || is_dir) {
    http_event_handler(nc, ev, p, user_data);
    return;
  }
  char *redirect_url = get_redirect_url();
  LOG(LL_DEBUG, ("Redirecting to: %s", redirect_url));
  mg_http_send_redirect(nc, 302, mg_mk_str(redirect_url), mg_mk_str(NULL));
}

static void mgos_wifi_setup_platform() {
#if CS_PLATFORM == CS_P_ESP8266
  int on = 1;
  wifi_softap_set_dhcps_offer_option(OFFER_ROUTER, &on);
#endif
#if CS_PLATFORM == CS_P_ESP32
  esp_wifi_set_mode(WIFI_MODE_APSTA);
#endif
}

bool mgos_wifi_setup_init(void) {
  // RPC
  mg_rpc_add_handler(mgos_rpc_get_global(), "Wifi.Scan", "",
                     wifi_scan_rpc_handler, NULL);
  //  Captive running auto only for AP mode #todo add captive.enable also
  bool captive = mgos_sys_config_get_wifi_ap_enable();
  // No more init for non-captive mode
  if (!captive) return true;
  // HAL
  mgos_wifi_setup_platform();
  // DNS
  struct mg_connection *dns =
      mg_bind(mgos_get_mgr(), "udp://:53", wifi_dns_handler, NULL);
  if (dns == NULL) {
    LOG(LL_ERROR, ("Failed to open DNS port"));
    return false;
  }
  mg_set_protocol_dns(dns);
  // Portal IP from settings
  const char *ip = mgos_sys_config_get_wifi_ap_ip();
  s_our_ip = ip ? ip : "192.168.4.1";
  // HTTP handler hijack
  struct mg_connection *nc = mgos_get_sys_http_server();
  if (nc == NULL) {
    LOG(LL_ERROR, ("Failed to get global HTTP connection"));
    return false;
  }
  http_event_handler = nc->handler;
  nc->handler = http_handler;

  return true;
}
