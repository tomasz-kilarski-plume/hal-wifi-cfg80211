/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2019 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "wifi_hal_hapd.h"

#if 0
#define DPF if (0) printf
#else
#define DPF printf
#endif

#define PRINT_IF_PRESENT(REF, NAME) do \
        { \
            if ((REF)->NAME.present) \
            { \
                DPF("%s=%s\n", #NAME, (REF)->NAME.value); \
            } \
        } while(0)


#define WRITE_IF_PRESENT(FP, REF, NAME) do \
        { \
            if ((REF)->NAME.present) \
            { \
                fprintf(FP, "%s=%s\n", #NAME, (REF)->NAME.value); \
            } \
        } while(0)

#define SET_CFG(NAME, VAL) do \
        { \
            snprintf(NAME.value, sizeof(NAME.value), "%s", VAL); \
            NAME.present = true; \
        } while(0)


void hapd_print_cfg(hapd_cfg_t *cfg)
{
    DPF("Hapd: config begin\n");
    PRINT_IF_PRESENT(cfg, accept_mac_file);
    PRINT_IF_PRESENT(cfg, ap_isolate);
    PRINT_IF_PRESENT(cfg, ap_setup_locked);
    PRINT_IF_PRESENT(cfg, auth_algs);
    PRINT_IF_PRESENT(cfg, beacon_int);
    PRINT_IF_PRESENT(cfg, bridge);
    PRINT_IF_PRESENT(cfg, bss);
    PRINT_IF_PRESENT(cfg, bssid);
    PRINT_IF_PRESENT(cfg, bss_load_update_period);
    PRINT_IF_PRESENT(cfg, bss_transition);
    PRINT_IF_PRESENT(cfg, channel);
    PRINT_IF_PRESENT(cfg, chan_util_avg_period);
    PRINT_IF_PRESENT(cfg, config_methods);
    PRINT_IF_PRESENT(cfg, country_code);
    PRINT_IF_PRESENT(cfg, ctrl_interface);
    PRINT_IF_PRESENT(cfg, disassoc_low_ack);
    PRINT_IF_PRESENT(cfg, driver);
    PRINT_IF_PRESENT(cfg, eap_server);
    PRINT_IF_PRESENT(cfg, ht_capab);
    PRINT_IF_PRESENT(cfg, hw_mode);
    PRINT_IF_PRESENT(cfg, ieee80211ac);
    PRINT_IF_PRESENT(cfg, ieee80211d);
    PRINT_IF_PRESENT(cfg, ieee80211n);
    PRINT_IF_PRESENT(cfg, ignore_broadcast_ssid);
    PRINT_IF_PRESENT(cfg, interface);
    PRINT_IF_PRESENT(cfg, logger_stdout);
    PRINT_IF_PRESENT(cfg, logger_stdout_level);
    PRINT_IF_PRESENT(cfg, logger_syslog);
    PRINT_IF_PRESENT(cfg, logger_syslog_level);
    PRINT_IF_PRESENT(cfg, macaddr_acl);
    PRINT_IF_PRESENT(cfg, preamble);
    PRINT_IF_PRESENT(cfg, rrm_neighbor_report);
    PRINT_IF_PRESENT(cfg, ssid);
    PRINT_IF_PRESENT(cfg, uapsd_advertisement_enabled);
    PRINT_IF_PRESENT(cfg, vht_oper_centr_freq_seg0_idx);
    PRINT_IF_PRESENT(cfg, vht_oper_chwidth);
    PRINT_IF_PRESENT(cfg, wmm_enabled);
    PRINT_IF_PRESENT(cfg, wpa);
    PRINT_IF_PRESENT(cfg, wpa_key_mgmt);
    PRINT_IF_PRESENT(cfg, wpa_pairwise);
    PRINT_IF_PRESENT(cfg, wpa_passphrase);
    PRINT_IF_PRESENT(cfg, wpa_psk_file);
    PRINT_IF_PRESENT(cfg, wps_pin_requests);
    PRINT_IF_PRESENT(cfg, wps_state);
    DPF("Hapd: config end\n");
}

static char* trim(char *str)
{
    const char *space=" \t\n\r";
    char *bgn;
    int len;

    for (bgn = str; *bgn != '\0' && strchr(space, *bgn) != NULL; bgn += 1);

    len = strlen(bgn);
    if (len > 0)
    {
        char *end;
        for (end = bgn + len - 1; end > bgn && strchr(space, *end) != NULL; end -= 1);
        end[1] = '\0';
    }
    return bgn;
}

static void hapd_parse_line(hapd_cfg_t *cfg, char *line, int line_index)
{
    char *key;
    char *value;

    key = line;
    value = strchr(line, '=');
    if (value == NULL)
    {
        DPF("Hapd: Missing value separator (line=%d)\n", line_index);
	return;
    }
    *value++ = '\0';

    key = trim(key);
    if (strlen(key) == 0)
    {
	DPF("Hapd: Hostapd configuration malformed (line=%d)\n", line_index);
	return;
    }

    value = trim(value);
    if (strlen(value) == 0)
    {
        DPF("Hapd: Value not specified for the key='%s' (line=%d)\n", key, line_index);
	return;
    }

    if (!strcmp(key, "accept_mac_file")) SET_CFG(cfg->accept_mac_file, value);
    else if (!strcmp(key, "ap_isolate")) SET_CFG(cfg->ap_isolate, value);
    else if (!strcmp(key, "ap_setup_locked")) SET_CFG(cfg->ap_setup_locked, value);
    else if (!strcmp(key, "auth_algs")) SET_CFG(cfg->auth_algs, value);
    else if (!strcmp(key, "beacon_int")) SET_CFG(cfg->beacon_int, value);
    else if (!strcmp(key, "bridge")) SET_CFG(cfg->bridge, value);
    else if (!strcmp(key, "bss")) SET_CFG(cfg->bss, value);
    else if (!strcmp(key, "bssid")) SET_CFG(cfg->bssid, value);
    else if (!strcmp(key, "bss_load_update_period")) SET_CFG(cfg->bss_load_update_period, value);
    else if (!strcmp(key, "bss_transition")) SET_CFG(cfg->bss_transition, value);
    else if (!strcmp(key, "channel")) SET_CFG(cfg->country_code, value);
    else if (!strcmp(key, "chan_util_avg_period")) SET_CFG(cfg->chan_util_avg_period, value);
    else if (!strcmp(key, "config_methods")) SET_CFG(cfg->config_methods, value);
    else if (!strcmp(key, "country_code")) SET_CFG(cfg->country_code, value);
    else if (!strcmp(key, "ctrl_interface")) SET_CFG(cfg->ctrl_interface, value);
    else if (!strcmp(key, "disassoc_low_ack")) SET_CFG(cfg->disassoc_low_ack, value);
    else if (!strcmp(key, "driver")) SET_CFG(cfg->driver, value);
    else if (!strcmp(key, "eap_server")) SET_CFG(cfg->eap_server, value);
    else if (!strcmp(key, "ht_capab")) SET_CFG(cfg->ht_capab, value);
    else if (!strcmp(key, "hw_mode")) SET_CFG(cfg->hw_mode, value);
    else if (!strcmp(key, "ieee80211ac")) SET_CFG(cfg->ieee80211ac, value);
    else if (!strcmp(key, "ieee80211d")) SET_CFG(cfg->ieee80211d, value);
    else if (!strcmp(key, "ieee80211n")) SET_CFG(cfg->ieee80211n, value);
    else if (!strcmp(key, "interface")) SET_CFG(cfg->interface, value);
    else if (!strcmp(key, "ignore_broadcast_ssid")) SET_CFG(cfg->ignore_broadcast_ssid, value);
    else if (!strcmp(key, "logger_stdout")) SET_CFG(cfg->logger_stdout, value);
    else if (!strcmp(key, "logger_stdout_level")) SET_CFG(cfg->logger_stdout_level, value);
    else if (!strcmp(key, "logger_syslog")) SET_CFG(cfg->logger_syslog, value);
    else if (!strcmp(key, "logger_syslog_level")) SET_CFG(cfg->logger_syslog_level, value);
    else if (!strcmp(key, "macaddr_acl")) SET_CFG(cfg->macaddr_acl, value);
    else if (!strcmp(key, "preamble")) SET_CFG(cfg->preamble, value);
    else if (!strcmp(key, "rrm_neighbor_report")) SET_CFG(cfg->rrm_neighbor_report, value);
    else if (!strcmp(key, "ssid")) SET_CFG(cfg->ssid, value);
    else if (!strcmp(key, "uapsd_advertisement_enabled")) SET_CFG(cfg->uapsd_advertisement_enabled, value);
    else if (!strcmp(key, "vht_oper_centr_freq_seg0_idx")) SET_CFG(cfg->vht_oper_centr_freq_seg0_idx, value);
    else if (!strcmp(key, "vht_oper_chwidth")) SET_CFG(cfg->vht_oper_chwidth, value);
    else if (!strcmp(key, "wmm_enabled")) SET_CFG(cfg->wmm_enabled, value);
    else if (!strcmp(key, "wpa")) SET_CFG(cfg->wpa, value);
    else if (!strcmp(key, "wpa_key_mgmt")) SET_CFG(cfg->wpa_key_mgmt, value);
    else if (!strcmp(key, "wpa_pairwise")) SET_CFG(cfg->wpa_pairwise, value);
    else if (!strcmp(key, "wpa_passphrase")) SET_CFG(cfg->wpa_passphrase, value);
    else if (!strcmp(key, "wpa_psk_file")) SET_CFG(cfg->wpa_psk_file, value);
    else if (!strcmp(key, "wps_pin_requests")) SET_CFG(cfg->wps_pin_requests, value);
    else if (!strcmp(key, "wps_state")) SET_CFG(cfg->wps_state, value);
    else
    {
        DPF("Hapd: Unknown hostapd configuration key='%s' (line=%d)\n", key, line_index);
    }
}

int hapd_read_cfg(hapd_cfg_t *cfg, const char *filename)
{
    FILE *stream;
    char *buffer = NULL;
    char *line;
    int index = 0;
    size_t len = 0;
    ssize_t nread;

    DPF("Hapd: Parse configuration '%s'\n", filename);
    stream = fopen(filename, "r");
    if (stream == NULL)
    {
        perror("fopen");
        return -1;
    }
    memset(cfg, 0, sizeof(*cfg));
    while ((nread = getline(&buffer, &len, stream)) != -1)
    {
        index += 1;

        line = trim(buffer);
	if (line[0] == '#' || strlen(line) == 0) continue;
        hapd_parse_line(cfg, line, index);
    }
    free(buffer);
    fclose(stream);

    return 0;
}

int hapd_write_cfg(hapd_cfg_t *cfg, const char *filename)
{
    FILE *fp;
    fp = fopen(filename, "w");
    if (fp == NULL)
    {
        perror("fopen");
        return -1;
    }

    WRITE_IF_PRESENT(fp, cfg, accept_mac_file);
    WRITE_IF_PRESENT(fp, cfg, ap_isolate);
    WRITE_IF_PRESENT(fp, cfg, ap_setup_locked);
    WRITE_IF_PRESENT(fp, cfg, auth_algs);
    WRITE_IF_PRESENT(fp, cfg, beacon_int);
    WRITE_IF_PRESENT(fp, cfg, bridge);
    WRITE_IF_PRESENT(fp, cfg, bss);
    WRITE_IF_PRESENT(fp, cfg, bssid);
    WRITE_IF_PRESENT(fp, cfg, bss_load_update_period);
    WRITE_IF_PRESENT(fp, cfg, bss_transition);
    WRITE_IF_PRESENT(fp, cfg, channel);
    WRITE_IF_PRESENT(fp, cfg, chan_util_avg_period);
    WRITE_IF_PRESENT(fp, cfg, config_methods);
    WRITE_IF_PRESENT(fp, cfg, country_code);
    WRITE_IF_PRESENT(fp, cfg, ctrl_interface);
    WRITE_IF_PRESENT(fp, cfg, disassoc_low_ack);
    WRITE_IF_PRESENT(fp, cfg, driver);
    WRITE_IF_PRESENT(fp, cfg, eap_server);
    WRITE_IF_PRESENT(fp, cfg, ht_capab);
    WRITE_IF_PRESENT(fp, cfg, hw_mode);
    WRITE_IF_PRESENT(fp, cfg, ieee80211ac);
    WRITE_IF_PRESENT(fp, cfg, ieee80211d);
    WRITE_IF_PRESENT(fp, cfg, ieee80211n);
    WRITE_IF_PRESENT(fp, cfg, ignore_broadcast_ssid);
    WRITE_IF_PRESENT(fp, cfg, interface);
    WRITE_IF_PRESENT(fp, cfg, logger_stdout);
    WRITE_IF_PRESENT(fp, cfg, logger_stdout_level);
    WRITE_IF_PRESENT(fp, cfg, logger_syslog);
    WRITE_IF_PRESENT(fp, cfg, logger_syslog_level);
    WRITE_IF_PRESENT(fp, cfg, macaddr_acl);
    WRITE_IF_PRESENT(fp, cfg, preamble);
    WRITE_IF_PRESENT(fp, cfg, rrm_neighbor_report);
    WRITE_IF_PRESENT(fp, cfg, ssid);
    WRITE_IF_PRESENT(fp, cfg, uapsd_advertisement_enabled);
    WRITE_IF_PRESENT(fp, cfg, vht_oper_centr_freq_seg0_idx);
    WRITE_IF_PRESENT(fp, cfg, vht_oper_chwidth);
    WRITE_IF_PRESENT(fp, cfg, wmm_enabled);
    WRITE_IF_PRESENT(fp, cfg, wpa);
    WRITE_IF_PRESENT(fp, cfg, wpa_key_mgmt);
    WRITE_IF_PRESENT(fp, cfg, wpa_pairwise);
    WRITE_IF_PRESENT(fp, cfg, wpa_passphrase);
    WRITE_IF_PRESENT(fp, cfg, wpa_psk_file);
    WRITE_IF_PRESENT(fp, cfg, wps_pin_requests);
    WRITE_IF_PRESENT(fp, cfg, wps_state);

    fclose(fp);
    return 0;
}

