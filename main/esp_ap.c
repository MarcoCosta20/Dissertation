/*  WiFi softAP Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"

#include "lwip/err.h"
#include "lwip/sys.h"
#include "esp_netif.h"
#include "esp_netif_types.h"
#include "lwip/ip_addr.h"
#include "esp_mac.h"

#define EXAMPLE_ESP_WIFI_SSID      "ESP32C6_AP"
#define EXAMPLE_ESP_WIFI_PASS      "MyPassword"
#define EXAMPLE_ESP_WIFI_CHANNEL   1
#define EXAMPLE_MAX_STA_CONN       5
#define WIFI_CHANNEL_MAX           13

static const char *TAG = "wifi softAP";

uint8_t mac_1[6] = {0x60, 0x55, 0xf9, 0xf7, 0x16, 0xa8};
uint8_t mac_2[6] = {0x60, 0x55, 0xf9, 0xf7, 0x21, 0x90};
uint8_t mac_3[6] = {0x60, 0x55, 0xf9, 0xf7, 0x2b, 0xbc};
uint8_t mac_4[6] = {0x60, 0x55, 0xf9, 0xf7, 0x16, 0xbc};

// Function to compare which device is connected to Access Point
int compare_mac(unsigned char *mac_comp){
    int sta_device = 0;
    if (memcmp(mac_comp, mac_1, 6) == 0) {
        sta_device = 1;
    }
    else if (memcmp(mac_comp, mac_2, 6) == 0) {
        sta_device = 2;
    }
    else if (memcmp(mac_comp, mac_3, 6) == 0) {
        sta_device = 3;
    }
    else if (memcmp(mac_comp, mac_4, 6) == 0) {
        sta_device = 4;
    }
    
    return sta_device;
}

void wifi_sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type)
{
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    wifi_pkt_rx_ctrl_t rx_ctrl = (wifi_pkt_rx_ctrl_t)pkt->rx_ctrl;
    
    uint8_t *src_addr = pkt->payload + 10;
    uint8_t *dst_addr = pkt->payload + 4;
    uint8_t *payload = pkt->payload + 24; // assuming a 18-byte header

    int sta_device = compare_mac(src_addr);

    if (sta_device && pkt->payload[24] == 0xAB) {     // pkt->payload[24] is the Tag Message 
        printf("\n** Device %d **\n", sta_device);
        // ESP_LOG_BUFFER_HEXDUMP(TAG, pkt->payload, pkt->rx_ctrl.sig_len, ESP_LOG_INFO);

        ESP_LOGI(TAG, "Received packet with RSSI %d dB", rx_ctrl.rssi);
        ESP_LOGI(TAG, "Received packet with NOISE FLOOR %d dBm", rx_ctrl.noise_floor);

        ESP_LOGI(TAG, "Source MAC address: %02X:%02X:%02X:%02X:%02X:%02X",
             src_addr[0], src_addr[1], src_addr[2], src_addr[3], src_addr[4], src_addr[5]);
        ESP_LOGI(TAG, "Destination MAC address: %02X:%02X:%02X:%02X:%02X:%02X",
                dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3], dst_addr[4], dst_addr[5]);

        // ESP_LOGI(TAG, "Payload (Hexadecimal):");
        // //Is "i< pkt.rx_ctrl.sig_len-4" because the transmitter add 4 bytes, that are the Frame Check Sequence (FCS)
        // for (int i = 26; i < pkt->rx_ctrl.sig_len-4; i++) {;
        //     printf("%02X ", pkt->payload[i]);
        // }
        // printf("\n");
        ESP_LOGI(TAG, "Payload (Decimal):");
        for (int i = 26; i < pkt->rx_ctrl.sig_len-4; i++) {;
            printf("%d ", pkt->payload[i] - pkt->payload[25]);
        }
        printf("\n");
    }
}

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                                    int32_t event_id, void* event_data)
{
    if (event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*) event_data;
        ESP_LOGI(TAG, "station: " MACSTR" join, AID=%d", MAC2STR(event->mac), event->aid);

    } else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*) event_data;
        ESP_LOGI(TAG, "station "MACSTR" leave, AID=%d", MAC2STR(event->mac), event->aid);
    }
}

void wifi_init_softap(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));

    wifi_config_t wifi_config = {
        .ap = {
            .ssid = EXAMPLE_ESP_WIFI_SSID,
            .ssid_len = strlen(EXAMPLE_ESP_WIFI_SSID),
            .channel = EXAMPLE_ESP_WIFI_CHANNEL,
            .password = EXAMPLE_ESP_WIFI_PASS,
            .max_connection = EXAMPLE_MAX_STA_CONN,
            .authmode = WIFI_AUTH_WPA_WPA2_PSK,
        },
    };
    if (strlen(EXAMPLE_ESP_WIFI_PASS) == 0) {
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));

    wifi_country_t wifi_country = {
        cc: "PT",
        schan: 1,
        nchan: WIFI_CHANNEL_MAX,
        max_tx_power: 100,
        policy: WIFI_COUNTRY_POLICY_AUTO,
    };
    
    esp_wifi_set_country(&wifi_country);
    esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N | WIFI_PROTOCOL_11AX);

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL, // Filter only data frames
    };

    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_callback));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "wifi_init_softap finished. SSID:%s password:%s channel:%d", EXAMPLE_ESP_WIFI_SSID, EXAMPLE_ESP_WIFI_PASS, EXAMPLE_ESP_WIFI_CHANNEL);
}

void app_main(void)
{
    //Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "ESP_WIFI_MODE_AP");

    wifi_init_softap();
}