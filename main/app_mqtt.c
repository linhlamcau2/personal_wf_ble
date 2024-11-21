    #include "app_mqtt.h"

    #include <stdio.h>
    #include <stdint.h>
    #include <stddef.h>
    #include <string.h>
    #include "esp_wifi.h"
    #include "esp_system.h"
    #include "nvs_flash.h"
    #include "esp_event.h"
    #include "esp_netif.h"


    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
    #include "freertos/semphr.h"
    #include "freertos/queue.h"

    #include "lwip/sockets.h"
    #include "lwip/dns.h"
    #include "lwip/netdb.h"
    #include "certs.h"
    #include "esp_log.h"
    #include "mqtt_client.h"
    #include "esp_tls.h"
    #include "esp_crt_bundle.h"
    #include <sys/param.h>

    const char *TAG = "mqtts_example";
    static mqtt_data_pt_t mqtt_data_pt= NULL;
    
    static void log_error_if_nonzero(const char *message, int error_code)
    {
        if (error_code != 0) {
            ESP_LOGE(TAG, "Last error %s: 0x%x", message, error_code);
        }
    }

    esp_mqtt_client_handle_t client;
    static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
    {
        ESP_LOGD(TAG, "Event dispatched from event loop base=%s, event_id=%" PRIi32, base, event_id);
        esp_mqtt_event_handle_t event = event_data;
        client = event->client;
        int msg_id;
        switch ((esp_mqtt_event_id_t)event_id) {
        case MQTT_EVENT_CONNECTED:
            ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
            msg_id = esp_mqtt_client_subscribe(client,"v1/gateway/rpc", 0);
            ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d", msg_id);
            
            break;
        case MQTT_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
            break;
        case MQTT_EVENT_SUBSCRIBED:
            ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
            break;
        case MQTT_EVENT_UNSUBSCRIBED:
            ESP_LOGI(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
            break;
        case MQTT_EVENT_PUBLISHED:
            ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
            break;
        case MQTT_EVENT_DATA:
            ESP_LOGI(TAG, "MQTT_EVENT_DATA");
            printf("TOPIC=%.*s\r\n", event->topic_len, event->topic);
            printf("DATA=%.*s\r\n", event->data_len, event->data);
            event->data [event->data_len]='\0';
            mqtt_data_pt((uint8_t *) event->data,event->data_len);

        
            break;
        case MQTT_EVENT_ERROR:
            ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
            if (event->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT) {
                log_error_if_nonzero("reported from esp-tls", event->error_handle->esp_tls_last_esp_err);
                log_error_if_nonzero("reported from tls stack", event->error_handle->esp_tls_stack_err);
                log_error_if_nonzero("captured as transport's socket errno",  event->error_handle->esp_transport_sock_errno);
                ESP_LOGI(TAG, "Last errno string (%s)", strerror(event->error_handle->esp_transport_sock_errno));

            }
            break;
        default:
            ESP_LOGI(TAG, "Other event id:%d", event->event_id);
            break;
        }
    }
    void mqtt_data_pt_set_callback(void *cb){
        if (cb)
        {
        mqtt_data_pt=cb;
        }
        
    }
    void publish_state_to_mqtt(int onoff_state, uint16_t addr) {
    char payload[50]; 
    snprintf(payload, sizeof(payload), "{\"0x%04x\":{\"value\":\"%d\"}}", addr, onoff_state);

    esp_err_t ret = esp_mqtt_client_publish(client, "v1/gateway/attributes", payload, 0, 0, 0);
    if (ret < 0) {
        ESP_LOGE(TAG, "Failed to publish message: %s", esp_err_to_name(ret));
    } else {
        ESP_LOGI(TAG, "Message published successfully: %s", payload);
    }
}

    void mqtt_app_start(void)
    {
        const esp_mqtt_client_config_t mqtt_cfg = {
            .broker = {
                .address.hostname="172.20.10.4",
                .address.port=1883,
                // .verification.certificate=cert_bundle,
                // .address.transport=MQTT_TRANSPORT_OVER_SSL,  
                .address.transport=MQTT_TRANSPORT_OVER_TCP,  
            },
            .credentials={
                // .client_id="mqttx_d7bc6d9b",
                .username="Lh6Qmuvj4k4p1IMrrsLw", 
            } 
        }; 
        ESP_LOGI(TAG, "[APP] Free memory: %" PRIu32 " bytes", esp_get_free_heap_size());
        esp_mqtt_client_handle_t client = esp_mqtt_client_init(&mqtt_cfg);
        /* The last argument may be used to pass data to the event handler, in this example mqtt_event_handler */
        esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
        esp_mqtt_client_start(client);
    }


