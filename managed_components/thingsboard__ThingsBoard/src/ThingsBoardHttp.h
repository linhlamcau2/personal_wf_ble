/*
  ThingsBoardHttp.h - Library API for sending data to the ThingsBoard
  Based on PubSub MQTT library.
  Created by Olender M. Oct 2018.
  Released into the public domain.
*/
#ifndef ThingsBoard_Http_h
#define ThingsBoard_Http_h

// Local includes.
#include "Constants.h"
#include "Telemetry.h"
#include "Helper.h"
#include "IHTTP_Client.h"
#include "DefaultLogger.h"


// HTTP topics.
#if THINGSBOARD_ENABLE_PROGMEM
char constexpr HTTP_TELEMETRY_TOPIC[] PROGMEM = "/api/v1/%s/telemetry";
char constexpr HTTP_ATTRIBUTES_TOPIC[] PROGMEM = "/api/v1/%s/attributes";
char constexpr HTTP_POST_PATH[] PROGMEM = "application/json";
int constexpr HTTP_RESPONSE_SUCCESS_RANGE_START PROGMEM = 200;
int constexpr HTTP_RESPONSE_SUCCESS_RANGE_END PROGMEM = 299;
#else
char constexpr HTTP_TELEMETRY_TOPIC[] = "/api/v1/%s/telemetry";
char constexpr HTTP_ATTRIBUTES_TOPIC[] = "/api/v1/%s/attributes";
char constexpr HTTP_POST_PATH[] = "application/json";
int constexpr HTTP_RESPONSE_SUCCESS_RANGE_START = 200;
int constexpr HTTP_RESPONSE_SUCCESS_RANGE_END = 299;
#endif // THINGSBOARD_ENABLE_PROGMEM

// Log messages.
#if THINGSBOARD_ENABLE_PROGMEM
char constexpr POST[] PROGMEM = "POST";
char constexpr GET[] PROGMEM = "GET";
char constexpr HTTP_FAILED[] PROGMEM = "(%s) failed HTTP response (%d)";
#else
char constexpr POST[] = "POST";
char constexpr GET[] = "GET";
char constexpr HTTP_FAILED[] = "(%s) failed HTTP response (%d)";
#endif // THINGSBOARD_ENABLE_PROGMEM


#if THINGSBOARD_ENABLE_DYNAMIC
/// @brief Wrapper around the ArduinoHttpClient or HTTPClient to allow connecting and sending / retrieving data from ThingsBoard over the HTTP orHTTPS protocol.
/// BufferSize of the underlying data buffer as well as the maximum amount of data points that can ever be sent are either dynamic or can be changed during runtime.
/// If this feature is not needed and the values can be sent once as template arguements it is recommended to use the static ThingsBoard instance instead.
/// Simply set THINGSBOARD_ENABLE_DYNAMIC to 0, before including ThingsBoardHttp.h
/// @tparam Logger Implementation that should be used to print error messages generated by internal processes and additional debugging messages if THINGSBOARD_ENABLE_DEBUG is set, default = DefaultLogger
template <typename Logger = DefaultLogger>
#else
/// @brief Wrapper around the ArduinoHttpClient or HTTPClient to allow connecting and sending / retrieving data from ThingsBoard over the HTTP orHTTPS protocol.
/// BufferSize of the underlying data buffer as well as the maximum amount of data points that can ever be sent have to defined as template arguments.
/// Changing is only possible if a new instance of this class is created. If theese values should be changeable and dynamic instead.
/// Simply set THINGSBOARD_ENABLE_DYNAMIC to 1, before including ThingsBoardHttp.h.
/// @tparam MaxFieldsAmount Maximum amount of key value pair that we will be able to sent to ThingsBoard in one call, default = 8
/// @tparam Logger Implementation that should be used to print error messages generated by internal processes and additional debugging messages if THINGSBOARD_ENABLE_DEBUG is set, default = DefaultLogger
template<size_t MaxFieldsAmount = Default_Fields_Amount, typename Logger = DefaultLogger>
#endif // THINGSBOARD_ENABLE_DYNAMIC
class ThingsBoardHttpSized {
  public:
    /// @brief Initalizes the underlying client with the needed information
    /// so it can initally connect to the given host over the given port
    /// @param client Client that should be used to establish the connection
    /// @param logger Logger implementation that should be used to print messages generated by internal processes
    /// @param access_token Token used to verify the devices identity with the ThingsBoard server
    /// @param host Host server we want to establish a connection to (example: "demo.thingsboard.io")
    /// @param port Port we want to establish a connection over (80 for HTTP, 443 for HTTPS)
    /// @param keepAlive Attempts to keep the establishes TCP connection alive to make sending data faster
    /// @param maxStackSize Maximum amount of bytes we want to allocate on the stack, default = Default_Max_Stack_Size
    ThingsBoardHttpSized(IHTTP_Client & client, char const * const access_token, char const * const host, uint16_t const & port = 80U, bool keepAlive = true, size_t const & maxStackSize = Default_Max_Stack_Size)
      : m_client(client)
      , m_max_stack(maxStackSize)
      , m_token(access_token)
    {
        m_client.set_keep_alive(keepAlive);
        if (m_client.connect(host, port) != 0) {
            Logger::println(CONNECT_FAILED);
        }
    }

    /// @brief Sets the maximum amount of bytes that we want to allocate on the stack, before the memory is allocated on the heap instead
    /// @param maxStackSize Maximum amount of bytes we want to allocate on the stack
    void setMaximumStackSize(size_t const & maxStackSize) {
        m_max_stack = maxStackSize;
    }

    /// @brief Attempts to send key value pairs from custom source over the given topic to the server
    /// @tparam TSource Source class that should be used to serialize the json that is sent to the server
    /// @param topic Topic we want to send the data over
    /// @param source Data source containing our json key value pairs we want to send
    /// @param jsonSize Size of the data inside the source
    /// @return Whether sending the data was successful or not
    template <typename TSource>
    bool Send_Json(char const * const topic, TSource const & source, size_t const & jsonSize) {
        // Check if allocating needed memory failed when trying to create the JsonObject,
        // if it did the isNull() method will return true. See https://arduinojson.org/v6/api/jsonvariant/isnull/ for more information
        if (source.isNull()) {
            Logger::println(UNABLE_TO_ALLOCATE_JSON);
            return false;
        }
#if !THINGSBOARD_ENABLE_DYNAMIC
        size_t const amount = source.size();
        if (MaxFieldsAmount < amount) {
            Logger::printfln(TOO_MANY_JSON_FIELDS, amount, MaxFieldsAmount);
            return false;
        }
#endif // !THINGSBOARD_ENABLE_DYNAMIC
        bool result = false;
        if (getMaximumStackSize() < jsonSize) {
            char * json = new char[jsonSize]();
            if (serializeJson(source, json, jsonSize) < jsonSize - 1) {
                Logger::println(UNABLE_TO_SERIALIZE_JSON);
            }
            else {
                result = Send_Json_String(topic, json);
            }
            // Ensure to actually delete the memory placed onto the heap, to make sure we do not create a memory leak
            // and set the pointer to null so we do not have a dangling reference.
            delete[] json;
            json = nullptr;
        }
        else {
            char json[jsonSize] = {};
            if (serializeJson(source, json, jsonSize) < jsonSize - 1) {
                Logger::println(UNABLE_TO_SERIALIZE_JSON);
                return result;
            }
            result = Send_Json_String(topic, json);
        }
        return result;
    }

    /// @brief Attempts to send custom json string over the given topic to the server
    /// @param topic Topic we want to send the data over
    /// @param json String containing our json key value pairs we want to attempt to send
    /// @return Whether sending the data was successful or not
    bool Send_Json_String(char const * const topic, char const * const json) {
        if (json == nullptr || m_token == nullptr) {
            return false;
        }

        char path[Helper::detectSize(topic, m_token)] = {};
        (void)snprintf(path, sizeof(path), topic, m_token);
        return postMessage(path, json);
    }

    //----------------------------------------------------------------------------
    // Telemetry API

    /// @brief Attempts to send telemetry data with the given key and value of the given type.
    /// See https://thingsboard.io/docs/user-guide/telemetry/ for more information
    /// @tparam T Type of the passed value
    /// @param key Key of the key value pair we want to send
    /// @param value Value of the key value pair we want to send
    /// @return Whether sending the data was successful or not
    template<typename T>
    bool sendTelemetryData(char const * const key, T const & value) {
        return sendKeyValue(key, value);
    }

    /// @brief Attempts to send aggregated telemetry data, expects iterators to a container containing Telemetry class instances.
    /// See https://thingsboard.io/docs/user-guide/telemetry/ for more information
    /// @tparam InputIterator Class that points to the begin and end iterator
    /// of the given data container, allows for using / passing either std::vector or std::array.
    /// See https://en.cppreference.com/w/cpp/iterator/input_iterator for more information on the requirements of the iterator
    /// @param first Iterator pointing to the first element in the data container
    /// @param last Iterator pointing to the end of the data container (last element + 1)
    /// @return Whether sending the aggregated telemetry data was successful or not
    template<typename InputIterator>
    bool sendTelemetry(InputIterator const & first, InputIterator const & last) {
        return sendDataArray(first, last, true);
    }

    /// @brief Attempts to send custom json telemetry string.
    /// See https://thingsboard.io/docs/user-guide/telemetry/ for more information
    /// @param json String containing our json key value pairs we want to attempt to send
    /// @return Whetherr sending the data was successful or not
    bool sendTelemetryJson(char const * const json) {
        return Send_Json_String(HTTP_TELEMETRY_TOPIC, json);
    }

    /// @brief Attempts to send telemetry key value pairs from custom source to the server.
    /// See https://thingsboard.io/docs/user-guide/telemetry/ for more information
    /// @tparam TSource Source class that should be used to serialize the json that is sent to the server
    /// @param source Data source containing our json key value pairs we want to send
    /// @param jsonSize Size of the data inside the source
    /// @return Whether sending the data was successful or not
    template <typename TSource>
    bool sendTelemetryJson(TSource const & source, size_t const & jsonSize) {
        return Send_Json(HTTP_TELEMETRY_TOPIC, source, jsonSize);
    }

    /// @brief Attempts to send a GET request over HTTP or HTTPS
    /// @param path API path we want to get data from (example: /api/v1/$TOKEN/rpc)
    /// @param response String the GET response will be copied into,
    /// will not be changed if the GET request wasn't successful
    /// @return Whetherr sending the GET request was successful or not
#if THINGSBOARD_ENABLE_STL
    bool sendGetRequest(char const * const path, std::string & response) {
#else
    bool sendGetRequest(char const * const path, String& response) {
#endif // THINGSBOARD_ENABLE_STL
        return getMessage(path, response);
    }

    /// @brief Attempts to send a POST request over HTTP or HTTPS
    /// @param path API path we want to send data to (example: /api/v1/$TOKEN/attributes)
    /// @param json String containing our json key value pairs we want to attempt to send
    /// @return Whetherr sending the POST request was successful or not
    bool sendPostRequest(char const * const path, char const * const json) {
        return postMessage(path, json);
    }

    //----------------------------------------------------------------------------
    // Attribute API

    /// @brief Attempts to send attribute data with the given key and value of the given type.
    /// See https://thingsboard.io/docs/user-guide/attributes/ for more information
    /// @tparam T Type of the passed value
    /// @param key Key of the key value pair we want to send
    /// @param value Value of the key value pair we want to send
    /// @return Whether sending the data was successful or not
    template<typename T>
    bool sendAttributeData(char const * const key, T const & value) {
        return sendKeyValue(key, value, false);
    }

    /// @brief Attempts to send aggregated attribute data, expects iterators to a container containing Attribute class instances.
    /// See https://thingsboard.io/docs/user-guide/attributes/ for more information
    /// @tparam InputIterator Class that points to the begin and end iterator
    /// of the given data container, allows for using / passing either std::vector or std::array.
    /// See https://en.cppreference.com/w/cpp/iterator/input_iterator for more information on the requirements of the iterator
    /// @param first Iterator pointing to the first element in the data container
    /// @param last Iterator pointing to the end of the data container (last element + 1)
    /// @return Whether sending the aggregated attribute data was successful or not
    template<typename InputIterator>
    bool sendAttributes(InputIterator const & first, InputIterator const & last) {
        return sendDataArray(first, last, false);
    }

    /// @brief Attempts to send custom json attribute string.
    /// See https://thingsboard.io/docs/user-guide/attributes/ for more information
    /// @param json String containing our json key value pairs we want to attempt to send
    /// @return Whetherr sending the data was successful or not
    bool sendAttributeJson(char const * const json) {
        return Send_Json_String(HTTP_ATTRIBUTES_TOPIC, json);
    }

    /// @brief Attempts to send attribute key value pairs from custom source to the server.
    /// See https://thingsboard.io/docs/user-guide/attributes/ for more information
    /// @tparam TSource Source class that should be used to serialize the json that is sent to the server
    /// @param source Data source containing our json key value pairs we want to send
    /// @param jsonSize Size of the data inside the source
    /// @return Whether sending the data was successful or not
    template <typename TSource>
    bool sendAttributeJson(TSource const & source, size_t const & jsonSize) {
        return Send_Json(HTTP_ATTRIBUTES_TOPIC, source, jsonSize);
    }

  private:
    IHTTP_Client& m_client;     // HttpClient instance
    size_t        m_max_stack;  // Maximum stack size we allocate at once on the stack.
    char const    *m_token;     // Access token used to connect with

    /// @brief Returns the maximum amount of bytes that we want to allocate on the stack, before the memory is allocated on the heap instead
    /// @return Maximum amount of bytes we want to allocate on the stack
    size_t const & getMaximumStackSize() const {
        return m_max_stack;
    }

    /// @brief Clears any remaining memory of the previous conenction,
    /// and resets the TCP as well, if data is resend the TCP connection has to be re-established
    void clearConnection() {
        m_client.stop();
    }

    /// @brief Attempts to send a POST request over HTTP or HTTPS
    /// @param path API path we want to send data to (example: /api/v1/$TOKEN/attributes)
    /// @param json String containing our json key value pairs we want to attempt to send
    /// @return Whetherr sending the POST request was successful or not
    bool postMessage(char const * const path, char const * const json) {
        bool success = m_client.post(path, HTTP_POST_PATH, json) == 0;
        int const status = m_client.get_response_status_code();

        if (!success || status < HTTP_RESPONSE_SUCCESS_RANGE_START || status > HTTP_RESPONSE_SUCCESS_RANGE_END) {
            Logger::printfln(HTTP_FAILED, POST, status);
            success = false;
        }

        clearConnection();
        return success;
    }

    /// @brief Attempts to send a GET request over HTTP or HTTPS
    /// @param path API path we want to get data from (example: /api/v1/$TOKEN/rpc)
    /// @param response String the GET response will be copied into,
    /// will not be changed if the GET request wasn't successful
    /// @return Whetherr sending the GET request was successful or not
#if THINGSBOARD_ENABLE_STL
    bool getMessage(char const * const path, std::string& response) {
#else
    bool getMessage(char const * const path, String& response) {
#endif // THINGSBOARD_ENABLE_STL
        bool success = m_client.get(path);
        int const status = m_client.get_response_status_code();

        if (!success || status < HTTP_RESPONSE_SUCCESS_RANGE_START || status > HTTP_RESPONSE_SUCCESS_RANGE_END) {
            Logger::printfln(HTTP_FAILED, GET, status);
            success = false;
            goto cleanup;
        }

        response = m_client.get_response_body();

        cleanup:
        clearConnection();
        return success;
    }

    /// @brief Attempts to send aggregated attribute or telemetry data
    /// @tparam InputIterator Class that points to the begin and end iterator
    /// of the given data container, allows for using / passing either std::vector or std::array.
    /// See https://en.cppreference.com/w/cpp/iterator/input_iterator for more information on the requirements of the iterator
    /// @param first Iterator pointing to the first element in the data container
    /// @param last Iterator pointing to the end of the data container (last element + 1)
    /// @param telemetry Whether the data we want to send should be sent over the attribute or telemtry topic
    /// @return Whether sending the aggregated data was successful or not
    template<typename InputIterator>
    bool sendDataArray(InputIterator const & first, InputIterator const & last, bool telemetry) {
#if THINGSBOARD_ENABLE_DYNAMIC
        // String are const char* and therefore stored as a pointer --> zero copy, meaning the size for the strings is 0 bytes,
        // Data structure size depends on the amount of key value pairs passed.
        // See https://arduinojson.org/v6/assistant/ for more information on the needed size for the JsonDocument
        size_t const size = Helper::distance(first, last);
        TBJsonDocument jsonBuffer(JSON_OBJECT_SIZE(size));
#else
        StaticJsonDocument<JSON_OBJECT_SIZE(MaxFieldsAmount)> jsonBuffer;
#endif // !THINGSBOARD_ENABLE_DYNAMIC

        for (auto it = first; it != last; ++it) {
            auto const & data = *it;
            if (!data.SerializeKeyValue(jsonBuffer)) {
                Logger::println(UNABLE_TO_SERIALIZE);
                return false;
            }
        }

        return telemetry ? sendTelemetryJson(jsonBuffer, Helper::Measure_Json(jsonBuffer)) : sendAttributeJson(jsonBuffer, Helper::Measure_Json(jsonBuffer));
    }

    /// @brief Sends single key-value attribute or telemetry data in a generic way
    /// @tparam T Type of the passed value
    /// @param key Key of the key value pair we want to send
    /// @param val Value of the key value pair we want to send
    /// @param telemetry Whetherr the aggregated data is telemetry (true) or attribut (false)
    /// @return Whetherr sending the data was successful or not
    template<typename T>
    bool sendKeyValue(char const * const key, T value, bool telemetry = true) {
        Telemetry const t(key, value);
        if (t.IsEmpty()) {
            // Message is ignored and not sent at all.
            return false;
        }

        StaticJsonDocument<JSON_OBJECT_SIZE(1)> jsonBuffer;
        if (!t.SerializeKeyValue(jsonBuffer)) {
            Logger::printfln(UNABLE_TO_SERIALIZE);
            return false;
        }

        return telemetry ? sendTelemetryJson(jsonBuffer, Helper::Measure_Json(jsonBuffer)) : sendAttributeJson(jsonBuffer, Helper::Measure_Json(jsonBuffer));
    }
};

using ThingsBoardHttp = ThingsBoardHttpSized<>;

#endif // ThingsBoard_Http_h