#ifndef PROXY_ENCRYPTER
#define PROXY_ENCRYPTER

#include <string>
#include <utility>
#include "http_request.hpp"
#include "http_response.hpp"
#include "http_client.hpp"


namespace proxy {

    
struct request_options {
    std::string path;
    std::map<std::string, std::string, std::less<>> headers;
    http::method method;
    std::string body;
};

struct interlayer_parameters
{
    std::vector<uint8_t> positions;
    std::string key;
};


class proxy_encrypter {
public:
    proxy_encrypter();
    ~proxy_encrypter() = default;

    // Prohibimos copiar el objeto (ProxyEncrypter p2 = p1; -> ERROR)
    proxy_encrypter(const proxy_encrypter&) = delete;
    proxy_encrypter& operator=(const proxy_encrypter&) = delete;

    // Permitimos mover el objeto (ProxyEncrypter p2 = std::move(p1); -> OK)
    proxy_encrypter(proxy_encrypter&&) = default;
    proxy_encrypter& operator=(proxy_encrypter&&) = default;

    void handle(const http::request& req, http::response& res);


protected:
    std::string key;
    std::string availableChars;
    bool enable_encrypt;
    bool encrypt_sending_files;
    std::string separator;

private:
    void get_path(const std::string_view path, std::string& new_path, interlayer_parameters& params);
    void get_token(const std::optional<std::string_view> token, std::string& new_token, interlayer_parameters& params);
    void get_body(const std::string_view* body, std::string& new_body, interlayer_parameters& params);
    void handle_request(const http::request& req, request_options& out_options);
    void handle_response(http_response server_response, http::response& res);
    http_response execute_request(request_options options);
};

}
#endif