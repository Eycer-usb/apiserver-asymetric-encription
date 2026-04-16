#ifndef PROXY_ENCRYPTER
#define PROXY_ENCRYPTER

#include <string>
#include <utility>
#include "http_request.hpp"
#include "http_response.hpp"
#include "http_client.hpp"


namespace proxy {

    
struct request_options {
    std::string key;
    int64_t timestamp;
    std::string path;
    std::map<std::string, std::string, std::less<>> headers;
    http::method method;
    std::variant<std::string, http_form_file> body;
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
    void get_path_and_sign(const std::string_view path, request_options& params);
    void get_token(const std::optional<std::string_view> token, request_options& params);
    void get_body_and_sign(const std::string_view* body, request_options& params);
    void decrypt_request(const http::request& req, request_options& out_options);
    http_response execute_request(request_options options);
    void encrypt_response(http::response& res, http_response server_response);
    std::string proxy_encrypter::body_factory(std::string body_raw, std::string_view req_type);
};

}
#endif