#ifndef PROXY_ENCRYPTER_HPP
#define PROXY_ENCRYPTER_HPP

#include <string>
#include <string_view>
#include <optional>
#include <variant>
#include <vector>
#include <map>
#include <cstdint>
#include <filesystem>

#include "http_request.hpp"
#include "http_response.hpp"
#include "http_client.hpp"

namespace proxy {

struct request_options {
    std::string key;
    int64_t     timestamp = 0;
    std::string path;
    std::map<std::string, std::string, std::less<>> headers;
    http::method method = http::method::get;
    std::variant<std::string, std::vector<http_form_part>> body;
};


class proxy_encrypter {
public:
    proxy_encrypter();
    ~proxy_encrypter() = default;

    proxy_encrypter(const proxy_encrypter&)            = delete;
    proxy_encrypter& operator=(const proxy_encrypter&) = delete;
    proxy_encrypter(proxy_encrypter&&)                 = default;
    proxy_encrypter& operator=(proxy_encrypter&&)      = default;

    void handle(const http::request& req, http::response& res);

protected:
    std::string key;
    bool        enable_encrypt       = false;
    bool        encrypt_sending_files = false;
    std::string backend_url;

private:
    // ── Decryption pipeline ──────────────────────────────────────────────────
    void decrypt_request  (const http::request& req,        request_options& out);
    void get_path_and_sign(std::string_view path,           request_options& out);
    void get_token        (std::optional<std::string_view>, request_options& out);
    void get_body_and_sign(std::string_view body,           request_options& out);

    // ── Body construction ────────────────────────────────────────────────────
    [[nodiscard]] std::variant<std::string, std::vector<http_form_part>>
    body_factory(std::string&& body_raw, std::string_view req_type);

    // ── Execution & response ─────────────────────────────────────────────────
    [[nodiscard]] http_response execute_request(request_options&& options);
    void encrypt_response(http::response& res, http_response&& server_response);
};

} // namespace proxy

#endif // PROXY_ENCRYPTER_HPP