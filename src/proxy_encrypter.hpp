#ifndef PROXY_ENCRYPTER
#define PROXY_ENCRYPTER

#include <string>
#include <utility>
#include "http_request.hpp"
#include "http_response.hpp"

class ProxyEncrypter {
public:
    ProxyEncrypter();
    ~ProxyEncrypter() = default;

    // Prohibimos copiar el objeto (ProxyEncrypter p2 = p1; -> ERROR)
    ProxyEncrypter(const ProxyEncrypter&) = delete;
    ProxyEncrypter& operator=(const ProxyEncrypter&) = delete;

    // Permitimos mover el objeto (ProxyEncrypter p2 = std::move(p1); -> OK)
    ProxyEncrypter(ProxyEncrypter&&) = default;
    ProxyEncrypter& operator=(ProxyEncrypter&&) = default;

    // Métodos de procesamiento
    // Cambiamos a recibir por referencia y devolver por valor (vía move)
    void handleRequest(const http::request& req);
    void handleResponse(const http::response& res);

protected:
    std::string key;
    std::string availableChars;
    bool enableEncrypt;
    bool encryptSendingFiles;
    std::string separator;
};

#endif