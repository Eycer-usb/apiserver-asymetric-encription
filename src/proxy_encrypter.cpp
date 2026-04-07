#include "proxy_encrypter.hpp"
#include "logger.hpp"

ProxyEncrypter::ProxyEncrypter() 
    : key("clave_secreta"), 
      availableChars("abcdef0123456789"), 
      enableEncrypt(true), 
      encryptSendingFiles(false), 
      separator(":") 
{
    // Cuerpo del constructor (puede estar vacío)
}

void ProxyEncrypter::handleRequest(const http::request& req) {
    util::log::debug("Processing request...");
}

void ProxyEncrypter::handleResponse(const http::response& res) {
    util::log::debug("Processing response...");
    // res.set_body(http::status::ok, "Hello, World!");
}