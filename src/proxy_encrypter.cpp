#include "proxy_encrypter.hpp"
#include "logger.hpp"
#include "aes_gcm.hpp"
#include "env.hpp"

ProxyEncrypter::ProxyEncrypter() 
    : key(env::get<std::string>("AES_KEY", "")), // Ejemplo de llave Base64 de 32 bytes
      enableEncrypt(true), 
      encryptSendingFiles(false)
{
    // Nota: En producción, carga 'key' desde una variable de entorno o un vault.
}

void ProxyEncrypter::handleRequest(const http::request& req) {
    if (!enableEncrypt) return;

    try {
        std::string body = req.get_body();
        if (!body.empty()) {
            // Suponiendo que el cliente envía datos cifrados que el proxy debe leer
            // o que el proxy debe cifrar antes de enviar al servidor destino.
            std::string encrypted = aes_gcm::encrypt(body, key);
            req.set_body(encrypted);
            
            util::log::debug("Request body encrypted successfully.");
        }
    } catch (const std::exception& e) {
        util::log::error("Encryption error in request: " + std::string(e.what()));
    }
}

void ProxyEncrypter::handleResponse(const http::response& res) {
    if (!enableEncrypt) return;

    try {
        std::string encrypted_body = res.get_body();
        if (!encrypted_body.empty()) {
            // Desciframos la respuesta del servidor antes de entregarla al cliente
            std::string decrypted = aes_gcm::decrypt(encrypted_body, key);
            res.set_body(decrypted);
            
            util::log::debug("Response body decrypted successfully.");
        }
    } catch (const std::exception& e) {
        // Si el tag no coincide, aes_gcm lanzará una excepción aquí.
        util::log::error("Decryption error in response: " + std::string(e.what()));
        res.set_status(http::status::bad_request);
        res.set_body("Integrity check failed: Data tampered or wrong key.");
    }
}