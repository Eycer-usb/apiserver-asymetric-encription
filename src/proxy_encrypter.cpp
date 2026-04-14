#include "proxy_encrypter.hpp"
#include "logger.hpp"
#include "aes_gcm.hpp"
#include "env.hpp"


namespace proxy {
    
proxy_encrypter::proxy_encrypter() 
    : key(env::get<std::string>("AES_KEY", "")), // Ejemplo de llave Base64 de 32 bytes
      enable_encrypt(true), 
      encrypt_sending_files(false)
{
    // Nota: En producción, carga 'key' desde una variable de entorno o un vault.
}

// Entry point for proxy
void proxy_encrypter::handle(const http::request& req, http::response& res) {
    if (!enable_encrypt) return;
    try
    {
        request_options options;
        this->handle_request(req, options);
    }
    catch(const std::exception& e)
    {
        util::log::debug("Error processing request decryption");
    }
    
    
}

void proxy::proxy_encrypter::handle_request(const http::request& req, request_options& options) {
    try {
        const std::string_view path = req.get_path();
        const auto token_opt = req.get_bearer_token();
        const auto& body_variant = req.get_body();
        const std::string_view* body_ptr = std::get_if<std::string_view>(&body_variant);

        util::log::debug("Original Path: {}", path);
        util::log::debug("Original Token: {}", token_opt.value_or("n/a"));
        
        if (body_ptr) {
            util::log::debug("Original Body: {}", *body_ptr);
        }

        if (path.empty()) {
            util::log::warn("Invalid Request: Path is empty");
            return; 
        }

        interlayer_parameters inter_params;

        
        this->get_path(path, options.path, inter_params);
        util::log::debug("New Path: {}", options.path);

        // Para el token, extraemos el valor del opcional o un string vacío
        this->get_token(token_opt, options.headers["Authorization"], inter_params);
        
        // Si el token fue procesado, le añadimos el prefijo Bearer
        if (!options.headers["Authorization"].empty()) {
            options.headers["Authorization"] = std::format("Bearer {}", options.headers["Authorization"]);
        }

        if (body_ptr) {
            this->get_body(body_ptr, options.body, inter_params);
            util::log::debug("New body: {}", options.body);
        }

        // 4. Sincronizar el método original
        options.method = req.get_method();

    } catch (const std::exception& e) {
        // En C++20 no necesitas std::string(e.what()), el formateador lo reconoce
        util::log::error("Encryption error in request: {}", e.what());
    }
}

void proxy_encrypter::get_path(std::string_view path, std::string& new_path, interlayer_parameters& params){}
void proxy_encrypter::get_token(const std::optional<std::string_view> token, std::string& new_token, interlayer_parameters& params){}
void proxy_encrypter::get_body(const std::string_view* body, std::string& new_body, interlayer_parameters& params){}


void proxy_encrypter::handle_response(http_response server_response, http::response& res) {
    if (!this->enable_encrypt) return;

    // try {
    //     std::string encrypted_body = res.get_body();
    //     if (!encrypted_body.empty()) {
    //         // Desciframos la respuesta del servidor antes de entregarla al cliente
    //         std::string decrypted = aes_gcm::decrypt(encrypted_body, key);
    //         res.set_body(decrypted);
            
    //         util::log::debug("Response body decrypted successfully.");
    //     }
    // } catch (const std::exception& e) {
    //     // Si el tag no coincide, aes_gcm lanzará una excepción aquí.
    //     util::log::error("Decryption error in response: " + std::string(e.what()));
    //     res.set_status(http::status::bad_request);
    //     res.set_body("Integrity check failed: Data tampered or wrong key.");
    // }
}
}