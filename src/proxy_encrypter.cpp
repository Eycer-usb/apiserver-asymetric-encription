#include "proxy_encrypter.hpp"
#include "logger.hpp"
#include "aes_gcm.hpp"
#include "env.hpp"


namespace proxy {
    
proxy_encrypter::proxy_encrypter() 
    : key(env::get<std::string>("AES_KEY", "")), // Ejemplo de llave Base64 de 32 bytes
      enable_encrypt(env::get<bool>("ENCRYPT_ENABLE", true)),
      encrypt_sending_files(env::get<bool>("ENCRYPT_FILES_ENABLE", false))
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
        const http_response response = this->execute_request(options);
        this->handle_response(response, res);
    }
    catch(const std::exception& e)
    {
        util::log::debug("Error processing request");
    }
    
}

http_response proxy_encrypter::execute_request(request_options options) {
    try {
        // Get the backend URL from environment variables
        const std::string backend_url = env::get<std::string>("BACKEND_URL", "http://localhost:8080");
        
        // Construct the full URL
        std::string full_url = backend_url;
        if (!options.path.empty()) {
            // Ensure proper URL formatting
            if (!full_url.empty() && full_url.back() == '/') {
                full_url.pop_back(); // Remove trailing slash from base URL
            }
            if (!options.path.empty() && options.path[0] != '/') {
                full_url += '/';
            }
            full_url += options.path;
        }
        
        util::log::debug("Executing request to: {}", full_url);
        util::log::debug("Method: {}", static_cast<int>(options.method));
        
        // Create HTTP client with default configuration
        http_client client;
        
        // Execute the request based on the HTTP method
        http_response response;
        switch (options.method) {
            case http::method::get:
                response = client.get(full_url, options.headers);
                break;
            case http::method::post:
                response = client.post(full_url, options.body, options.headers);
                break;
            case http::method::put:
                response = client.put(full_url, options.body, options.headers);
                break;
            case http::method::patch:
                response = client.patch(full_url, options.body, options.headers);
                break;
            case http::method::options:
                response = client.options(full_url, options.headers);
                break;
            default:
                util::log::error("Unsupported HTTP method: {}", static_cast<int>(options.method));
                throw std::runtime_error("Unsupported HTTP method");
        }
        
        util::log::debug("Request completed with status: {}", response.status_code);
        
        return response;
        
    } catch (const curl_exception& e) {
        util::log::error("CURL error in execute_request: {}", e.what());
        throw;
    } catch (const std::exception& e) {
        util::log::error("Error in execute_request: {}", e.what());
        throw;
    }
}

void proxy_encrypter::handle_request(const http::request& req, request_options& options) {
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

        
        try
        {
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
        }
        catch(const std::exception& e)
        {
            // Continue with original resources
            util::log::debug("Continue with original resources");
            // TODO
        }
        

    } catch (const std::exception& e) {
        util::log::error("Encryption error in request: {}", e.what());
        throw e;
    }
}

void proxy_encrypter::get_path(std::string_view path, std::string& new_path, interlayer_parameters& params){}
void proxy_encrypter::get_token(const std::optional<std::string_view> token, std::string& new_token, interlayer_parameters& params){}
void proxy_encrypter::get_body(const std::string_view* body, std::string& new_body, interlayer_parameters& params){}


void proxy_encrypter::handle_response(http_response server_response, http::response& res) {
    if (!this->enable_encrypt) return;
    res.set_body(http::status::ok, "Respuesta");
}
}