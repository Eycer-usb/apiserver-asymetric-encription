#include "proxy_encrypter.hpp"
#include "logger.hpp"
#include "aes_gcm.hpp"
#include "env.hpp"


namespace proxy {

const int8_t req_sign_delimiter_position = 112; // lenght from Encryption(key{100} + timestamp_b64{12}) = 112
const int8_t key_encrypted_length = 100;
const int8_t timestamp_b64_length = 12;
const int8_t req_type_spec_length = 68;

void trim_inplace(std::string_view& vista, std::string_view espacios = " \t\n\r\f\v") {
    // Quitar del principio (Left Trim)
    size_t inicio = vista.find_first_not_of(espacios);
    if (inicio == std::string_view::npos) {
        vista = ""; // Todo era espacio
        return;
    }
    vista.remove_prefix(inicio);

    // Quitar del final (Right Trim)
    size_t fin = vista.find_last_not_of(espacios);
    if (fin != std::string_view::npos) {
        vista.remove_suffix(vista.size() - fin - 1);
    }
}


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
        this->decrypt_request(req, options);
        const http_response response = this->execute_request(options);
        this->encrypt_response(res, response);
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
        std::visit([&](const auto& real_content){
            switch (options.method) {
                case http::method::get:
                    response = client.get(full_url, options.headers);
                    break;
                case http::method::post:
                    response = client.post(full_url, real_content, options.headers);
                    break;
                case http::method::put:
                    response = client.put(full_url, real_content, options.headers);
                    break;
                case http::method::patch:
                    response = client.patch(full_url, real_content, options.headers);
                    break;
                case http::method::options:
                    response = client.options(full_url, options.headers);
                    break;
                default:
                    util::log::error("Unsupported HTTP method: {}", static_cast<int>(options.method));
                    throw std::runtime_error("Unsupported HTTP method");
            }
        }, options.body);
        
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

void proxy_encrypter::decrypt_request(const http::request& req, request_options& options) {
    try {
        const std::string_view path = req.get_path();
        const std::optional<std::string_view> token_opt = req.get_bearer_token();
        const http::request_body& body_variant = req.get_body();
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
        
        try
        {
            this->get_path_and_sign(path, options);
            util::log::debug("New Path: {}", options.path);

          
            this->get_token(token_opt, options);
            this->get_body_and_sign(body_ptr, options);
            util::log::debug("New body: {}", options.body);

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

void proxy_encrypter::get_path_and_sign(std::string_view path, request_options& params){
        
    const std::string_view request_sign = path.substr(0, req_sign_delimiter_position);
    const std::string_view path_key_e = path.substr(req_sign_delimiter_position);

    // Timestamp
    const std::string_view time_key_e = std::string_view(aes_gcm::decrypt(request_sign, key));
    params.timestamp = aes_gcm::b64_to_timestamp(time_key_e.substr(0, timestamp_b64_length));
    
    // Path
    const std::string_view key_e = time_key_e.substr(timestamp_b64_length, key_encrypted_length);
    const std::string key = aes_gcm::decrypt(key_e, key);
    const std::string path_key = aes_gcm::decrypt(path_key_e, key);
    
    // Asignation
    params.key = aes_gcm::decrypt(path_key.substr(0, key_encrypted_length), key);
    params.body = path_key.substr(key_encrypted_length);
}


void proxy_encrypter::get_token(const std::optional<std::string_view> token, request_options& params){
    std::string_view key_t = params.key;
    if(!token.has_value()){
        return;
    }
    std::string token_dec = aes_gcm::decrypt(token.value(), key_t);
    params.key = aes_gcm::decrypt(token_dec.substr(0, key_encrypted_length), key);
    params.headers["Authorization"] = "Bearer " + token_dec.substr(key_encrypted_length);
}


void proxy_encrypter::get_body_and_sign(const std::string_view* body, request_options& params){
    std::string_view key_bs = params.key;
    const std::string_view req_type_and_key_e = aes_gcm::decrypt(body->substr(0, 260), key_bs); // lenght req_type_and_key_e = 168
    std::string_view req_type = req_type_and_key_e.substr(0, req_type_spec_length);
    trim_inplace(req_type);
    params.headers["Content-Type"] = req_type;
    std::string_view key_b = aes_gcm::decrypt(req_type_and_key_e.substr(req_type_spec_length), key);
    params.body = this->body_factory(aes_gcm::decrypt(body->substr(260), key_b), req_type);
}

std::string proxy_encrypter::body_factory(std::string body_raw, std::string_view req_type){
    if(req_type.compare("application/json")){
        // TODO: Parse json
    }
    else{
        // TODO Parse multipart-form-data

    }
}



void proxy_encrypter::encrypt_response(http::response& res, http_response server_response) {
    if (!this->enable_encrypt) return;
    res.set_body(http::status::ok, "Respuesta");
}
}