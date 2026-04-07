#ifndef API_ROUTER_HPP
#define API_ROUTER_HPP

#include "http_request.hpp"
#include "http_response.hpp"
#include "input_validator.hpp"
#include "webapi_path.hpp"
#include <string_view>
#include <unordered_map>
#include <functional>
#include <memory>
#include <regex>

// A type alias for our API handler functions
using api_handler_func = std::function<void(const http::request&, http::response&)>;

// A type-erased wrapper for our validation logic
using validator_func = std::function<void(const http::request&)>;

/**
 * @struct api_endpoint
 * @brief Holds all the information for a registered API endpoint.
 */
struct api_endpoint {
    http::method method;
    validator_func validator;
    api_handler_func handler;
    bool is_secure;
    std::optional<std::regex> path_regex;
};

/**
 * @class api_router
 * @brief The central catalog for registering and looking up API endpoints.
 */
class api_router {
public:
    /**
     * @brief Registers a new API endpoint.
     * @tparam Validator The specific type of the validation::validator.
     * @param path The compile-time validated URI path.
     * @param method The required HTTP method for this endpoint.
     * @param v The validator instance for this endpoint.
     * @param handler The function to execute for this endpoint.
     * @param is_secure True if the endpoint requires authentication.
     */
    template<typename Validator>
    void register_api(webapi_path path, http::method method, const Validator& v, api_handler_func handler, bool is_secure = true) {
        validator_func vf = [v](const http::request& req) {
            v.validate(req);
        };
        m_routes[path.get()] = {method, std::move(vf), std::move(handler), is_secure, std::nullopt};
    }

    /**
     * @brief Registers an API endpoint that has no validation rules.
     */
    void register_api(webapi_path path, http::method method, api_handler_func handler, bool is_secure = true) {
        // Create a no-op validator for endpoints that do not require input validation.
        validator_func vf = [](const http::request&){
            // This lambda is intentionally empty as no validation is needed for this endpoint type.
        };
        m_routes[path.get()] = {method, std::move(vf), std::move(handler), is_secure, std::nullopt};
    }
    
    /**
     * @brief Registra un endpoint usando una expresión regular.
     */
    void register_api_regex(std::string pattern, http::method method, api_handler_func handler, bool is_secure = true) {
        validator_func vf = [](const http::request&){};
        
        // Guardamos en una estructura separada o marcamos el endpoint
        m_regex_routes.push_back({
            std::regex(pattern, std::regex::optimize), 
            {method, std::move(vf), std::move(handler), is_secure, std::regex(pattern)}
        });
    }

    /**
     * @brief Finds the handler for a given request path.
     * @param path The path from an incoming http::request.
     * @return A pointer to the api_endpoint if found, otherwise nullptr.
     */
    [[nodiscard]] const api_endpoint* find_handler(std::string_view path) const {
        // 1. Intentar búsqueda exacta (O(1)) para máxima velocidad
        if (auto it = m_routes.find(path); it != m_routes.end()) {
            return &it->second;
        }

        // 2. Si no hay match exacto, buscar en rutas regex (O(N))
        std::string path_str(path);
        for (const auto& [re, endpoint] : m_regex_routes) {
            if (std::regex_match(path_str, re)) {
                return &endpoint;
            }
        }
        return nullptr;
    }

private:
    // NOTE: The key is string_view, which is efficient but assumes the lifetime
    // of the path string is managed externally (which is true for webapi_path).
    std::unordered_map<std::string_view, api_endpoint> m_routes;

    // Almacenamos el regex compilado y su endpoint asociado
    std::vector<std::pair<std::regex, api_endpoint>> m_regex_routes;
};

#endif // API_ROUTER_HPP
