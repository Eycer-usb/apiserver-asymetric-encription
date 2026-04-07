#include "server.hpp"
#include "logger.hpp"
#include "webapi_path.hpp"
#include "sql.hpp"
#include "input_validator.hpp"
#include "util.hpp"
#include "json_parser.hpp"
#include "jwt.hpp"
#include "http_client.hpp"
#include "otp.hpp" 
#include "mfa.hpp" // for TOTP validation handler
#include "restclient.hpp" // for  get_remote_customer() API handler
#include <functional>
#include <algorithm> 
#include <chrono>
#include <filesystem>
#include <fstream>
#include <cctype>
#include <string_view> 
#include <ranges>


// Use namespaces to make code less verbose
using namespace validation;
using enum http::status;
using enum http::method;

// --- Custom Exception for File Operations ---
class file_system_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};





int main() {
    try {
        util::log::info("Application starting...");
        server s;
        s.register_api_regex("/.*", http::method::any, [](const http::request& req, http::response& res) {
            util::log::debug("Processing request...");
            
            const auto& body = req.get_body();
            if (const auto* body_sv = std::get_if<std::string_view>(&body); body_sv && !body_sv->empty()) {
                res.set_body(ok, std::string(*body_sv));
            } else {
                res.set_body(ok, R"({})");
            }
        },
        false
        );

        s.start();

        util::log::info("Application shutting down gracefully.");

    } catch (const file_system_error& e) {
        util::log::critical("A critical file system error occurred: {}", e.what());
        return 1;
    } catch (const server_error& e) {
        util::log::critical("A critical server error occurred: {}", e.what());
        return 1;
    } catch (const std::exception& e) {
        util::log::critical("An unexpected error occurred: {}", e.what());
        return 1;
    } catch (...) {
        util::log::critical("An unknown error occurred.");
        return 1;
    }

    return 0;
}