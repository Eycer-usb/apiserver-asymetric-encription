#include "proxy_encrypter.hpp"
#include "logger.hpp"
#include "aes_gcm.hpp"
#include "env.hpp"
#include "json.hpp"

#include <chrono>
#include <fstream>
#include <filesystem>
#include <stdexcept>

namespace proxy {

// ─────────────────────────────────────────────────────────────────────────────
//  Constantes (size_t evita comparaciones signed/unsigned)
// ─────────────────────────────────────────────────────────────────────────────
// Tamaños verificados contra la salida real de aes_gcm::encrypt():
//
//  encrypt(44-char key,       key) → base64(1+12+16+44)  = base64(73)  = 100 chars  ✓
//  encrypt(112-char time_key, key) → base64(1+12+16+112) = base64(141) = 188 chars
//  encrypt(168-char type+key, key) → base64(1+12+16+168) = base64(197) = 264 chars
//
static constexpr size_t kReqSignDelimiter  = 188;   // era 112 → corregido
static constexpr size_t kKeyEncryptedLen   = 100;
static constexpr size_t kTimestampB64Len   =  12;
static constexpr size_t kReqTypeSpecLen    =  68;
static constexpr size_t kReqTypeAndKeyLen  = 264;   // era 260 → corregido

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers internos (sin linkage externo)
// ─────────────────────────────────────────────────────────────────────────────
namespace {

void trim_inplace(std::string_view& sv,
                  std::string_view  chars = " \t\n\r\f\v") noexcept
{
    const size_t first = sv.find_first_not_of(chars);
    if (first == std::string_view::npos) { sv = {}; return; }
    sv.remove_prefix(first);
    sv.remove_suffix(sv.size() - sv.find_last_not_of(chars) - 1);
}

// Decodifica base64 → bytes usando el decoder ya presente en aes_gcm
std::vector<uint8_t> b64_to_bytes(std::string_view b64)
{
    std::vector<uint8_t> out(aes_gcm::detail::b64_dec_max(b64.size()));
    const size_t n = aes_gcm::detail::b64_decode_into(b64.data(), b64.size(), out.data());
    out.resize(n);
    return out;
}

// Escribe bytes en un archivo temporal; devuelve la ruta
std::filesystem::path write_tmp_file(std::string_view fname,
                                     int64_t          last_modified,
                                     const uint8_t*   data,
                                     size_t           size)
{
    auto path = std::filesystem::temp_directory_path()
                / (std::to_string(last_modified) + '_' + std::string(fname));

    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs)
        throw std::runtime_error("proxy: no se pudo crear temporal: " + path.string());

    ofs.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
    return path;
}

} // anonymous namespace

// ─────────────────────────────────────────────────────────────────────────────
//  Constructor
// ─────────────────────────────────────────────────────────────────────────────
proxy_encrypter::proxy_encrypter()
    : key                 (env::get<std::string>("AES_KEY",              ""))
    , enable_encrypt      (env::get<bool>       ("ENCRYPT_ENABLE",       true))
    , encrypt_sending_files(env::get<bool>      ("ENCRYPT_FILES_ENABLE", false))
    , backend_url         (env::get<std::string>("BACKEND_URL",          "http://localhost:8080"))
{}


// ─────────────────────────────────────────────────────────────────────────────
//  handle — entry point
// ─────────────────────────────────────────────────────────────────────────────
void proxy_encrypter::handle(const http::request& req, http::response& res)
{
    if (!enable_encrypt) return;
    try {
        request_options options;
        decrypt_request(req, options);
        http_response response = execute_request(std::move(options));
        encrypt_response(res, std::move(response));
    } catch (const std::exception& e) {
        util::log::error("Error handling request in proxy encripter: {}", e.what());
        res.set_body(http::status::bad_request, "Request Error");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  execute_request  — recibe options por move, sin copia
// ─────────────────────────────────────────────────────────────────────────────
http_response proxy_encrypter::execute_request(request_options&& options)
{
    // Construir URL
    std::string url = std::move(backend_url); // temporal local, no modifica miembro
    // (backend_url es miembro; para no modificarlo hacemos copia solo del string)
    url = backend_url;
    if (!options.path.empty()) {
        if (!url.empty() && url.back() == '/') url.pop_back();
        if (options.path.front() != '/')       url += '/';
        url += options.path;   // options.path ya no se necesita después
    }

    util::log::debug("execute_request → {} (method={})", url, static_cast<int>(options.method));

    http_client client;

    auto dispatch = [&](auto&& body_arg) -> http_response {
        using B = std::decay_t<decltype(body_arg)>;
        switch (options.method) {
            case http::method::get:
                return client.get    (url, options.headers);
            case http::method::post:
                return client.post   (url, std::forward<B>(body_arg), options.headers);
            case http::method::put:
                return client.put    (url, std::forward<B>(body_arg), options.headers);
            case http::method::patch:
                return client.patch  (url, std::forward<B>(body_arg), options.headers);
            case http::method::options:
                return client.options(url, options.headers);
            default:
                throw std::runtime_error("execute_request: método HTTP no soportado");
        }
    };

    http_response response = std::visit(
        [&](auto&& body) { return dispatch(std::forward<decltype(body)>(body)); },
        std::move(options.body)   // move el variant completo
    );

    util::log::debug("execute_request ← status {}", response.status_code);
    return response;
}

// ─────────────────────────────────────────────────────────────────────────────
//  decrypt_request
// ─────────────────────────────────────────────────────────────────────────────
void proxy_encrypter::decrypt_request(const http::request& req, request_options& options)
{
    const std::string_view path      = req.get_path();
    const auto             token_opt = req.get_bearer_token();
    const auto&            body_var  = req.get_body();
    const auto*            body_ptr  = std::get_if<std::string_view>(&body_var);

    util::log::debug("path={}  token={}", path, token_opt.value_or("n/a"));

    if (path.empty()) {
        util::log::warn("decrypt_request: path vacío");
        return;
    }

    try {
        get_path_and_sign(path, options);
        util::log::debug("new path={}", options.path);

        get_token(token_opt, options);

        if (body_ptr && !body_ptr->empty())
            get_body_and_sign(*body_ptr, options);

        options.method = req.get_method();
    } catch (const std::exception& e) {
        util::log::warn("decrypt_request: fallback a recursos originales ({})", e.what());
        throw e;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  get_path_and_sign
// ─────────────────────────────────────────────────────────────────────────────
void proxy_encrypter::get_path_and_sign(std::string_view path, request_options& p)
{
    const std::string_view sign_enc   = path.substr(0, kReqSignDelimiter);
    const std::string_view path_key_e = path.substr(kReqSignDelimiter);

    // Descifrar firma → "timestamp_b64 (12) | key_e (100)"
    const std::string time_key = aes_gcm::decrypt(sign_enc, key);
    if (time_key.size() < kTimestampB64Len + kKeyEncryptedLen)
        throw std::runtime_error("get_path_and_sign: firma demasiado corta");

    p.timestamp = aes_gcm::b64_to_timestamp(
        std::string_view(time_key).substr(0, kTimestampB64Len));

    // Descifrar clave de sesión (variable local, nombre distinto al miembro)
    const std::string session_key = aes_gcm::decrypt(
        std::string_view(time_key).substr(kTimestampB64Len, kKeyEncryptedLen), key);

    // Descifrar path+key con la clave de sesión
    const std::string path_and_key = aes_gcm::decrypt(path_key_e, session_key);
    if (path_and_key.size() < kKeyEncryptedLen)
        throw std::runtime_error("get_path_and_sign: path+key demasiado corto");

    p.key  = aes_gcm::decrypt(
        std::string_view(path_and_key).substr(0, kKeyEncryptedLen), session_key);
    p.path = path_and_key.substr(kKeyEncryptedLen);
}

// ─────────────────────────────────────────────────────────────────────────────
//  get_token
// ─────────────────────────────────────────────────────────────────────────────
void proxy_encrypter::get_token(std::optional<std::string_view> token,
                                request_options& p)
{
    if (!token.has_value()) return;

    const std::string token_dec = aes_gcm::decrypt(token.value(), p.key);
    if (token_dec.size() < kKeyEncryptedLen)
        throw std::runtime_error("get_token: token descifrado demasiado corto");

    p.key = aes_gcm::decrypt(
        std::string_view(token_dec).substr(0, kKeyEncryptedLen), key);
    p.headers["Authorization"] = "Bearer " + token_dec.substr(kKeyEncryptedLen);
}

// ─────────────────────────────────────────────────────────────────────────────
//  get_body_and_sign
//  Recibe string_view directo en lugar de puntero
// ─────────────────────────────────────────────────────────────────────────────
void proxy_encrypter::get_body_and_sign(std::string_view body, request_options& p)
{
    // Primera parte: tipo de contenido + clave de body (primeros 260 chars cifrados)
    const std::string type_and_key = aes_gcm::decrypt(body.substr(0, kReqTypeAndKeyLen), p.key);
    if (type_and_key.size() < kReqTypeSpecLen)
        throw std::runtime_error("get_body_and_sign: cabecera demasiado corta");

    std::string_view req_type = std::string_view(type_and_key).substr(0, kReqTypeSpecLen);
    trim_inplace(req_type);
    p.headers["Content-Type"] = std::string(req_type);

    // Descifrar clave del body
    const std::string body_key = aes_gcm::decrypt(
        std::string_view(type_and_key).substr(kReqTypeSpecLen), key);

    // Descifrar body real y construir variant (move, sin copia extra)
    p.body = body_factory(
        aes_gcm::decrypt(body.substr(kReqTypeAndKeyLen), body_key),
        req_type);
}

// ─────────────────────────────────────────────────────────────────────────────
//  body_factory
//  body_raw se recibe por move — cero copias cuando es application/json
// ─────────────────────────────────────────────────────────────────────────────
std::variant<std::string, std::vector<http_form_part>>
proxy_encrypter::body_factory(std::string&& body_raw, std::string_view req_type)
{
    if (req_type == "application/json")
        return std::move(body_raw);   // cero copias

    using json = nlohmann::json;
    const json j = json::parse(body_raw);  // parse desde string existente, sin copia

    std::vector<http_form_part> parts;
    parts.reserve(j.size());

    for (const auto& item : j) {
        if (!item.contains("name"))
            throw std::runtime_error("body_factory: parte sin campo 'name'");

        http_form_part part;
        part.name = item.at("name").get<std::string>();

        // ── ARCHIVO: tiene "content" (base64) + "mimeType" ───────────────────
        if (item.contains("content") && item.contains("mimeType")) {
            const auto&  b64_val  = item.at("content");
            const std::string_view b64 = b64_val.get_ref<const std::string&>();

            auto bytes = b64_to_bytes(b64);

            const std::string fname = item.value("originalName", part.name);
            const int64_t     lm    = item.value("lastModified",  int64_t{0});

            auto tmp = write_tmp_file(fname, lm, bytes.data(), bytes.size());

            http_form_file ff;
            ff.file_path    = tmp.string();
            ff.content_type = item.at("mimeType").get<std::string>();
            part.contents   = std::move(ff);
        }
        // ── OBJETO JSON arbitrario ────────────────────────────────────────────
        else if (item.contains("object")) {
            part.contents = item.at("object").dump();   // serializa compacto
        }
        // ── VALOR SIMPLE (string / número / bool) ─────────────────────────────
        else if (item.contains("value")) {
            const auto& v = item.at("value");
            part.contents = v.is_string() ? v.get<std::string>() : v.dump();
        }
        else {
            throw std::runtime_error(
                "body_factory: parte '" + part.name +
                "' sin 'content'+'mimeType', 'object' ni 'value'");
        }

        parts.push_back(std::move(part));
    }

    return parts;
}

// ─────────────────────────────────────────────────────────────────────────────
//  encrypt_response
// ─────────────────────────────────────────────────────────────────────────────
void proxy_encrypter::encrypt_response(http::response& res,
                                       http_response&& server_response)
{
    if (!enable_encrypt) return;
    // TODO: cifrar server_response.body y headers antes de devolver
    res.set_body(http::status::ok, std::move(server_response.body));
}

} // namespace proxy