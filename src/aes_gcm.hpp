#pragma once

#include <string>
#include <vector>
#include <stdexcept>
#include <array>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>

/**
 * @brief AES-256-GCM encryption/decryption utilities.
 *
 * Format of the encrypted output (binary, then base64-encoded):
 *   [ IV (12 bytes) | TAG (16 bytes) | CIPHERTEXT (N bytes) ]
 *
 * Usage:
 *   std::string key = aes_gcm::generate_key();   // generate once, store securely
 *   std::string enc = aes_gcm::encrypt("hello", key);
 *   std::string dec = aes_gcm::decrypt(enc, key);
 */
namespace aes_gcm {

    // Tamaños fijos del algoritmo
    static constexpr int KEY_SIZE = 32;   // AES-256 → 32 bytes
    static constexpr int IV_SIZE  = 12;   // GCM recomienda 96 bits (12 bytes)
    static constexpr int TAG_SIZE = 16;   // Tag de autenticación GCM: 128 bits

    // -------------------------------------------------------------------------
    // Helpers internos: base64
    // -------------------------------------------------------------------------
    namespace detail {

        static const std::string B64_CHARS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        inline std::string base64_encode(const uint8_t* data, size_t len) {
            std::string out;
            out.reserve(((len + 2) / 3) * 4);
            for (size_t i = 0; i < len; i += 3) {
                uint32_t b = static_cast<uint32_t>(data[i]) << 16;
                if (i + 1 < len) b |= static_cast<uint32_t>(data[i + 1]) << 8;
                if (i + 2 < len) b |= data[i + 2];
                out += B64_CHARS[(b >> 18) & 0x3F];
                out += B64_CHARS[(b >> 12) & 0x3F];
                out += (i + 1 < len) ? B64_CHARS[(b >> 6) & 0x3F] : '=';
                out += (i + 2 < len) ? B64_CHARS[b & 0x3F]        : '=';
            }
            return out;
        }

        inline std::vector<uint8_t> base64_decode(const std::string& in) {
            auto is_b64 = [](unsigned char c) {
                return std::isalnum(c) || c == '+' || c == '/';
            };
            std::vector<uint8_t> out;
            out.reserve((in.size() / 4) * 3);
            int val = 0, bits = -8;
            for (unsigned char c : in) {
                if (c == '=') break;
                if (!is_b64(c)) throw std::invalid_argument("Invalid base64 character");
                size_t pos = B64_CHARS.find(c);
                val = (val << 6) + static_cast<int>(pos);
                bits += 6;
                if (bits >= 0) {
                    out.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
                    bits -= 8;
                }
            }
            return out;
        }

    } // namespace detail

    // -------------------------------------------------------------------------
    // generate_key()
    // Genera una clave AES-256 aleatoria y la retorna en base64.
    // Guárdala de forma segura (variable de entorno cifrada, Kubernetes secret, etc.)
    // -------------------------------------------------------------------------
    inline std::string generate_key() {
        std::array<uint8_t, KEY_SIZE> key{};
        if (RAND_bytes(key.data(), KEY_SIZE) != 1)
            throw std::runtime_error("aes_gcm: RAND_bytes failed generating key");
        return detail::base64_encode(key.data(), KEY_SIZE);
    }

    // -------------------------------------------------------------------------
    // encrypt(plaintext, key_b64) → ciphertext en base64
    //
    // @param plaintext  Texto plano a cifrar (std::string, puede ser binario)
    // @param key_b64    Clave AES-256 en base64 (32 bytes → 44 chars b64)
    // @return           IV + TAG + CIPHERTEXT codificado en base64
    // -------------------------------------------------------------------------
    inline std::string encrypt(const std::string& plaintext, const std::string& key_b64) {
        // Decodificar clave
        auto key_bytes = detail::base64_decode(key_b64);
        if (key_bytes.size() != KEY_SIZE)
            throw std::invalid_argument("aes_gcm: key must be 32 bytes (AES-256)");

        // Generar IV aleatorio
        std::array<uint8_t, IV_SIZE> iv{};
        if (RAND_bytes(iv.data(), IV_SIZE) != 1)
            throw std::runtime_error("aes_gcm: RAND_bytes failed generating IV");

        // Cifrar
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("aes_gcm: EVP_CIPHER_CTX_new failed");

        // RAII guard para el contexto
        struct CtxGuard {
            EVP_CIPHER_CTX* c;
            ~CtxGuard() { EVP_CIPHER_CTX_free(c); }
        } guard{ctx};

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                               key_bytes.data(), iv.data()) != 1)
            throw std::runtime_error("aes_gcm: EncryptInit failed");

        std::vector<uint8_t> ciphertext(plaintext.size());
        int out_len = 0;

        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len,
                              reinterpret_cast<const uint8_t*>(plaintext.data()),
                              static_cast<int>(plaintext.size())) != 1)
            throw std::runtime_error("aes_gcm: EncryptUpdate failed");

        int final_len = 0;
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &final_len) != 1)
            throw std::runtime_error("aes_gcm: EncryptFinal failed");

        ciphertext.resize(out_len + final_len);

        // Extraer tag de autenticación
        std::array<uint8_t, TAG_SIZE> tag{};
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data()) != 1)
            throw std::runtime_error("aes_gcm: GET_TAG failed");

        // Ensamblar: IV | TAG | CIPHERTEXT
        std::vector<uint8_t> blob;
        blob.reserve(IV_SIZE + TAG_SIZE + ciphertext.size());
        blob.insert(blob.end(), iv.begin(),         iv.end());
        blob.insert(blob.end(), tag.begin(),        tag.end());
        blob.insert(blob.end(), ciphertext.begin(), ciphertext.end());

        return detail::base64_encode(blob.data(), blob.size());
    }

    // -------------------------------------------------------------------------
    // decrypt(ciphertext_b64, key_b64) → plaintext original
    //
    // @param ciphertext_b64  Salida de encrypt() (base64)
    // @param key_b64         La misma clave usada al cifrar (base64)
    // @return                Texto plano original
    // @throws std::runtime_error si el tag de autenticación no coincide (datos alterados)
    // -------------------------------------------------------------------------
    inline std::string decrypt(const std::string& ciphertext_b64, const std::string& key_b64) {
        auto key_bytes = detail::base64_decode(key_b64);
        if (key_bytes.size() != KEY_SIZE)
            throw std::invalid_argument("aes_gcm: key must be 32 bytes (AES-256)");

        auto blob = detail::base64_decode(ciphertext_b64);
        if (blob.size() < static_cast<size_t>(IV_SIZE + TAG_SIZE))
            throw std::invalid_argument("aes_gcm: ciphertext too short");

        // Separar IV, TAG y datos cifrados
        std::array<uint8_t, IV_SIZE>  iv{};
        std::array<uint8_t, TAG_SIZE> tag{};
        std::memcpy(iv.data(),  blob.data(),             IV_SIZE);
        std::memcpy(tag.data(), blob.data() + IV_SIZE,   TAG_SIZE);

        const uint8_t* enc_data = blob.data() + IV_SIZE + TAG_SIZE;
        int enc_len = static_cast<int>(blob.size() - IV_SIZE - TAG_SIZE);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("aes_gcm: EVP_CIPHER_CTX_new failed");

        struct CtxGuard {
            EVP_CIPHER_CTX* c;
            ~CtxGuard() { EVP_CIPHER_CTX_free(c); }
        } guard{ctx};

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                               key_bytes.data(), iv.data()) != 1)
            throw std::runtime_error("aes_gcm: DecryptInit failed");

        std::vector<uint8_t> plaintext(enc_len);
        int out_len = 0;

        if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len, enc_data, enc_len) != 1)
            throw std::runtime_error("aes_gcm: DecryptUpdate failed");

        // Setear el tag ANTES de llamar a Final (verificación de autenticidad)
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.data()) != 1)
            throw std::runtime_error("aes_gcm: SET_TAG failed");

        int final_len = 0;
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len) != 1)
            // Tag inválido → datos corruptos o manipulados
            throw std::runtime_error("aes_gcm: authentication tag mismatch — data may be corrupted or tampered");

        plaintext.resize(out_len + final_len);
        return std::string(plaintext.begin(), plaintext.end());
    }

} // namespace aes_gcm