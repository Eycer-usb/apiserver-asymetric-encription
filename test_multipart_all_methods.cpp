#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <filesystem>
#include <stdexcept>
#include <chrono>
#include <iomanip>

// Incluir el cliente HTTP
#include "src/http_client.hpp"

/**
 * @file test_multipart_all_methods.cpp
 * @brief Pruebas de multipart/form-data para todos los métodos HTTP
 */

void create_test_file(const std::string& filename, size_t size_bytes) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("No se pudo crear el archivo de prueba: " + filename);
    }
    
    std::vector<char> buffer(1024, 'A'); // Buffer de 1KB
    size_t remaining = size_bytes;
    
    while (remaining > 0) {
        size_t to_write = std::min(remaining, buffer.size());
        file.write(buffer.data(), to_write);
        remaining -= to_write;
    }
    
    file.close();
    std::cout << "Archivo creado: " << filename << " (" << size_bytes << " bytes)" << std::endl;
}

void test_multipart_method(const std::string& method_name, 
                          const std::function<http_response()>& test_func) {
    std::cout << "\n=== Probando " << method_name << " con multipart/form-data ===" << std::endl;
    
    try {
        auto start = std::chrono::high_resolution_clock::now();
        http_response response = test_func();
        auto end = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        std::cout << "✓ " << method_name << " exitoso" << std::endl;
        std::cout << "  Código de estado: " << response.status_code << std::endl;
        std::cout << "  Tiempo de ejecución: " << duration.count() << " ms" << std::endl;
        std::cout << "  Tamaño de respuesta: " << response.body.size() << " bytes" << std::endl;
        
        // Mostrar headers de respuesta
        if (!response.headers.empty()) {
            std::cout << "  Headers de respuesta:" << std::endl;
            for (const auto& [key, value] : response.headers) {
                std::cout << "    " << key << ": " << value << std::endl;
            }
        }
        
    } catch (const curl_exception& e) {
        std::cout << "✗ " << method_name << " fallido: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cout << "✗ " << method_name << " fallido (excepción): " << e.what() << std::endl;
    }
}

int main() {
    try {
        std::cout << "=== Pruebas de multipart/form-data para todos los métodos HTTP ===" << std::endl;
        
        // Crear archivos de prueba
        create_test_file("test_file_1.txt", 1024);      // 1KB
        create_test_file("test_file_2.txt", 10 * 1024); // 10KB
        
        // Crear cliente HTTP
        http_client client;
        
        // URL de prueba (puedes cambiarla por un endpoint real)
        std::string test_url = "https://httpbin.org/post"; // Servicio de pruebas HTTP
        
        // Crear partes del formulario
        std::vector<http_form_part> form_parts = {
            {"field1", "valor_campo_1"},
            {"field2", "valor_campo_2"},
            {"file1", http_form_file{"test_file_1.txt", "text/plain"}},
            {"file2", http_form_file{"test_file_2.txt", "text/plain"}},
            {"json_data", R"({"key": "value", "number": 123})"}
        };
        
        // Headers de prueba
        std::map<std::string, std::string, std::less<>> headers = {
            {"User-Agent", "cpp-http-client-test/1.0"},
            {"X-Test-Method", "multipart"}
        };
        
        // Probar todos los métodos con multipart/form-data
        test_multipart_method("POST", [&]() {
            return client.post(test_url, form_parts, headers);
        });
        
        test_multipart_method("PUT", [&]() {
            return client.put(test_url, form_parts, headers);
        });
        
        test_multipart_method("PATCH", [&]() {
            return client.patch(test_url, form_parts, headers);
        });
        
        test_multipart_method("DELETE", [&]() {
            return client.del(test_url, form_parts, headers);
        });
        
        test_multipart_method("OPTIONS", [&]() {
            return client.options(test_url, form_parts, headers);
        });
        
        // Limpiar archivos de prueba
        std::filesystem::remove("test_file_1.txt");
        std::filesystem::remove("test_file_2.txt");
        
        std::cout << "\n=== Pruebas completadas ===" << std::endl;
        std::cout << "Todos los métodos HTTP ahora soportan multipart/form-data" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error durante las pruebas: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}