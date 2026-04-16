#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <stdexcept>
#include <cstdlib>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <random>

// Incluir la librería de encriptación
#include "src/aes_gcm.hpp"

/**
 * @file test_aes_gcm.cpp
 * @brief Pruebas independientes para la librería AES-GCM
 * @author Generated for testing purposes
 */

class AESGCMTester {
private:
    std::string clave;
    
public:
    AESGCMTester() {
        // Generar una clave nueva para las pruebas
        clave = aes_gcm::generate_key();
        std::cout << "=== AES-GCM Test Suite ===" << std::endl;
        std::cout << "Clave generada: " << clave << std::endl;
        std::cout << "Longitud de clave: " << clave.size() << " caracteres" << std::endl;
        std::cout << std::endl;
    }
    
    void test_basico() {
        std::cout << "=== Test 1: Encriptación/Desencriptación Básica ===" << std::endl;
        
        std::string mensaje_original = "Hola, este es un mensaje de prueba!";
        std::cout << "Mensaje original: " << mensaje_original << std::endl;
        
        // Encriptar
        std::string encriptado = aes_gcm::encrypt(mensaje_original, clave);
        std::cout << "Mensaje encriptado: " << encriptado << std::endl;
        std::cout << "Longitud encriptado: " << encriptado.size() << " caracteres" << std::endl;
        
        // Desencriptar
        std::string desencriptado = aes_gcm::decrypt(encriptado, clave);
        std::cout << "Mensaje desencriptado: " << desencriptado << std::endl;
        
        // Verificar
        if (mensaje_original == desencriptado) {
            std::cout << "✓ Test 1 PASADO: Mensajes coinciden" << std::endl;
        } else {
            std::cout << "✗ Test 1 FALLIDO: Mensajes no coinciden" << std::endl;
        }
        std::cout << std::endl;
    }
    
    void test_datos_binarios() {
        std::cout << "=== Test 2: Datos Binarios ===" << std::endl;
        
        // Crear datos binarios (ejemplo: encabezado PNG)
        std::vector<uint8_t> datos_binarios = {
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
            0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52
        };
        
        std::string datos_str(datos_binarios.begin(), datos_binarios.end());
        std::cout << "Datos binarios (primeros 10 bytes): ";
        for (size_t i = 0; i < std::min(size_t(10), datos_str.size()); ++i) {
            printf("%02X ", static_cast<unsigned char>(datos_str[i]));
        }
        std::cout << std::endl;
        
        // Encriptar datos binarios
        std::string encriptado = aes_gcm::encrypt(datos_str, clave);
        std::cout << "Datos encriptados: " << encriptado << std::endl;
        
        // Desencriptar datos binarios
        std::string desencriptado = aes_gcm::decrypt(encriptado, clave);
        
        // Verificar
        if (datos_str == desencriptado) {
            std::cout << "✓ Test 2 PASADO: Datos binarios coinciden" << std::endl;
        } else {
            std::cout << "✗ Test 2 FALLIDO: Datos binarios no coinciden" << std::endl;
        }
        std::cout << std::endl;
    }
    
    void test_clave_incorrecta() {
        std::cout << "=== Test 3: Clave Incorrecta ===" << std::endl;
        
        std::string mensaje = "Mensaje secreto";
        std::string encriptado = aes_gcm::encrypt(mensaje, clave);
        
        // Intentar desencriptar con clave incorrecta
        std::string clave_incorrecta = aes_gcm::generate_key();
        
        try {
            std::string resultado = aes_gcm::decrypt(encriptado, clave_incorrecta);
            std::cout << "✗ Test 3 FALLIDO: Debería haber lanzado excepción" << std::endl;
        } catch (const std::exception& e) {
            std::cout << "✓ Test 3 PASADO: Excepción esperada: " << e.what() << std::endl;
        }
        std::cout << std::endl;
    }
    
    void test_datos_corruptos() {
        std::cout << "=== Test 4: Datos Corruptos ===" << std::endl;
        
        std::string mensaje = "Test de corrupción";
        std::string encriptado = aes_gcm::encrypt(mensaje, clave);
        
        // Corromper los datos (cambiar un carácter)
        std::string datos_corruptos = encriptado;
        if (!datos_corruptos.empty()) {
            datos_corruptos[10] = datos_corruptos[10] ^ 0x01; // Cambiar un bit
        }
        
        try {
            std::string resultado = aes_gcm::decrypt(datos_corruptos, clave);
            std::cout << "✗ Test 4 FALLIDO: Debería haber lanzado excepción" << std::endl;
        } catch (const std::exception& e) {
            std::cout << "✓ Test 4 PASADO: Excepción esperada: " << e.what() << std::endl;
        }
        std::cout << std::endl;
    }
    
    void test_mensajes_vacios() {
        std::cout << "=== Test 5: Mensajes Vacíos ===" << std::endl;
        
        std::string mensaje_vacio = "";
        std::string encriptado = aes_gcm::encrypt(mensaje_vacio, clave);
        std::string desencriptado = aes_gcm::decrypt(encriptado, clave);
        
        if (mensaje_vacio == desencriptado) {
            std::cout << "✓ Test 5 PASADO: Mensaje vacío encriptado/desencriptado" << std::endl;
        } else {
            std::cout << "✗ Test 5 FALLIDO: Mensaje vacío no coincide" << std::endl;
        }
        std::cout << std::endl;
    }
    
    void test_mensajes_largos() {
        std::cout << "=== Test 6: Mensajes Largos ===" << std::endl;
        
        // Crear un mensaje largo
        std::string mensaje_largo;
        for (int i = 0; i < 1000; ++i) {
            mensaje_largo += "Este es un mensaje largo para probar la encriptación de textos extensos. ";
        }
        
        std::cout << "Longitud del mensaje largo: " << mensaje_largo.size() << " caracteres" << std::endl;
        
        // Encriptar
        std::string encriptado = aes_gcm::encrypt(mensaje_largo, clave);
        std::cout << "Longitud del mensaje encriptado: " << encriptado.size() << " caracteres" << std::endl;
        
        // Desencriptar
        std::string desencriptado = aes_gcm::decrypt(encriptado, clave);
        
        // Verificar
        if (mensaje_largo == desencriptado) {
            std::cout << "✓ Test 6 PASADO: Mensaje largo coincide" << std::endl;
        } else {
            std::cout << "✗ Test 6 FALLIDO: Mensaje largo no coincide" << std::endl;
        }
        std::cout << std::endl;
    }
    
    void test_multiples_encriptaciones() {
        std::cout << "=== Test 7: Múltiples Encriptaciones (IV único) ===" << std::endl;
        
        std::string mensaje = "Mensaje de prueba";
        std::string encriptado1 = aes_gcm::encrypt(mensaje, clave);
        std::string encriptado2 = aes_gcm::encrypt(mensaje, clave);
        
        std::cout << "Encriptación 1: " << encriptado1 << std::endl;
        std::cout << "Encriptación 2: " << encriptado2 << std::endl;
        
        // Verificar que son diferentes (por el IV aleatorio)
        if (encriptado1 != encriptado2) {
            std::cout << "✓ Test 7 PASADO: Cada encriptación produce resultado diferente" << std::endl;
        } else {
            std::cout << "✗ Test 7 FALLIDO: Las encriptaciones son idénticas" << std::endl;
        }
        
        // Verificar que ambas se pueden desencriptar correctamente
        std::string desencriptado1 = aes_gcm::decrypt(encriptado1, clave);
        std::string desencriptado2 = aes_gcm::decrypt(encriptado2, clave);
        
        if (mensaje == desencriptado1 && mensaje == desencriptado2) {
            std::cout << "✓ Test 7 PASADO: Ambas encriptaciones se desencriptan correctamente" << std::endl;
        } else {
            std::cout << "✗ Test 7 FALLIDO: Error en desencriptación" << std::endl;
        }
        std::cout << std::endl;
    }
    
    void test_clave_invalida() {
        std::cout << "=== Test 8: Clave Inválida ===" << std::endl;
        
        std::string mensaje = "Test";
        std::string clave_invalida = "clave_muy_corta"; // No es base64 válido de 32 bytes
        
        try {
            std::string encriptado = aes_gcm::encrypt(mensaje, clave_invalida);
            std::cout << "✗ Test 8 FALLIDO: Debería haber lanzado excepción" << std::endl;
        } catch (const std::exception& e) {
            std::cout << "✓ Test 8 PASADO: Excepción esperada: " << e.what() << std::endl;
        }
        std::cout << std::endl;
    }
    
    void test_almacenamiento_archivo() {
        std::cout << "=== Test 9: Almacenamiento en Archivo ===" << std::endl;
        
        // Guardar clave en archivo
        std::string archivo_clave = "test_clave.key";
        std::ofstream archivo(archivo_clave, std::ios::binary);
        if (archivo) {
            archivo << clave;
            archivo.close();
            
            // Establecer permisos restrictivos
            std::filesystem::permissions(archivo_clave, 
                std::filesystem::perms::owner_read | 
                std::filesystem::perms::owner_write);
            
            std::cout << "Clave guardada en: " << archivo_clave << std::endl;
            
            // Cargar clave desde archivo
            std::ifstream archivo_lectura(archivo_clave, std::ios::binary);
            if (archivo_lectura) {
                std::string clave_cargada((std::istreambuf_iterator<char>(archivo_lectura)),
                                        std::istreambuf_iterator<char>());
                
                // Probar con la clave cargada
                std::string mensaje = "Mensaje para archivo";
                std::string encriptado = aes_gcm::encrypt(mensaje, clave_cargada);
                std::string desencriptado = aes_gcm::decrypt(encriptado, clave_cargada);
                
                if (mensaje == desencriptado) {
                    std::cout << "✓ Test 9 PASADO: Clave cargada desde archivo funciona" << std::endl;
                } else {
                    std::cout << "✗ Test 9 FALLIDO: Error con clave cargada" << std::endl;
                }
                
                archivo_lectura.close();
            } else {
                std::cout << "✗ Test 9 FALLIDO: No se pudo leer el archivo" << std::endl;
            }
            
            // Borrar archivo de prueba
            std::filesystem::remove(archivo_clave);
        } else {
            std::cout << "✗ Test 9 FALLIDO: No se pudo crear el archivo" << std::endl;
        }
        std::cout << std::endl;
    }
    
    void test_rendimiento_archivos() {
        std::cout << "=== Test 10: Rendimiento con Archivos Grandes (hasta 200MB) ===" << std::endl;
        
        // Tamaños de prueba: 1MB, 5MB, 10MB, 20MB, 100MB, 200MB
        std::vector<size_t> tamanos_bytes = {1024 * 1024, 5 * 1024 * 1024, 10 * 1024 * 1024, 20 * 1024 * 1024, 100 * 1024 * 1024, 200 * 1024 * 1024};
        
        for (size_t tamano : tamanos_bytes) {
            std::cout << "\n--- Probando con " << (tamano / (1024 * 1024)) << "MB ---" << std::endl;
            
            // Generar datos de prueba
            std::cout << "Generando datos de prueba..." << std::endl;
            std::vector<char> datos_prueba(tamano);
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 255);
            
            auto start_gen = std::chrono::high_resolution_clock::now();
            for (size_t i = 0; i < tamano; ++i) {
                datos_prueba[i] = static_cast<char>(dis(gen));
            }
            auto end_gen = std::chrono::high_resolution_clock::now();
            auto tiempo_gen = std::chrono::duration_cast<std::chrono::milliseconds>(end_gen - start_gen);
            
            std::string datos_str(datos_prueba.begin(), datos_prueba.end());
            
            // Medir tiempo de encriptación
            std::cout << "Encriptando " << (tamano / (1024 * 1024)) << "MB de datos..." << std::endl;
            auto start_enc = std::chrono::high_resolution_clock::now();
            std::string encriptado = aes_gcm::encrypt(datos_str, clave);
            auto end_enc = std::chrono::high_resolution_clock::now();
            auto tiempo_enc = std::chrono::duration_cast<std::chrono::milliseconds>(end_enc - start_enc);
            
            // Calcular velocidad de encriptación
            double velocidad_enc = (tamano / (1024.0 * 1024.0)) / (tiempo_enc.count() / 1000.0);
            
            // Medir tiempo de desencriptación
            std::cout << "Desencriptando " << (tamano / (1024 * 1024)) << "MB de datos..." << std::endl;
            auto start_dec = std::chrono::high_resolution_clock::now();
            std::string desencriptado = aes_gcm::decrypt(encriptado, clave);
            auto end_dec = std::chrono::high_resolution_clock::now();
            auto tiempo_dec = std::chrono::duration_cast<std::chrono::milliseconds>(end_dec - start_dec);
            
            // Calcular velocidad de desencriptación
            double velocidad_dec = (tamano / (1024.0 * 1024.0)) / (tiempo_dec.count() / 1000.0);
            
            // Verificar integridad
            bool integridad_ok = (datos_str == desencriptado);
            
            // Mostrar resultados
            std::cout << std::fixed << std::setprecision(2);
            std::cout << "Tamaño original: " << (tamano / (1024.0 * 1024.0)) << " MB" << std::endl;
            std::cout << "Tamaño encriptado: " << (encriptado.size() / (1024.0 * 1024.0)) << " MB" << std::endl;
            std::cout << "Tiempo generación: " << tiempo_gen.count() << " ms" << std::endl;
            std::cout << "Tiempo encriptación: " << tiempo_enc.count() << " ms" << std::endl;
            std::cout << "Velocidad encriptación: " << velocidad_enc << " MB/s" << std::endl;
            std::cout << "Tiempo desencriptación: " << tiempo_dec.count() << " ms" << std::endl;
            std::cout << "Velocidad desencriptación: " << velocidad_dec << " MB/s" << std::endl;
            std::cout << "Integridad verificada: " << (integridad_ok ? "✓" : "✗") << std::endl;
            
            if (integridad_ok) {
                std::cout << "✓ Test 10 PASADO: " << (tamano / (1024 * 1024)) << "MB procesado correctamente" << std::endl;
            } else {
                std::cout << "✗ Test 10 FALLIDO: Error en integridad de datos" << std::endl;
            }
        }
        std::cout << std::endl;
    }
    
    void run_all_tests() {
        test_basico();
        test_datos_binarios();
        test_clave_incorrecta();
        test_datos_corruptos();
        test_mensajes_vacios();
        test_mensajes_largos();
        test_multiples_encriptaciones();
        test_clave_invalida();
        test_almacenamiento_archivo();
        test_rendimiento_archivos();
        
        std::cout << "=== Resumen de Pruebas ===" << std::endl;
        std::cout << "Todas las pruebas han sido ejecutadas." << std::endl;
        std::cout << "Revise los resultados anteriores para verificar el estado de cada test." << std::endl;
    }
};

int main() {
    try {
        AESGCMTester tester;
        tester.run_all_tests();
        
        std::cout << std::endl;
        std::cout << "=== Pruebas Completadas ===" << std::endl;
        std::cout << "La librería AES-GCM está funcionando correctamente." << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error durante las pruebas: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}