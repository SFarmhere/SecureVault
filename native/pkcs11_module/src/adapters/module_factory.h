// module_factory.h
#pragma once

#ifdef _WIN32
    #if defined(SECUREVAULT_EXPORTS) || defined(SECUREVAULT_NATIVE_EXPORTS) || defined(SECUREVAULT_NATIVE_STATIC)
        #define SECUREVAULT_API __declspec(dllexport)
    #else
        #define SECUREVAULT_API __declspec(dllimport)
    #endif
#else
    #define SECUREVAULT_API
#endif

#include <memory>
#include <string>
#include <map>
#include <functional>
#include "../../include/token_types.h"

namespace securevault {
namespace pkcs11 {

class ITokenModule;

// Глобальная функция для создания модуля по типу токена
SECUREVAULT_API std::unique_ptr<ITokenModule> CreateTokenModule(TokenType type);

// Глобальная функция для определения типа токена по пути библиотеки (не экспортируется)
TokenType DetectTokenType(const std::string& library_path);

// Тип фабричной функции: создаёт модуль по типу токена
using ModuleCreator = std::function<std::unique_ptr<ITokenModule>()>;

// Единая фабрика
class ModuleFactory {
public:
    static ModuleFactory& Instance();

    // Регистрация нового типа токена
    void Register(TokenType type, ModuleCreator creator, const std::string& name);

    // Создание модуля по типу
    std::unique_ptr<ITokenModule> Create(TokenType type) const;

    // Определение типа по пути к библиотеке
    TokenType Detect(const std::string& library_path) const;

    // Получить список всех зарегистрированных типов
    std::vector<TokenType> GetRegisteredTypes() const;

private:
    struct ModuleInfo {
        ModuleCreator creator;
        std::string name;
    };

    std::map<TokenType, ModuleInfo> registry_;
};

// Удобный макрос для регистрации модуля
#define REGISTER_MODULE(TYPE, CLASS) \
    static bool __registered_##CLASS = []() { \
        ModuleFactory::Instance().Register( \
            TokenType::TYPE, \
            []() -> std::unique_ptr<ITokenModule> { \
                return std::make_unique<CLASS>(); \
            }, \
            #TYPE \
        ); \
        return true; \
    }();

} // namespace pkcs11
} // namespace securevault