// module_factory.cpp
#include "module_factory.h"
#include "../../include/pkcs11_api.h"
#include "../../include/token_types.h"
#include <algorithm>
#include <vector>

namespace securevault {
namespace pkcs11 {

ModuleFactory& ModuleFactory::Instance() {
    static ModuleFactory instance;
    return instance;
}

void ModuleFactory::Register(TokenType type, ModuleCreator creator, const std::string& name) {
    registry_[type] = {creator, name};
}

std::unique_ptr<ITokenModule> ModuleFactory::Create(TokenType type) const {
    auto it = registry_.find(type);
    if (it != registry_.end()) {
        return it->second.creator();
    }
    return nullptr;
}

TokenType ModuleFactory::Detect(const std::string& library_path) const {
    std::string lower = library_path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    // Проходим по всем зарегистрированным типам
    for (const auto& entry : registry_) {
        // Проверяем по имени (можно расширить логику)
        // Например, если имя "RUTOKEN" и в пути есть "rutoken"
        std::string type_name = entry.second.name;
        std::transform(type_name.begin(), type_name.end(), type_name.begin(), ::tolower);

        if (lower.find(type_name) != std::string::npos) {
            return entry.first;
        }
    }

    // Дополнительные проверки для специфических библиотек
    if (lower.find("asepkcs") != std::string::npos ||
        lower.find("aladdin") != std::string::npos) {
        return TokenType::ETOKEN;  // fallback
    }

    return TokenType::UNKNOWN;
}

std::vector<TokenType> ModuleFactory::GetRegisteredTypes() const {
    std::vector<TokenType> types;
    for (const auto& entry : registry_) {
        types.push_back(entry.first);
    }
    return types;
}

std::unique_ptr<ITokenModule> CreateTokenModule(TokenType type) {
    return ModuleFactory::Instance().Create(type);
}

TokenType DetectTokenType(const std::string& library_path) {
    return ModuleFactory::Instance().Detect(library_path);
}

} // namespace pkcs11
} // namespace securevault