// ============================================================================
// SecureVault - Реализация для Рутокен (Aktiv Co.)
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// Поддерживаемые модели:
// - Рутокен ЭЦП 2.0
// - Рутокен ЭЦП 3.0
// - Рутокен S (SC/SC+)
// - Рутокен Lite
// ============================================================================

#include "../../include/pkcs11_api.h"
#include "../../include/session_types.h"  // для SessionId, SlotId
#include "../../include/token_types.h"    // для KeyInfo, KeyFlags
#include "module_factory.h"

// Динамическая загрузка PKCS#11 библиотеки
#ifdef _WIN32
    #include <windows.h>
    #define PKCS11_LIB_HANDLE HMODULE
    #define PKCS11_LOAD_LIB(x) LoadLibraryA(x)
    #define PKCS11_GET_FUNC(h, f) GetProcAddress(h, f)
    #define PKCS11_UNLOAD_LIB(h) FreeLibrary(h)
#else
    #include <dlfcn.h>
    #define PKCS11_LIB_HANDLE void*
    #define PKCS11_LOAD_LIB(x) dlopen(x, RTLD_LAZY)
    #define PKCS11_GET_FUNC(h, f) dlsym(h, f)
    #define PKCS11_UNLOAD_LIB(h) dlclose(h)
#endif

#include <vector>
#include <string>
#include <memory>
#include <mutex>
#include <map>
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <random>      // для GenerateKeyId

// PKCS#11 v2.40 базовые определения (минимально необходимые)
typedef unsigned long CK_ULONG;
typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_ULONG CK_KEY_TYPE;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef CK_BYTE CK_BBOOL;

// Структура атрибута
struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    void* pValue;
    CK_ULONG ulValueLen;
};

// Флаги сессий
#define CKF_RW_SESSION          0x00000002
#define CKF_SERIAL_SESSION     0x00000004

// Классы объектов
#define CKO_PUBLIC_KEY      0x00000002
#define CKO_PRIVATE_KEY     0x00000003
#define CKO_CERTIFICATE     0x00000001
#define CKO_DATA           0x00000004
#define CKO_SECRET_KEY     0x00000005

// Типы ключей
#define CKK_RSA                 0x00000000

// Определения для Рутокен (Aktiv Co.)
#ifndef CK_TRUE
#define CK_TRUE 1
#endif
#ifndef CK_FALSE
#define CK_FALSE 0
#endif

// Механизмы Рутокен
#define CKM_RSA_PKCS_KEY_PAIR_GEN 0x00000000
#define CKM_RSA_PKCS             0x00000001
#define CKM_RSA_PKCS_PSS        0x0000000D
#define CKM_SHA256_RSA_PKCS     0x00000040
#define CKM_SHA256_RSA_PKCS_PSS 0x00000043
#define CKM_RSA_PKCS_OAEP       0x00000009
#define CKM_SHA256             0x00000250

// Атрибуты объектов
#define CKA_CLASS              0x00000000
#define CKA_TOKEN             0x00000001
#define CKA_PRIVATE           0x00000002
#define CKA_LABEL             0x00000003
#define CKA_KEY_TYPE          0x00000100
#define CKA_MODULUS           0x00000120
#define CKA_MODULUS_BITS      0x00000121
#define CKA_PUBLIC_EXPONENT   0x00000122
#define CKA_SIGN             0x00000108
#define CKA_VERIFY           0x0000010A
#define CKA_ENCRYPT          0x00000104
#define CKA_DECRYPT          0x00000105
#define CKA_EXTRACTABLE      0x00000162
#define CKA_SENSITIVE        0x00000163
#define CKA_MODIFIABLE       0x00000170
#define CKA_ID               0x00000102
#define CKA_VALUE_LEN      0x00000161
#define CKA_START_DATE     0x00000110
#define CKA_END_DATE       0x00000111

// Стандартные ошибки PKCS#11
#define CKR_OK                       0x00000000
#define CKR_PIN_INCORRECT           0x000000A0
#define CKR_PIN_LOCKED             0x000000A4
#define CKR_SESSION_CLOSED         0x000000B0
#define CKR_SESSION_HANDLE_INVALID 0x000000B3
#define CKR_DEVICE_REMOVED         0x000000B6
#define CKR_FUNCTION_NOT_SUPPORTED 0x00000054

namespace securevault {
namespace pkcs11 {

// ============================================================================
// ТИПЫ PKCS#11 ФУНКЦИЙ
// ============================================================================

typedef CK_RV (*C_GetFunctionList)(CK_RV (**f)(void));
typedef CK_RV (*C_Initialize)(CK_RV (*)(void));
typedef CK_RV (*C_Finalize)(CK_RV (*)(void));
typedef CK_RV (*C_GetSlotList)(CK_BYTE, CK_SLOT_ID*, CK_ULONG*);
typedef CK_RV (*C_GetTokenInfo)(CK_SLOT_ID, void*);
typedef CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_ULONG, void*, void*, CK_SESSION_HANDLE*);
typedef CK_RV (*C_CloseSession)(CK_SESSION_HANDLE);
typedef CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE*, CK_ULONG);
typedef CK_RV (*C_Logout)(CK_SESSION_HANDLE);
typedef CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM_TYPE*, void*, CK_ULONG,
                                   CK_ATTRIBUTE*, CK_ULONG, CK_ATTRIBUTE*, CK_ULONG,
                                   CK_OBJECT_HANDLE*, CK_OBJECT_HANDLE*);
typedef CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
typedef CK_RV (*C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE*, CK_ULONG, CK_ULONG*);
typedef CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);
typedef CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
                                     CK_ATTRIBUTE*, CK_ULONG);
typedef CK_RV (*C_SetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
                                     CK_ATTRIBUTE*, CK_ULONG);
typedef CK_RV (*C_DestroyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
typedef CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM_TYPE*, void*, CK_OBJECT_HANDLE);
typedef CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
typedef CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM_TYPE*, void*, CK_OBJECT_HANDLE);
typedef CK_RV (*C_Verify)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG);
typedef CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE, CK_MECHANISM_TYPE*, void*, CK_OBJECT_HANDLE);
typedef CK_RV (*C_Encrypt)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
typedef CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE, CK_MECHANISM_TYPE*, void*, CK_OBJECT_HANDLE);
typedef CK_RV (*C_Decrypt)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
typedef CK_RV (*C_SetPIN)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG);

// ============================================================================
// РЕАЛИЗАЦИЯ МОДУЛЯ РУТОКЕН
// ============================================================================

/**
 * @brief Реализация ITokenModule для Рутокен
 */
class RutokenModule : public ITokenModule {
private:
    // ------------------------------------------------------------------------
    // ПОЛЯ КЛАССА
    // ------------------------------------------------------------------------

    PKCS11_LIB_HANDLE lib_handle_;
    bool initialized_;
    mutable std::mutex mutex_;

    // Указатели на функции PKCS#11
    C_GetFunctionList C_GetFunctionList_;
    C_Initialize C_Initialize_;
    C_Finalize C_Finalize_;
    C_GetSlotList C_GetSlotList_;
    C_GetTokenInfo C_GetTokenInfo_;
    C_OpenSession C_OpenSession_;
    C_CloseSession C_CloseSession_;
    C_Login C_Login_;
    C_Logout C_Logout_;
    C_GenerateKeyPair C_GenerateKeyPair_;
    C_FindObjectsInit C_FindObjectsInit_;
    C_FindObjects C_FindObjects_;
    C_FindObjectsFinal C_FindObjectsFinal_;
    C_GetAttributeValue C_GetAttributeValue_;
    C_SetAttributeValue C_SetAttributeValue_;
    C_DestroyObject C_DestroyObject_;
    C_SignInit C_SignInit_;
    C_Sign C_Sign_;
    C_VerifyInit C_VerifyInit_;
    C_Verify C_Verify_;
    C_EncryptInit C_EncryptInit_;
    C_Encrypt C_Encrypt_;
    C_DecryptInit C_DecryptInit_;
    C_Decrypt C_Decrypt_;
    C_SetPIN C_SetPIN_;

    // Активные сессии: internal_id -> {pkcs11_handle, slot_id}
    std::map<int, std::pair<CK_SESSION_HANDLE, CK_SLOT_ID>> sessions_;
    int next_session_id_;

    // ------------------------------------------------------------------------
    // ВНУТРЕННИЕ МЕТОДЫ
    // ------------------------------------------------------------------------

    /**
     * @brief Загрузить все функции PKCS#11 из библиотеки
     */
    TokenResult LoadFunctions() {
        CK_RV (*func_list)(void);

        if (!C_GetFunctionList_) {
            C_GetFunctionList_ = (C_GetFunctionList)PKCS11_GET_FUNC(lib_handle_, "C_GetFunctionList");
            if (!C_GetFunctionList_) {
                return TokenResult::ERR_NOT_SUPPORTED;
            }
        }

        CK_RV rv = C_GetFunctionList_(&func_list);
        if (rv != CKR_OK) {
            return TokenResult::ERR_GENERAL;
        }

        // Здесь должно быть получение всех функций через func_list
        // Для простоты используем прямой импорт

        C_Initialize_ = (C_Initialize)PKCS11_GET_FUNC(lib_handle_, "C_Initialize");
        C_Finalize_ = (C_Finalize)PKCS11_GET_FUNC(lib_handle_, "C_Finalize");
        C_GetSlotList_ = (C_GetSlotList)PKCS11_GET_FUNC(lib_handle_, "C_GetSlotList");
        C_GetTokenInfo_ = (C_GetTokenInfo)PKCS11_GET_FUNC(lib_handle_, "C_GetTokenInfo");
        C_OpenSession_ = (C_OpenSession)PKCS11_GET_FUNC(lib_handle_, "C_OpenSession");
        C_CloseSession_ = (C_CloseSession)PKCS11_GET_FUNC(lib_handle_, "C_CloseSession");
        C_Login_ = (C_Login)PKCS11_GET_FUNC(lib_handle_, "C_Login");
        C_Logout_ = (C_Logout)PKCS11_GET_FUNC(lib_handle_, "C_Logout");
        C_GenerateKeyPair_ = (C_GenerateKeyPair)PKCS11_GET_FUNC(lib_handle_, "C_GenerateKeyPair");
        C_FindObjectsInit_ = (C_FindObjectsInit)PKCS11_GET_FUNC(lib_handle_, "C_FindObjectsInit");
        C_FindObjects_ = (C_FindObjects)PKCS11_GET_FUNC(lib_handle_, "C_FindObjects");
        C_FindObjectsFinal_ = (C_FindObjectsFinal)PKCS11_GET_FUNC(lib_handle_, "C_FindObjectsFinal");
        C_GetAttributeValue_ = (C_GetAttributeValue)PKCS11_GET_FUNC(lib_handle_, "C_GetAttributeValue");
        C_SetAttributeValue_ = (C_SetAttributeValue)PKCS11_GET_FUNC(lib_handle_, "C_SetAttributeValue");
        C_DestroyObject_ = (C_DestroyObject)PKCS11_GET_FUNC(lib_handle_, "C_DestroyObject");
        C_SignInit_ = (C_SignInit)PKCS11_GET_FUNC(lib_handle_, "C_SignInit");
        C_Sign_ = (C_Sign)PKCS11_GET_FUNC(lib_handle_, "C_Sign");
        C_VerifyInit_ = (C_VerifyInit)PKCS11_GET_FUNC(lib_handle_, "C_VerifyInit");
        C_Verify_ = (C_Verify)PKCS11_GET_FUNC(lib_handle_, "C_Verify");
        C_EncryptInit_ = (C_EncryptInit)PKCS11_GET_FUNC(lib_handle_, "C_EncryptInit");
        C_Encrypt_ = (C_Encrypt)PKCS11_GET_FUNC(lib_handle_, "C_Encrypt");
        C_DecryptInit_ = (C_DecryptInit)PKCS11_GET_FUNC(lib_handle_, "C_DecryptInit");
        C_Decrypt_ = (C_Decrypt)PKCS11_GET_FUNC(lib_handle_, "C_Decrypt");
        C_SetPIN_ = (C_SetPIN)PKCS11_GET_FUNC(lib_handle_, "C_SetPIN");

        if (!C_Initialize_ || !C_Finalize_ || !C_GetSlotList_ || !C_OpenSession_) {
            return TokenResult::ERR_GENERAL;
        }

        return TokenResult::SUCCESS;
    }

    /**
     * @brief Конвертировать PKCS#11 ошибку в TokenResult
     */
    TokenResult MapError(CK_RV rv) {
        switch (rv) {
            case CKR_OK:
                return TokenResult::SUCCESS;
            case CKR_PIN_INCORRECT:
                return TokenResult::ERR_PIN_INCORRECT;
            case CKR_PIN_LOCKED:
                return TokenResult::ERR_PIN_LOCKED;
            case CKR_SESSION_CLOSED:
            case CKR_SESSION_HANDLE_INVALID:
                return TokenResult::ERR_SESSION_ERROR;
            case CKR_DEVICE_REMOVED:
                return TokenResult::ERR_TOKEN_NOT_FOUND;
            case CKR_FUNCTION_NOT_SUPPORTED:
                return TokenResult::ERR_NOT_SUPPORTED;
            default:
                return TokenResult::ERR_GENERAL;
        }
    }

    /**
     * @brief Генерировать уникальный ID для ключа
     */
    std::string GenerateKeyId() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 15);

        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < 16; ++i) {
            ss << std::setw(2) << dis(gen);
        }
        return ss.str();
    }

    /**
     * @brief Получить PKCS#11 хендл сессии по внутреннему ID
     */
    TokenResult GetSessionHandle(int session_id, CK_SESSION_HANDLE& handle) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it == sessions_.end()) {
            return TokenResult::ERR_SESSION_ERROR;
        }
        handle = it->second.first;
        return TokenResult::SUCCESS;
    }

public:
    // ------------------------------------------------------------------------
    // КОНСТРУКТОР / ДЕСТРУКТОР
    // ------------------------------------------------------------------------

    RutokenModule()
        : lib_handle_(nullptr)
        , initialized_(false)
        , C_GetFunctionList_(nullptr)
        , C_Initialize_(nullptr)
        , C_Finalize_(nullptr)
        , C_GetSlotList_(nullptr)
        , C_GetTokenInfo_(nullptr)
        , C_OpenSession_(nullptr)
        , C_CloseSession_(nullptr)
        , C_Login_(nullptr)
        , C_Logout_(nullptr)
        , C_GenerateKeyPair_(nullptr)
        , C_FindObjectsInit_(nullptr)
        , C_FindObjects_(nullptr)
        , C_FindObjectsFinal_(nullptr)
        , C_GetAttributeValue_(nullptr)
        , C_SetAttributeValue_(nullptr)
        , C_DestroyObject_(nullptr)
        , C_SignInit_(nullptr)
        , C_Sign_(nullptr)
        , C_VerifyInit_(nullptr)
        , C_Verify_(nullptr)
        , C_EncryptInit_(nullptr)
        , C_Encrypt_(nullptr)
        , C_DecryptInit_(nullptr)
        , C_Decrypt_(nullptr)
        , C_SetPIN_(nullptr)
        , next_session_id_(1000)  // Начинаем с 1000 для удобства
    {
    }

    ~RutokenModule() override {
        Finalize();
    }

    // ------------------------------------------------------------------------
    // ИНИЦИАЛИЗАЦИЯ И УПРАВЛЕНИЕ
    // ------------------------------------------------------------------------

    TokenResult Initialize(const std::string& library_path) override {
        std::lock_guard<std::mutex> lock(mutex_);

        if (initialized_) {
            return TokenResult::SUCCESS;
        }

        // Загружаем библиотеку Рутокен
        lib_handle_ = PKCS11_LOAD_LIB(library_path.c_str());
        if (!lib_handle_) {
            return TokenResult::ERR_TOKEN_NOT_FOUND;
        }

        // Загружаем функции
        TokenResult result = LoadFunctions();
        if (result != TokenResult::SUCCESS) {
            PKCS11_UNLOAD_LIB(lib_handle_);
            lib_handle_ = nullptr;
            return result;
        }

        // Инициализируем PKCS#11
        CK_RV rv = C_Initialize_(nullptr);
        if (rv != CKR_OK) {
            PKCS11_UNLOAD_LIB(lib_handle_);
            lib_handle_ = nullptr;
            return MapError(rv);
        }

        initialized_ = true;
        return TokenResult::SUCCESS;
    }

    void Finalize() override {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!initialized_) {
            return;
        }

        // Закрываем все открытые сессии
        for (auto& pair : sessions_) {
            if (C_CloseSession_) {
                C_CloseSession_(pair.second.first);
            }
        }
        sessions_.clear();

        // Финализируем PKCS#11
        if (C_Finalize_) {
            C_Finalize_(nullptr);
        }

        // Выгружаем библиотеку
        if (lib_handle_) {
            PKCS11_UNLOAD_LIB(lib_handle_);
            lib_handle_ = nullptr;
        }

        initialized_ = false;
    }

    bool IsInitialized() const override {
        return initialized_;
    }

    // ------------------------------------------------------------------------
    // РАБОТА С ТОКЕНАМИ
    // ------------------------------------------------------------------------

    std::vector<TokenInfo> GetAvailableTokens() override {
        std::vector<TokenInfo> tokens;

        if (!initialized_) {
            return tokens;
        }

        std::lock_guard<std::mutex> lock(mutex_);

        // Получаем список слотов
        CK_SLOT_ID slots[32];
        CK_ULONG slot_count = 32;
        CK_RV rv = C_GetSlotList_(1, slots, &slot_count);  // 1 = токены присутствуют
        if (rv != CKR_OK) {
            return tokens;
        }

        for (CK_ULONG i = 0; i < slot_count; ++i) {
            // TODO: Получить реальную информацию через C_GetTokenInfo
            TokenInfo info;
            strncpy(info.manufacturer_name, "Aktiv Co.", sizeof(info.manufacturer_name) - 1);
            strncpy(info.model, "Rutoken ECP", sizeof(info.model) - 1);
            strncpy(info.serial_number, "00000000", sizeof(info.serial_number) - 1);
            strncpy(info.label, "Rutoken", sizeof(info.label) - 1);
            info.total_memory = 32768;   // 32KB для ECP
            info.free_memory = 16384;     // Приблизительно
            info.set_initialized(true);
            info.set_user_pin_set(true);
            info.set_so_pin_set(false);
            info.max_pin_len = 8;
            info.min_pin_len = 4;
            info.pin_retries = 3;
            info.so_pin_retries = 3;
            info.insert_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();

            tokens.push_back(info);
        }

        return tokens;
    }

    /**
     * @brief Открыть сессию на Рутокен
     *
     * @param slot_id ID слота (фиксированный 32-битный)
     * @param pin PIN-код пользователя
     * @return SessionId ID сессии или -1 при ошибке
     */
    SessionId OpenSession(SlotId slot_id, const std::string& pin) override {
        if (!initialized_) {
            return -1;
        }

        std::lock_guard<std::mutex> lock(mutex_);

        // Конвертируем SlotId (uint32_t) в CK_SLOT_ID (unsigned long)
        CK_SLOT_ID pkcs11_slot = static_cast<CK_SLOT_ID>(slot_id);

        CK_SESSION_HANDLE session;
        CK_RV rv = C_OpenSession_(pkcs11_slot, CKF_RW_SESSION | CKF_SERIAL_SESSION,
                                  nullptr, nullptr, &session);
        if (rv != CKR_OK) {
            return -1;
        }

        // Логинимся с PIN-кодом
        rv = C_Login_(session, 0, (CK_BYTE*)pin.c_str(), (CK_ULONG)pin.length());  // 0 = CKU_USER
        if (rv != CKR_OK) {
            C_CloseSession_(session);
            return -1;
        }

        int internal_id = next_session_id_++;
        sessions_[internal_id] = {session, pkcs11_slot};

        return static_cast<SessionId>(internal_id);
    }

    void CloseSession(SessionId session_id) override {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = sessions_.find(static_cast<int>(session_id));
        if (it != sessions_.end()) {
            if (C_Logout_) {
                C_Logout_(it->second.first);
            }
            if (C_CloseSession_) {
                C_CloseSession_(it->second.first);
            }
            sessions_.erase(it);
        }
    }

    bool IsSessionValid(SessionId session_id) const override {
        std::lock_guard<std::mutex> lock(mutex_);
        return sessions_.find(static_cast<int>(session_id)) != sessions_.end();
    }

    TokenResult ChangePin(SessionId session_id, const std::string& old_pin,
                         const std::string& new_pin) override {
        if (!initialized_) {
            return TokenResult::ERR_NOT_INITIALIZED;
        }

        CK_SESSION_HANDLE session;
        TokenResult result = GetSessionHandle(static_cast<int>(session_id), session);
        if (result != TokenResult::SUCCESS) {
            return result;
        }

        CK_RV rv = C_SetPIN_(session,
                            (CK_BYTE*)old_pin.c_str(), (CK_ULONG)old_pin.length(),
                            (CK_BYTE*)new_pin.c_str(), (CK_ULONG)new_pin.length());

        return MapError(rv);
    }

    // ------------------------------------------------------------------------
    // УПРАВЛЕНИЕ КЛЮЧАМИ
    // ------------------------------------------------------------------------

    /**
     * @brief Сгенерировать пару ключей RSA на Рутокен
     *
     * @param session_id ID сессии
     * @param params Параметры генерации
     * @return std::string ID ключа (hex) или пустая строка при ошибке
     */
    std::string GenerateRsaKeyPair(SessionId session_id, const RsaKeyParams& params) override {
        if (!initialized_) {
            return "";
        }

        CK_SESSION_HANDLE session;
        TokenResult result = GetSessionHandle(static_cast<int>(session_id), session);
        if (result != TokenResult::SUCCESS) {
            return "";
        }

        // Генерируем ID ключа
        std::string key_id = GenerateKeyId();

        // Атрибуты для публичного ключа
        CK_BBOOL token = params.is_token() ? CK_TRUE : CK_FALSE;
        CK_BBOOL private_attr = params.is_private() ? CK_TRUE : CK_FALSE;
        CK_ULONG key_size_ul = static_cast<CK_ULONG>(params.key_size);
        CK_ULONG pub_exp = static_cast<CK_ULONG>(params.public_exponent);
        
        // Создаем копии строк для атрибутов (должны пережить массивы атрибутов)
        std::string label_str(params.get_label());
        std::string id_str(key_id);
        
        // Получаем длины строк
        CK_ULONG label_len = static_cast<CK_ULONG>(label_str.length());
        CK_ULONG id_len = static_cast<CK_ULONG>(id_str.length());
        
        // Буферы для CKA_LABEL и CKA_ID (PKCS#11 ожидает, что данные будут доступны во время вызова)
        std::vector<CK_BYTE> label_buf(128);
        std::vector<CK_BYTE> id_buf(64);
        memcpy(label_buf.data(), label_str.c_str(), label_len);
        memcpy(id_buf.data(), id_str.c_str(), id_len);

        CK_OBJECT_CLASS pub_class = CKO_PUBLIC_KEY;
        CK_OBJECT_CLASS priv_class = CKO_PRIVATE_KEY;
        CK_KEY_TYPE key_type = CKK_RSA;

        CK_ATTRIBUTE public_attrs[] = {
            {CKA_CLASS, &pub_class, sizeof(pub_class)},
            {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
            {CKA_TOKEN, &token, sizeof(CK_BBOOL)},
            {CKA_PRIVATE, &private_attr, sizeof(CK_BBOOL)},
            {CKA_MODULUS_BITS, &key_size_ul, sizeof(CK_ULONG)},
            {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(CK_ULONG)},
            {CKA_ENCRYPT, &private_attr, sizeof(CK_BBOOL)},
            {CKA_VERIFY, &private_attr, sizeof(CK_BBOOL)},
            {CKA_LABEL, label_buf.data(), label_len},
            {CKA_ID, id_buf.data(), id_len},
        };

        // Атрибуты для приватного ключа
        CK_BBOOL false_val = CK_FALSE;
        CK_BBOOL true_val = CK_TRUE;
        CK_BBOOL extractable = params.is_extractable() ? CK_TRUE : CK_FALSE;
        CK_BBOOL sensitive = params.is_sensitive() ? CK_TRUE : CK_FALSE;
        CK_BBOOL modifiable = params.is_modifiable() ? CK_TRUE : CK_FALSE;

        CK_ATTRIBUTE private_attrs[] = {
            {CKA_CLASS, &priv_class, sizeof(priv_class)},
            {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
            {CKA_TOKEN, &token, sizeof(CK_BBOOL)},
            {CKA_PRIVATE, &true_val, sizeof(CK_BBOOL)},
            {CKA_SENSITIVE, &sensitive, sizeof(CK_BBOOL)},
            {CKA_EXTRACTABLE, &extractable, sizeof(CK_BBOOL)},
            {CKA_MODIFIABLE, &modifiable, sizeof(CK_BBOOL)},
            {CKA_DECRYPT, &true_val, sizeof(CK_BBOOL)},
            {CKA_SIGN, &true_val, sizeof(CK_BBOOL)},
            {CKA_LABEL, label_buf.data(), label_len},
            {CKA_ID, id_buf.data(), id_len},
        };

        CK_OBJECT_HANDLE pub_key, priv_key;
        CK_MECHANISM_TYPE mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;

        CK_RV rv = C_GenerateKeyPair_(session, &mechanism, nullptr, 0,
                                      public_attrs, sizeof(public_attrs) / sizeof(CK_ATTRIBUTE),
                                      private_attrs, sizeof(private_attrs) / sizeof(CK_ATTRIBUTE),
                                      &pub_key, &priv_key);

        if (rv != CKR_OK) {
            return "";
        }

        return key_id;
    }

    /**
     * @brief Получить список всех ключей на Рутокен
     *
     * @param session_id ID сессии
     * @return std::vector<KeyInfo> Список ключей
     */
    std::vector<KeyInfo> ListKeys(SessionId session_id) override {
        std::vector<KeyInfo> keys;

        if (!initialized_) {
            return keys;
        }

        CK_SESSION_HANDLE session;
        TokenResult result = GetSessionHandle(static_cast<int>(session_id), session);
        if (result != TokenResult::SUCCESS) {
            return keys;
        }

        // Ищем все приватные ключи
        CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE find_attrs[] = {
            {CKA_CLASS, (void*)&key_class, sizeof(key_class)},
        };

        CK_RV rv = C_FindObjectsInit_(session, find_attrs, 1);
        if (rv != CKR_OK) {
            return keys;
        }

        CK_OBJECT_HANDLE objects[32];
        CK_ULONG object_count;

        while (true) {
            rv = C_FindObjects_(session, objects, 32, &object_count);
            if (rv != CKR_OK || object_count == 0) {
                break;
            }

            for (CK_ULONG i = 0; i < object_count; ++i) {
                KeyInfo info;

                // Получаем атрибуты ключа
                CK_BYTE id_buf[32];
                CK_ULONG id_len = 32;
                CK_ATTRIBUTE id_attr = {CKA_ID, id_buf, id_len};

                CK_BYTE label_buf[64];
                CK_ULONG label_len = 64;
                CK_ATTRIBUTE label_attr = {CKA_LABEL, label_buf, label_len};

                CK_KEY_TYPE key_type;
                CK_ATTRIBUTE type_attr = {CKA_KEY_TYPE, &key_type, sizeof(key_type)};

                CK_ULONG modulus_bits = 0;
                CK_ATTRIBUTE bits_attr = {CKA_MODULUS_BITS, &modulus_bits, sizeof(modulus_bits)};

                CK_BBOOL extractable = CK_FALSE;
                CK_ATTRIBUTE ext_attr = {CKA_EXTRACTABLE, &extractable, sizeof(extractable)};

                CK_ATTRIBUTE attrs[] = {id_attr, label_attr, type_attr, bits_attr, ext_attr};

                rv = C_GetAttributeValue_(session, objects[i], attrs, 5);
                if (rv == CKR_OK) {
                    info.set_id(std::string((char*)id_buf, id_len).c_str());
                    info.set_label(std::string((char*)label_buf, label_len).c_str());
                    info.type = KeyType::RSA_PRIVATE;
                    info.size_bits = static_cast<KeySizeBits>(modulus_bits);

                    // Устанавливаем флаги вместо отдельных bool
                    info.set_private(true);
                    info.set_extractable(extractable == CK_TRUE);
                    info.set_modifiable(true);
                    info.set_token(true);

                    info.created_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();

                    keys.push_back(info);
                }
            }
        }

        C_FindObjectsFinal_(session);
        return keys;
    }

    std::unique_ptr<KeyInfo> FindKeyById(SessionId session_id, const std::string& key_id) override {
        auto keys = ListKeys(session_id);
        for (auto& key : keys) {
            if (key_id == key.get_id()) {
                return std::make_unique<KeyInfo>(key);
            }
        }
        return nullptr;
    }

    TokenResult DeleteKey(SessionId session_id, const std::string& key_id) override {
        if (!initialized_) {
            return TokenResult::ERR_NOT_INITIALIZED;
        }

        CK_SESSION_HANDLE session;
        TokenResult result = GetSessionHandle(static_cast<int>(session_id), session);
        if (result != TokenResult::SUCCESS) {
            return result;
        }

        // Ищем ключ по ID
        CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE find_attrs[] = {
            {CKA_CLASS, (void*)&key_class, sizeof(key_class)},
            {CKA_ID, (void*)key_id.c_str(), (CK_ULONG)key_id.length()},
        };

        CK_RV rv = C_FindObjectsInit_(session, find_attrs, 2);
        if (rv != CKR_OK) {
            return MapError(rv);
        }

        CK_OBJECT_HANDLE obj;
        CK_ULONG obj_count;
        rv = C_FindObjects_(session, &obj, 1, &obj_count);

        if (rv == CKR_OK && obj_count > 0) {
            rv = C_DestroyObject_(session, obj);
        }

        C_FindObjectsFinal_(session);
        return MapError(rv);
    }

    // ------------------------------------------------------------------------
    // КРИПТОГРАФИЧЕСКИЕ ОПЕРАЦИИ
    // ------------------------------------------------------------------------

    std::vector<uint8_t> SignRsa(SessionId session_id,
                                const std::string& key_id,
                                const std::vector<uint8_t>& data,
                                const RsaSignParams& params) override {
        std::vector<uint8_t> signature;

        if (!initialized_) {
            return signature;
        }

        CK_SESSION_HANDLE session;
        TokenResult result = GetSessionHandle(static_cast<int>(session_id), session);
        if (result != TokenResult::SUCCESS) {
            return signature;
        }

        // Ищем ключ
        CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE find_attrs[] = {
            {CKA_CLASS, (void*)&key_class, sizeof(key_class)},
            {CKA_ID, (void*)key_id.c_str(), (CK_ULONG)key_id.length()},
        };

        CK_RV rv = C_FindObjectsInit_(session, find_attrs, 2);
        if (rv != CKR_OK) {
            return signature;
        }

        CK_OBJECT_HANDLE key;
        CK_ULONG key_count;
        rv = C_FindObjects_(session, &key, 1, &key_count);
        C_FindObjectsFinal_(session);

        if (rv != CKR_OK || key_count == 0) {
            return signature;
        }

        // Выбираем механизм подписи
        CK_MECHANISM_TYPE mechanism;
        if (params.padding == RsaSignParams::Padding::PSS) {
            mechanism = CKM_SHA256_RSA_PKCS_PSS;
        } else {
            mechanism = CKM_SHA256_RSA_PKCS;
        }

        // Инициализируем подпись
        rv = C_SignInit_(session, &mechanism, nullptr, key);
        if (rv != CKR_OK) {
            return signature;
        }

        // Получаем размер подписи
        CK_ULONG sig_len = 0;
        rv = C_Sign_(session, (CK_BYTE*)data.data(), (CK_ULONG)data.size(), nullptr, &sig_len);
        if (rv != CKR_OK || sig_len == 0) {
            return signature;
        }

        // Подписываем
        signature.resize(sig_len);
        rv = C_Sign_(session, (CK_BYTE*)data.data(), (CK_ULONG)data.size(),
                    signature.data(), &sig_len);
        signature.resize(sig_len);

        if (rv != CKR_OK) {
            signature.clear();
        }

        return signature;
    }

    bool VerifyRsa(SessionId session_id,
                  const std::string& key_id,
                  const std::vector<uint8_t>& data,
                  const std::vector<uint8_t>& signature,
                  const RsaSignParams& params) override {
        if (!initialized_) {
            return false;
        }

        CK_SESSION_HANDLE session;
        TokenResult result = GetSessionHandle(static_cast<int>(session_id), session);
        if (result != TokenResult::SUCCESS) {
            return false;
        }

        // Ищем публичный ключ
        CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
        CK_ATTRIBUTE find_attrs[] = {
            {CKA_CLASS, (void*)&key_class, sizeof(key_class)},
            {CKA_ID, (void*)key_id.c_str(), (CK_ULONG)key_id.length()},
        };

        CK_RV rv = C_FindObjectsInit_(session, find_attrs, 2);
        if (rv != CKR_OK) {
            return false;
        }

        CK_OBJECT_HANDLE key;
        CK_ULONG key_count;
        rv = C_FindObjects_(session, &key, 1, &key_count);
        C_FindObjectsFinal_(session);

        if (rv != CKR_OK || key_count == 0) {
            return false;
        }

        // Выбираем механизм проверки
        CK_MECHANISM_TYPE mechanism;
        if (params.padding == RsaSignParams::Padding::PSS) {
            mechanism = CKM_SHA256_RSA_PKCS_PSS;
        } else {
            mechanism = CKM_SHA256_RSA_PKCS;
        }

        // Инициализируем проверку
        rv = C_VerifyInit_(session, &mechanism, nullptr, key);
        if (rv != CKR_OK) {
            return false;
        }

        // Проверяем подпись
        rv = C_Verify_(session, (CK_BYTE*)data.data(), (CK_ULONG)data.size(),
                      (CK_BYTE*)signature.data(), (CK_ULONG)signature.size());

        return rv == CKR_OK;
    }

    std::vector<uint8_t> EncryptRsa(SessionId session_id,
                                   const std::string& key_id,
                                   const std::vector<uint8_t>& plaintext,
                                   const RsaEncryptParams& params) override {
        std::vector<uint8_t> ciphertext;

        if (!initialized_) {
            return ciphertext;
        }

        CK_SESSION_HANDLE session;
        TokenResult result = GetSessionHandle(static_cast<int>(session_id), session);
        if (result != TokenResult::SUCCESS) {
            return ciphertext;
        }

        // Ищем публичный ключ
        CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
        CK_ATTRIBUTE find_attrs[] = {
            {CKA_CLASS, (void*)&key_class, sizeof(key_class)},
            {CKA_ID, (void*)key_id.c_str(), (CK_ULONG)key_id.length()},
        };

        CK_RV rv = C_FindObjectsInit_(session, find_attrs, 2);
        if (rv != CKR_OK) {
            return ciphertext;
        }

        CK_OBJECT_HANDLE key;
        CK_ULONG key_count;
        rv = C_FindObjects_(session, &key, 1, &key_count);
        C_FindObjectsFinal_(session);

        if (rv != CKR_OK || key_count == 0) {
            return ciphertext;
        }

        // Выбираем механизм шифрования
        CK_MECHANISM_TYPE mechanism;
        if (params.padding == RsaEncryptParams::Padding::OAEP) {
            mechanism = CKM_RSA_PKCS_OAEP;
            // TODO: Реализовать параметры OAEP (хеш, MGF, label)
        } else {
            mechanism = CKM_RSA_PKCS;
        }

        // Инициализируем шифрование
        rv = C_EncryptInit_(session, &mechanism, nullptr, key);
        if (rv != CKR_OK) {
            return ciphertext;
        }

        // Получаем размер шифротекста
        CK_ULONG cipher_len = 0;
        rv = C_Encrypt_(session, (CK_BYTE*)plaintext.data(), (CK_ULONG)plaintext.size(),
                       nullptr, &cipher_len);
        if (rv != CKR_OK || cipher_len == 0) {
            return ciphertext;
        }

        // Шифруем
        ciphertext.resize(cipher_len);
        rv = C_Encrypt_(session, (CK_BYTE*)plaintext.data(), (CK_ULONG)plaintext.size(),
                       ciphertext.data(), &cipher_len);
        ciphertext.resize(cipher_len);

        if (rv != CKR_OK) {
            ciphertext.clear();
        }

        return ciphertext;
    }

    std::vector<uint8_t> DecryptRsa(SessionId session_id,
                                   const std::string& key_id,
                                   const std::vector<uint8_t>& ciphertext,
                                   const RsaEncryptParams& params) override {
        std::vector<uint8_t> plaintext;

        if (!initialized_) {
            return plaintext;
        }

        CK_SESSION_HANDLE session;
        TokenResult result = GetSessionHandle(static_cast<int>(session_id), session);
        if (result != TokenResult::SUCCESS) {
            return plaintext;
        }

        // Ищем приватный ключ
        CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE find_attrs[] = {
            {CKA_CLASS, (void*)&key_class, sizeof(key_class)},
            {CKA_ID, (void*)key_id.c_str(), (CK_ULONG)key_id.length()},
        };

        CK_RV rv = C_FindObjectsInit_(session, find_attrs, 2);
        if (rv != CKR_OK) {
            return plaintext;
        }

        CK_OBJECT_HANDLE key;
        CK_ULONG key_count;
        rv = C_FindObjects_(session, &key, 1, &key_count);
        C_FindObjectsFinal_(session);

        if (rv != CKR_OK || key_count == 0) {
            return plaintext;
        }

        // Выбираем механизм расшифровки
        CK_MECHANISM_TYPE mechanism = CKM_RSA_PKCS;

        // Инициализируем расшифровку
        rv = C_DecryptInit_(session, &mechanism, nullptr, key);
        if (rv != CKR_OK) {
            return plaintext;
        }

        // Получаем размер открытого текста
        CK_ULONG plain_len = 0;
        rv = C_Decrypt_(session, (CK_BYTE*)ciphertext.data(), (CK_ULONG)ciphertext.size(),
                       nullptr, &plain_len);
        if (rv != CKR_OK || plain_len == 0) {
            return plaintext;
        }

        // Расшифровываем
        plaintext.resize(plain_len);
        rv = C_Decrypt_(session, (CK_BYTE*)ciphertext.data(), (CK_ULONG)ciphertext.size(),
                       plaintext.data(), &plain_len);
        plaintext.resize(plain_len);

        if (rv != CKR_OK) {
            plaintext.clear();
        }

        return plaintext;
    }

    // ------------------------------------------------------------------------
    // РАБОТА С СЕРТИФИКАТАМИ
    // ------------------------------------------------------------------------

    std::vector<CertificateInfo> ListCertificates(SessionId /*session_id*/) override {
        return {};  // Заглушка: возвращаем пустой список
    }

    TokenResult ImportCertificate(SessionId /*session_id*/,
                                  const std::vector<uint8_t>& /*cert_data*/,
                                  const std::string& /*label*/,
                                  const std::string& /*key_id*/) override {
        return TokenResult::ERR_NOT_SUPPORTED;  // Заглушка
    }

    std::vector<uint8_t> ExportCertificate(SessionId /*session_id*/,
                                           const std::string& /*cert_id*/,
                                           const std::string& /*format*/) override {
        return {};  // Заглушка
    }

    // ------------------------------------------------------------------------
    // УТИЛИТЫ
    // ------------------------------------------------------------------------

    std::string GetErrorMessage(TokenResult result) const override {
        switch (result) {
            case TokenResult::SUCCESS:
                return "Success";
            case TokenResult::ERR_GENERAL:
                return "PKCS#11 general error";
            case TokenResult::ERR_NOT_INITIALIZED:
                return "Module not initialized";
            case TokenResult::ERR_TOKEN_NOT_FOUND:
                return "Rutoken not found. Check connection";
            case TokenResult::ERR_SESSION_ERROR:
                return "Session error. Reconnect token";
            case TokenResult::ERR_PIN_INCORRECT:
                return "Incorrect PIN. Attempts left: 3";
            case TokenResult::ERR_PIN_LOCKED:
                return "PIN locked. PUK required";
            case TokenResult::ERR_KEY_NOT_FOUND:
                return "Key not found on Rutoken";
            case TokenResult::ERR_SIGN_FAILED:
                return "Signing failed on token";
            case TokenResult::ERR_DECRYPT_FAILED:
                return "Decryption failed";
            case TokenResult::ERR_ENCRYPT_FAILED:
                return "Encryption failed";
            case TokenResult::ERR_MEMORY:
                return "Insufficient token memory";
            case TokenResult::ERR_TIMEOUT:
                return "Token operation timeout";
            case TokenResult::ERR_NOT_SUPPORTED:
                return "Operation not supported by this Rutoken";
            case TokenResult::ERR_ACCESS_DENIED:
                return "Access denied. Check permissions";
            default:
                return "Unknown error";
        }
    }

    std::string GetVersion() const override {
        return "SecureVault PKCS#11 for Rutoken v2.0.0";
    }
};

// ============================================================================
// РЕГИСТРАЦИЯ МОДУЛЯ В ФАБРИКЕ
// ============================================================================

// Регистрируем RutokenModule в глобальной фабрике при загрузке модуля
static bool __rutoken_registered = []() {
    ModuleFactory::Instance().Register(
        TokenType::RUTOKEN,
        []() -> std::unique_ptr<ITokenModule> {
            return std::make_unique<RutokenModule>();
        },
        "RUTOKEN"
    );
    return true;
}();

} // namespace pkcs11
} // namespace securevault
