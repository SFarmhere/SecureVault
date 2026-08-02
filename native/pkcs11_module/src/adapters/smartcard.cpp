// ============================================================================
// SecureVault - Универсальный адаптер для смарт-карт через PC/SC
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// Поддерживаемые карты:
// - ГОСТ Р 34.10-2012 (КриптоПро)
// - Рутокен ЭЦП (PC/SC режим)
// - eToken PRO JavaCard
// - Generic ISO 7816
// - JaCarta
//
// ============================================================================

#include "../../include/pkcs11_api.h"
#include "../../include/session_types.h"  // для SessionId, SlotId
#include "../../include/token_types.h"    // для KeyInfo, KeyFlags, KeySizeBits
#include "module_factory.h"

// PC/SC API - платформозависимые включения и типы
#ifdef _WIN32
    #include <windows.h>
    #include <winscard.h>
    
    #define PCSC_LIB_HANDLE HMODULE
    #define PCSC_LOAD_LIB(x) LoadLibraryA(x)
    #define PCSC_GET_FUNC(h, f) GetProcAddress(h, f)
    #define PCSC_UNLOAD_LIB(h) FreeLibrary(h)
    
    // Windows-specific types (already defined in winscard.h)
    typedef DWORD PCSC_DWORD;
    typedef LONG PCSC_LONG;
    typedef BYTE PCSC_BYTE;
#else
    #include <dlfcn.h>
    #include <pcsclite.h>
    
    #define PCSC_LIB_HANDLE void*
    #define PCSC_LOAD_LIB(x) dlopen(x, RTLD_LAZY)
    #define PCSC_GET_FUNC(h, f) dlsym(h, f)
    #define PCSC_UNLOAD_LIB(h) dlclose(h)
    
    // Linux/macOS types from pcsclite.h
    typedef uint32_t PCSC_DWORD;
    typedef int32_t PCSC_LONG;
    typedef uint8_t PCSC_BYTE;
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
#include <thread>
#include <chrono>
#include <random>

// PKCS#11 определения
typedef unsigned long CK_ULONG;
typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_BYTE CK_BBOOL;
typedef CK_ULONG CK_KEY_TYPE;
typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_ULONG CK_MECHANISM_TYPE;

// Структура атрибута
struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    void* pValue;
    CK_ULONG ulValueLen;
};

// Флаги сессий
#define CKF_RW_SESSION          0x00000002
#define CKF_SERIAL_SESSION     0x00000004

// КОНСТАНТЫ TRUE/FALSE
#ifndef CK_TRUE
#define CK_TRUE 1
#endif
#ifndef CK_FALSE
#define CK_FALSE 0
#endif

// Механизмы
#define CKM_RSA_PKCS_KEY_PAIR_GEN 0x00000000
#define CKM_RSA_PKCS             0x00000001
#define CKM_RSA_PKCS_PSS        0x0000000D
#define CKM_SHA256_RSA_PKCS     0x00000040
#define CKM_SHA256_RSA_PKCS_PSS 0x00000043
#define CKM_SHA256             0x00000250

// Атрибуты объектов
#define CKA_CLASS              0x00000000
#define CKA_TOKEN             0x00000001
#define CKA_PRIVATE           0x00000002
#define CKA_LABEL             0x00000003
#define CKA_KEY_TYPE          0x00000100
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
#define CKA_LOCAL            0x00000143
#define CKA_ALWAYS_SENSITIVE 0x00000165
#define CKA_NEVER_EXTRACTABLE 0x00000166

// Классы объектов
#define CKO_PUBLIC_KEY      0x00000002
#define CKO_PRIVATE_KEY     0x00000003
#define CKO_CERTIFICATE     0x00000001
#define CKO_SECRET_KEY     0x00000005

// Типы ключей
#define CKK_RSA            0x00000000
#define CKK_AES            0x0000001F

// Стандартные ошибки PKCS#11
#define CKR_OK                       0x00000000
#define CKR_PIN_INCORRECT           0x000000A0
#define CKR_PIN_LOCKED             0x000000A4
#define CKR_SESSION_CLOSED         0x000000B0
#define CKR_SESSION_HANDLE_INVALID 0x000000B3
#define CKR_DEVICE_REMOVED         0x000000B6
#define CKR_FUNCTION_NOT_SUPPORTED 0x00000054

// ISO 7816 APDU команды
#define ISO_CLA_SMART_CARD  0x00
#define ISO_INS_SELECT      0xA4
#define ISO_INS_VERIFY      0x20
#define ISO_INS_CHANGE_PIN  0x24
#define ISO_INS_GENERATE    0x46
#define ISO_INS_PERFORM_SEC  0x2A

// Статус слова APDU
#define APDU_SW_SUCCESS     0x9000
#define APDU_SW_MORE_DATA   0x6100
#define APDU_SW_PIN_BASE    0x63C0
#define APDU_SW_PIN_LOCKED  0x6983
#define APDU_SW_SECURITY    0x6982
#define APDU_SW_FILE_NOT_FOUND 0x6A82

namespace securevault {
namespace pkcs11 {

// ============================================================================
// ТИПЫ PC/SC ФУНКЦИЙ (платформозависимые)
// ============================================================================

#ifdef _WIN32
// Windows: используем типы из winscard.h
typedef LONG (WINAPI *SCardEstablishContext_t)(DWORD, LPCVOID, LPCVOID, LPSCARDCONTEXT);
typedef LONG (WINAPI *SCardReleaseContext_t)(SCARDCONTEXT);
typedef LONG (WINAPI *SCardListReadersA_t)(SCARDCONTEXT, LPCSTR, LPSTR, LPDWORD);
typedef LONG (WINAPI *SCardConnectA_t)(SCARDCONTEXT, LPCSTR, DWORD, DWORD, LPSCARDHANDLE, LPDWORD);
typedef LONG (WINAPI *SCardDisconnect_t)(SCARDHANDLE, DWORD);
typedef LONG (WINAPI *SCardStatusA_t)(SCARDHANDLE, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LONG (WINAPI *SCardTransmit_t)(SCARDHANDLE, LPCSCARD_IO_REQUEST, LPCBYTE, DWORD,
                                       LPSCARD_IO_REQUEST, LPBYTE, LPDWORD);
typedef LONG (WINAPI *SCardGetStatusChangeA_t)(SCARDCONTEXT, DWORD, LPSCARD_READERSTATEA, DWORD);
#else
// Linux/macOS: используем типы из pcsclite.h
typedef PCSC_LONG (*SCardEstablishContext_t)(PCSC_DWORD, const void*, const void*, SCARDCONTEXT*);
typedef PCSC_LONG (*SCardReleaseContext_t)(SCARDCONTEXT);
typedef PCSC_LONG (*SCardListReaders_t)(SCARDCONTEXT, const char*, char*, PCSC_DWORD*);
typedef PCSC_LONG (*SCardConnect_t)(SCARDCONTEXT, const char*, PCSC_DWORD, PCSC_DWORD, SCARDHANDLE*, PCSC_DWORD*);
typedef PCSC_LONG (*SCardDisconnect_t)(SCARDHANDLE, PCSC_DWORD);
typedef PCSC_LONG (*SCardStatus_t)(SCARDHANDLE, char*, PCSC_DWORD*, PCSC_DWORD*, PCSC_DWORD*, PCSC_BYTE*, PCSC_DWORD*);
typedef PCSC_LONG (*SCardTransmit_t)(SCARDHANDLE, const SCARD_IO_REQUEST*, const PCSC_BYTE*, PCSC_DWORD,
                                     SCARD_IO_REQUEST*, PCSC_BYTE*, PCSC_DWORD*);
typedef PCSC_LONG (*SCardGetStatusChange_t)(SCARDCONTEXT, PCSC_DWORD, SCARD_READERSTATE*, PCSC_DWORD);
#endif

// ============================================================================
// ВСПОМОГАТЕЛЬНЫЕ СТРУКТУРЫ
// ============================================================================

/**
 * @brief Контекст PC/SC для одной карты
 */
struct PcscContext {
    SCARDCONTEXT global_ctx;        // Глобальный контекст PC/SC
    SCARDHANDLE card_handle;        // Хендл карты
    std::string reader_name;        // Имя читателя
    std::string atr;                // ATR карты (hex)
    CK_SLOT_ID slot_id;             // ID слота
    bool connected;                 // Подключена ли карта
};

/**
 * @brief Ответ APDU
 */
struct ApduResponse {
    std::vector<uint8_t> data;      // Данные ответа
    uint16_t sw;                    // Status Word (SW1 SW2)
    bool success() const { return sw == APDU_SW_SUCCESS; }
};

// ============================================================================
// РЕАЛИЗАЦИЯ МОДУЛЯ СМАРТ-КАРТ
// ============================================================================

/**
 * @brief Реализация ITokenModule для смарт-карт через PC/SC
 */
class SmartcardModule : public ITokenModule {
private:
    // ------------------------------------------------------------------------
    // ПОЛЯ КЛАССА
    // ------------------------------------------------------------------------

    PCSC_LIB_HANDLE pcsc_lib_;
    bool initialized_;
    mutable std::mutex mutex_;

    // Функции PC/SC
    SCardEstablishContext_t SCardEstablishContext_;
    SCardReleaseContext_t SCardReleaseContext_;
#ifdef _WIN32
    SCardListReadersA_t SCardListReaders_;
    SCardConnectA_t SCardConnect_;
    SCardDisconnect_t SCardDisconnect_;
    SCardStatusA_t SCardStatus_;
    SCardTransmit_t SCardTransmit_;
    SCardGetStatusChangeA_t SCardGetStatusChange_;
#else
    SCardListReaders_t SCardListReaders_;
    SCardConnect_t SCardConnect_;
    SCardDisconnect_t SCardDisconnect_;
    SCardStatus_t SCardStatus_;
    SCardTransmit_t SCardTransmit_;
    SCardGetStatusChange_t SCardGetStatusChange_;
#endif

    SCARDCONTEXT pcsc_context_;
    std::vector<std::string> readers_;

    // Активные карты: internal_id -> PcscContext
    std::map<int, PcscContext> cards_;
    int next_card_id_;

    // ------------------------------------------------------------------------
    // ВНУТРЕННИЕ МЕТОДЫ
    // ------------------------------------------------------------------------

    /**
     * @brief Загрузить PC/SC библиотеку
     */
    TokenResult LoadPcscLibrary() {
#ifdef _WIN32
        pcsc_lib_ = PCSC_LOAD_LIB("winscard.dll");
#elif defined(__APPLE__)
        pcsc_lib_ = PCSC_LOAD_LIB("/System/Library/Frameworks/PCSC.framework/PCSC");
#else
        pcsc_lib_ = PCSC_LOAD_LIB("libpcsclite.so.1");
#endif

        if (!pcsc_lib_) {
            return TokenResult::ERR_NOT_SUPPORTED;
        }

        // Загружаем функции
        SCardEstablishContext_ = (SCardEstablishContext_t)PCSC_GET_FUNC(pcsc_lib_, "SCardEstablishContext");
        SCardReleaseContext_ = (SCardReleaseContext_t)PCSC_GET_FUNC(pcsc_lib_, "SCardReleaseContext");
        
#ifdef _WIN32
        SCardListReaders_ = (SCardListReadersA_t)PCSC_GET_FUNC(pcsc_lib_, "SCardListReadersA");
        SCardConnect_ = (SCardConnectA_t)PCSC_GET_FUNC(pcsc_lib_, "SCardConnectA");
        SCardDisconnect_ = (SCardDisconnect_t)PCSC_GET_FUNC(pcsc_lib_, "SCardDisconnect");
        SCardStatus_ = (SCardStatusA_t)PCSC_GET_FUNC(pcsc_lib_, "SCardStatusA");
        SCardTransmit_ = (SCardTransmit_t)PCSC_GET_FUNC(pcsc_lib_, "SCardTransmit");
        SCardGetStatusChange_ = (SCardGetStatusChangeA_t)PCSC_GET_FUNC(pcsc_lib_, "SCardGetStatusChangeA");
#else
        SCardListReaders_ = (SCardListReaders_t)PCSC_GET_FUNC(pcsc_lib_, "SCardListReaders");
        SCardConnect_ = (SCardConnect_t)PCSC_GET_FUNC(pcsc_lib_, "SCardConnect");
        SCardDisconnect_ = (SCardDisconnect_t)PCSC_GET_FUNC(pcsc_lib_, "SCardDisconnect");
        SCardStatus_ = (SCardStatus_t)PCSC_GET_FUNC(pcsc_lib_, "SCardStatus");
        SCardTransmit_ = (SCardTransmit_t)PCSC_GET_FUNC(pcsc_lib_, "SCardTransmit");
        SCardGetStatusChange_ = (SCardGetStatusChange_t)PCSC_GET_FUNC(pcsc_lib_, "SCardGetStatusChange");
#endif

        if (!SCardEstablishContext_ || !SCardListReaders_ || !SCardConnect_) {
            return TokenResult::ERR_NOT_SUPPORTED;
        }

        return TokenResult::SUCCESS;
    }

    /**
     * @brief Получить список читателей
     */
    TokenResult ListReaders() {
        if (!SCardListReaders_) {
            return TokenResult::ERR_NOT_SUPPORTED;
        }

        // Сначала получаем размер буфера
        PCSC_DWORD readers_len = 0;
        PCSC_LONG result = SCardListReaders_(pcsc_context_, nullptr, nullptr, &readers_len);

        if (result != SCARD_S_SUCCESS || readers_len == 0) {
            readers_.clear();
            return TokenResult::ERR_GENERAL;
        }

        // Выделяем буфер
        std::vector<char> readers_buf(readers_len);
        result = SCardListReaders_(pcsc_context_, nullptr, readers_buf.data(), &readers_len);

        if (result != SCARD_S_SUCCESS) {
            readers_.clear();
            return TokenResult::ERR_GENERAL;
        }

        // Парсим список читателей (разделен нулями, двойной нуль в конце)
        readers_.clear();
        char* p = readers_buf.data();
        while (*p) {
            readers_.push_back(p);
            p += strlen(p) + 1;
        }

        return TokenResult::SUCCESS;
    }

    /**
     * @brief Получить ATR карты
     */
    TokenResult GetCardAtr(PcscContext& ctx, std::string& atr) {
        if (!SCardStatus_) {
            return TokenResult::ERR_NOT_SUPPORTED;
        }

        PCSC_DWORD atr_len = 64;
        PCSC_BYTE atr_buf[64];
        PCSC_DWORD state, protocol;

        PCSC_LONG result = SCardStatus_(ctx.card_handle, nullptr, nullptr, &state, &protocol,
                                   atr_buf, &atr_len);

        if (result != SCARD_S_SUCCESS) {
            return TokenResult::ERR_GENERAL;
        }

        // Конвертируем в hex строку
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (PCSC_DWORD i = 0; i < atr_len; ++i) {
            ss << std::setw(2) << (int)atr_buf[i] << " ";
        }
        atr = ss.str();

        return TokenResult::SUCCESS;
    }

    /**
     * @brief Отправить APDU команду
     */
    ApduResponse TransmitApdu(SCARDHANDLE handle, const std::vector<uint8_t>& apdu) {
        ApduResponse response;
        response.sw = 0;

        if (!SCardTransmit_) {
            return response;
        }

        SCARD_IO_REQUEST pio_send;
        SCARD_IO_REQUEST pio_recv;

        // Получаем параметры протокола
        PCSC_LONG result = SCardStatus_(handle, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
        if (result != SCARD_S_SUCCESS) {
            return response;
        }

        // Отправляем APDU
        PCSC_BYTE recv_buf[256];
        PCSC_DWORD recv_len = sizeof(recv_buf);

        result = SCardTransmit_(handle, &pio_send, apdu.data(), (PCSC_DWORD)apdu.size(),
                               &pio_recv, recv_buf, &recv_len);

        if (result != SCARD_S_SUCCESS) {
            return response;
        }

        // Парсим ответ (data + SW1 SW2)
        if (recv_len >= 2) {
            response.data.assign(recv_buf, recv_buf + recv_len - 2);
            response.sw = (recv_buf[recv_len - 2] << 8) | recv_buf[recv_len - 1];
        }

        return response;
    }

    /**
     * @brief Проверить PIN через APDU
     */
    TokenResult VerifyPin(PcscContext& ctx, const std::string& pin) {
        // Формируем APDU: CLA=0x00, INS=0x20, P1=0x00, P2=0x00, Lc=pin_len, data=pin+0xFF
        std::vector<uint8_t> apdu;
        apdu.push_back(ISO_CLA_SMART_CARD);
        apdu.push_back(ISO_INS_VERIFY);
        apdu.push_back(0x00);
        apdu.push_back(0x00);
        apdu.push_back((uint8_t)(pin.length() + 1));
        apdu.insert(apdu.end(), pin.begin(), pin.end());
        apdu.push_back(0xFF);  // Padding

        ApduResponse response = TransmitApdu(ctx.card_handle, apdu);

        if (response.sw == APDU_SW_SUCCESS) {
            return TokenResult::SUCCESS;
        } else if ((response.sw & 0xFFF0) == APDU_SW_PIN_BASE) {
            // PIN неверен, количество попыток = SW & 0x0F
            return TokenResult::ERR_PIN_INCORRECT;
        } else if (response.sw == APDU_SW_PIN_LOCKED) {
            return TokenResult::ERR_PIN_LOCKED;
        } else {
            return TokenResult::ERR_GENERAL;
        }
    }

    /**
     * @brief Генерировать уникальный ID
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

public:
    // ------------------------------------------------------------------------
    // КОНСТРУКТОР / ДЕСТРУКТОР
    // ------------------------------------------------------------------------

    SmartcardModule()
        : pcsc_lib_(nullptr)
        , initialized_(false)
        , SCardEstablishContext_(nullptr)
        , SCardReleaseContext_(nullptr)
        , SCardListReaders_(nullptr)
        , SCardConnect_(nullptr)
        , SCardDisconnect_(nullptr)
        , SCardStatus_(nullptr)
        , SCardTransmit_(nullptr)
        , SCardGetStatusChange_(nullptr)
        , pcsc_context_(0)
        , next_card_id_(3000)
    {
    }

    ~SmartcardModule() override {
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

        // Загружаем PC/SC библиотеку
        TokenResult result = LoadPcscLibrary();
        if (result != TokenResult::SUCCESS) {
            return result;
        }

        // Инициализируем PC/SC контекст
        PCSC_LONG rc = SCardEstablishContext_(SCARD_SCOPE_USER, nullptr, nullptr, &pcsc_context_);
        if (rc != SCARD_S_SUCCESS) {
            PCSC_UNLOAD_LIB(pcsc_lib_);
            pcsc_lib_ = nullptr;
            return TokenResult::ERR_GENERAL;
        }

        // Получаем список читателей
        result = ListReaders();
        if (result != TokenResult::SUCCESS) {
            SCardReleaseContext_(pcsc_context_);
            PCSC_UNLOAD_LIB(pcsc_lib_);
            pcsc_lib_ = nullptr;
            return result;
        }

        initialized_ = true;
        return TokenResult::SUCCESS;
    }

    void Finalize() override {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!initialized_) {
            return;
        }

        // Закрываем все карты
        for (auto& pair : cards_) {
            if (SCardDisconnect_ && pair.second.connected) {
                SCardDisconnect_(pair.second.card_handle, SCARD_LEAVE_CARD);
            }
        }
        cards_.clear();

        // Освобождаем контекст
        if (SCardReleaseContext_ && pcsc_context_) {
            SCardReleaseContext_(pcsc_context_);
            pcsc_context_ = 0;
        }

        // Выгружаем библиотеку
        if (pcsc_lib_) {
            PCSC_UNLOAD_LIB(pcsc_lib_);
            pcsc_lib_ = nullptr;
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

        // Обновляем список читателей
        ListReaders();

        // Для каждого читателя проверяем наличие карты
        for (size_t i = 0; i < readers_.size(); ++i) {
            SCARDHANDLE handle;
            PCSC_DWORD active_protocol;

            PCSC_LONG rc = SCardConnect_(pcsc_context_, readers_[i].c_str(),
                                   SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                                   &handle, &active_protocol);

            if (rc == SCARD_S_SUCCESS) {
                // Карта присутствует
                TokenInfo info;
                strncpy(info.manufacturer_name, "SmartCard", sizeof(info.manufacturer_name) - 1);
                strncpy(info.model, "ISO 7816", sizeof(info.model) - 1);
                strncpy(info.serial_number, "N/A", sizeof(info.serial_number) - 1);
                strncpy(info.label, readers_[i].c_str(), sizeof(info.label) - 1);

                // Получаем ATR
                PcscContext ctx;
                ctx.card_handle = handle;
                std::string atr;
                GetCardAtr(ctx, atr);
                strncpy(info.serial_number, atr.c_str(), sizeof(info.serial_number) - 1);

                info.total_memory = 0;  // Неизвестно для generic карт
                info.free_memory = 0;
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

                // Отключаемся
                SCardDisconnect_(handle, SCARD_LEAVE_CARD);
            }
        }

        return tokens;
    }

    SessionId OpenSession(SlotId slot_id, const std::string& pin) override {
        if (!initialized_) {
            return -1;
        }

        std::lock_guard<std::mutex> lock(mutex_);

        if (slot_id >= readers_.size()) {
            return -1;
        }

        // Подключаемся к карте
        SCARDHANDLE handle;
        PCSC_DWORD active_protocol;

        PCSC_LONG rc = SCardConnect_(pcsc_context_, readers_[slot_id].c_str(),
                               SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                               &handle, &active_protocol);

        if (rc != SCARD_S_SUCCESS) {
            return -1;
        }

        // Создаем контекст
        PcscContext ctx;
        ctx.global_ctx = pcsc_context_;
        ctx.card_handle = handle;
        ctx.reader_name = readers_[slot_id];
        ctx.slot_id = slot_id;
        ctx.connected = true;

        // Получаем ATR
        TokenResult result = GetCardAtr(ctx, ctx.atr);
        if (result != TokenResult::SUCCESS) {
            SCardDisconnect_(handle, SCARD_LEAVE_CARD);
            return -1;
        }

        // Проверяем PIN
        result = VerifyPin(ctx, pin);
        if (result != TokenResult::SUCCESS) {
            SCardDisconnect_(handle, SCARD_LEAVE_CARD);
            return -1;
        }

        // Сохраняем контекст
        int internal_id = next_card_id_++;
        cards_[internal_id] = ctx;

        return static_cast<SessionId>(internal_id);
    }

    void CloseSession(SessionId session_id) override {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = cards_.find(static_cast<int>(session_id));
        if (it != cards_.end()) {
            if (SCardDisconnect_ && it->second.connected) {
                SCardDisconnect_(it->second.card_handle, SCARD_LEAVE_CARD);
            }
            cards_.erase(it);
        }
    }

    bool IsSessionValid(SessionId session_id) const override {
        std::lock_guard<std::mutex> lock(mutex_);
        return cards_.find(static_cast<int>(session_id)) != cards_.end();
    }

    TokenResult ChangePin(SessionId session_id,
                         const std::string& old_pin,
                         const std::string& new_pin) override {
        if (!initialized_) {
            return TokenResult::ERR_NOT_INITIALIZED;
        }

        std::lock_guard<std::mutex> lock(mutex_);

        auto it = cards_.find(static_cast<int>(session_id));
        if (it == cards_.end()) {
            return TokenResult::ERR_SESSION_ERROR;
        }

        // Формируем APDU для смены PIN: CLA=0x00, INS=0x24, P1=0x00, P2=0x00
        std::vector<uint8_t> apdu;
        apdu.push_back(ISO_CLA_SMART_CARD);
        apdu.push_back(ISO_INS_CHANGE_PIN);
        apdu.push_back(0x00);
        apdu.push_back(0x00);
        apdu.push_back((uint8_t)(old_pin.length() + new_pin.length() + 2));
        apdu.insert(apdu.end(), old_pin.begin(), old_pin.end());
        apdu.push_back(0xFF);
        apdu.insert(apdu.end(), new_pin.begin(), new_pin.end());
        apdu.push_back(0xFF);

        ApduResponse response = TransmitApdu(it->second.card_handle, apdu);

        if (response.sw == APDU_SW_SUCCESS) {
            return TokenResult::SUCCESS;
        } else {
            return TokenResult::ERR_GENERAL;
        }
    }

    // ------------------------------------------------------------------------
    // УПРАВЛЕНИЕ КЛЮЧАМИ
    // ------------------------------------------------------------------------

    std::string GenerateRsaKeyPair(SessionId session_id, const RsaKeyParams& params) override {
        if (!initialized_) {
            return "";
        }

        std::lock_guard<std::mutex> lock(mutex_);

        auto it = cards_.find(static_cast<int>(session_id));
        if (it == cards_.end()) {
            return "";
        }

        // Генерируем ID ключа
        std::string key_id = GenerateKeyId();

        // TODO: Реализовать генерацию ключей через APDU
        // Заглушка для совместимости
        return key_id;
    }

    std::vector<KeyInfo> ListKeys(SessionId session_id) override {
        std::vector<KeyInfo> keys;

        if (!initialized_) {
            return keys;
        }

        std::lock_guard<std::mutex> lock(mutex_);

        auto it = cards_.find(static_cast<int>(session_id));
        if (it == cards_.end()) {
            return keys;
        }

        // TODO: Реализовать чтение ключей через APDU
        // Заглушка для совместимости

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

        std::lock_guard<std::mutex> lock(mutex_);

        auto it = cards_.find(static_cast<int>(session_id));
        if (it == cards_.end()) {
            return TokenResult::ERR_SESSION_ERROR;
        }

        // TODO: Реализовать удаление ключа через APDU

        return TokenResult::ERR_NOT_SUPPORTED;
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

        std::lock_guard<std::mutex> lock(mutex_);

        auto it = cards_.find(static_cast<int>(session_id));
        if (it == cards_.end()) {
            return signature;
        }

        // TODO: Реализовать подпись через APDU (PERFORM SECURITY OPERATION)

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

        std::lock_guard<std::mutex> lock(mutex_);

        auto it = cards_.find(static_cast<int>(session_id));
        if (it == cards_.end()) {
            return false;
        }

        // TODO: Реализовать верификацию через APDU

        return false;
    }

    std::vector<uint8_t> EncryptRsa(SessionId session_id,
                                   const std::string& key_id,
                                   const std::vector<uint8_t>& plaintext,
                                   const RsaEncryptParams& params) override {
        std::vector<uint8_t> ciphertext;

        if (!initialized_) {
            return ciphertext;
        }

        std::lock_guard<std::mutex> lock(mutex_);

        auto it = cards_.find(static_cast<int>(session_id));
        if (it == cards_.end()) {
            return ciphertext;
        }

        // TODO: Реализовать шифрование через APDU

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

        std::lock_guard<std::mutex> lock(mutex_);

        auto it = cards_.find(static_cast<int>(session_id));
        if (it == cards_.end()) {
            return plaintext;
        }

        // TODO: Реализовать расшифрование через APDU

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
                return "SmartCard PC/SC general error";
            case TokenResult::ERR_NOT_INITIALIZED:
                return "SmartCard module not initialized";
            case TokenResult::ERR_TOKEN_NOT_FOUND:
                return "No smart card readers found";
            case TokenResult::ERR_SESSION_ERROR:
                return "SmartCard session error";
            case TokenResult::ERR_PIN_INCORRECT:
                return "Incorrect PIN";
            case TokenResult::ERR_PIN_LOCKED:
                return "PIN locked";
            case TokenResult::ERR_KEY_NOT_FOUND:
                return "Key not found on card";
            case TokenResult::ERR_SIGN_FAILED:
                return "Signing failed";
            case TokenResult::ERR_DECRYPT_FAILED:
                return "Decryption failed";
            case TokenResult::ERR_ENCRYPT_FAILED:
                return "Encryption failed";
            case TokenResult::ERR_NOT_SUPPORTED:
                return "Operation not supported";
            case TokenResult::ERR_ACCESS_DENIED:
                return "Access denied";
            default:
                return "Unknown error";
        }
    }

    std::string GetVersion() const override {
        return "SecureVault PC/SC for SmartCards v2.0.0";
    }
};

// ============================================================================
// РЕГИСТРАЦИЯ МОДУЛЯ В ФАБРИКЕ
// ============================================================================

// Регистрируем SmartcardModule в глобальной фабрике
static bool __smartcard_registered = []() {
    ModuleFactory::Instance().Register(
        TokenType::PCSC_SMARTCARD,
        []() -> std::unique_ptr<ITokenModule> {
            return std::make_unique<SmartcardModule>();
        },
        "PCSC_SMARTCARD"
    );
    return true;
}();

} // namespace pkcs11
} // namespace securevault