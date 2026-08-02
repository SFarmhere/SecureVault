// ============================================================================
// SecureVault - Менеджер слотов PKCS#11 и хотплаг токенов
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// НАЗНАЧЕНИЕ:
//   Централизованное управление слотами PKCS#11, обнаружение токенов,
//   обработка горячего подключения/отключения (hotplug), мониторинг состояния.
//
// ВХОДНЫЕ ДАННЫЕ (ОТКУДА):
//   - SessionManager: запросы на получение списка доступных слотов
//   - Системные события: USB hotplug (libudev/SetupAPI/IOKit)
//   - Таймеры: периодический опрос состояния токенов
//   - GUI: запрос статуса токена для индикатора
//
// ВЫХОДНЫЕ ДАННЫЕ (КУДА):
//   - В SessionManager: актуальный список слотов с токенами
//   - В GUI (token_indicator.py): события подключения/отключения
//   - В Emergency (wipe_controller.py): сигнал об извлечении токена
//   - В Audit (audit_backend.py): логи событий с токенами
//   - В Metrics: статистика использования токенов
//
// ЗАВИСИМОСТИ:
//   - libudev (Linux) / SetupAPI (Windows) / IOKit (macOS)
//   - pthread / std::thread
// ============================================================================

#include "../../include/pkcs11_api.h"
#include "../../include/session_types.h"  // для SlotId, SlotState, SlotEventType
#include "../../include/token_types.h"    // для TokenType, TokenInfo
#include "../adapters/module_factory.h"

#include <vector>
#include <string>
#include <memory>
#include <mutex>
#include <map>
#include <set>
#include <functional>
#include <thread>
#include <chrono>
#include <atomic>
#include <condition_variable>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>

// ============================================================================
// ПЛАТФОРМО-ЗАВИСИМЫЕ ЗАГОЛОВКИ ДЛЯ ХОТПЛАГА
// ============================================================================

#ifdef _WIN32
    #include <windows.h>
    #include <dbt.h>
    #include <setupapi.h>
    #include <devguid.h>
    #include <cfgmgr32.h>
    #pragma comment(lib, "setupapi.lib")
    #pragma comment(lib, "user32.lib")
    
    // Prevent collision with Windows ERROR macro (defined as 0 in windows.h)
    // This must be done before using SlotState::ERROR enum value
    #ifdef ERROR
    #undef ERROR
    #endif
#elif defined(__linux__)
    #include <libudev.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/select.h>
    #include <dlfcn.h>
#elif defined(__APPLE__)
    #include <dlfcn.h>
    #include <IOKit/IOKitLib.h>
    #include <IOKit/usb/IOUSBLib.h>
    #include <IOKit/hid/IOHIDManager.h>
    #include <CoreFoundation/CoreFoundation.h>
#endif

namespace securevault {
namespace pkcs11 {

#ifdef _WIN32
// GUID для USB устройств
static const GUID GUID_DEVINTERFACE_USB_DEVICE = 
    {0xA5DCBF10L, 0x6530, 0x11D2, {0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED}};
#endif

// ============================================================================
// PKCS#11 TYPE DEFINITIONS (minimal subset for dynamic loading)
// ============================================================================

using CK_BYTE = unsigned char;              ///< 8-bit unsigned integer
using CK_BBOOL = CK_BYTE;                   ///< Boolean type (CK_TRUE=1, CK_FALSE=0)
using CK_ULONG = unsigned long;             ///< 32-bit unsigned integer (Windows) / 64-bit (Linux 64-bit)
using CK_LONG = long;                       ///< Signed long
using CK_SLOT_ID = CK_ULONG;                ///< Slot ID type
using CK_SESSION_HANDLE = CK_ULONG;         ///< Session handle
using CK_OBJECT_HANDLE = CK_ULONG;          ///< Object handle
using CK_VOID_PTR = void*;                  ///< Generic pointer
using CK_CHAR_PTR = char*;                  ///< String pointer
using CK_USER_TYPE = CK_ULONG;              ///< User type for login

constexpr CK_BBOOL CK_TRUE = 1;             ///< Boolean true
constexpr CK_BBOOL CK_FALSE = 0;            ///< Boolean false

/**
 * @brief Return values for PKCS#11 functions
 */
using CK_RV = CK_ULONG;

// Additional PKCS#11 types (needed before function pointer typedefs)
using CK_CHAR = CK_BYTE;
using CK_ATTRIBUTE_TYPE = CK_ULONG;
using CK_FLAGS = CK_ULONG;
using CK_NOTIFY = CK_RV (*)(CK_SESSION_HANDLE hSession, CK_ULONG event, CK_VOID_PTR pApplication);
using CK_SLOT_ID_PTR = CK_SLOT_ID*;
using CK_SESSION_HANDLE_PTR = CK_SESSION_HANDLE*;
using CK_OBJECT_HANDLE_PTR = CK_OBJECT_HANDLE*;
using CK_ULONG_PTR = CK_ULONG*;
using CK_BYTE_PTR = CK_BYTE*;
using CK_VOID_PTR_PTR = CK_VOID_PTR*;
using CK_UTF8CHAR_PTR = CK_CHAR_PTR;

// Additional PKCS#11 types for function pointer typedefs
using CK_MECHANISM_TYPE = CK_ULONG;
using CK_MECHANISM_TYPE_PTR = CK_MECHANISM_TYPE*;

struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR pParameter;
    CK_ULONG ulParameterLen;
};
using CK_MECHANISM_PTR = CK_MECHANISM*;

struct CK_MECHANISM_INFO {
    CK_ULONG ulMinKeySize;
    CK_ULONG ulMaxKeySize;
    CK_FLAGS flags;
};
using CK_MECHANISM_INFO_PTR = CK_MECHANISM_INFO*;

struct CK_SESSION_INFO {
    CK_SLOT_ID slotID;
    CK_ULONG ulDeviceError;
    CK_FLAGS flags;
};
using CK_SESSION_INFO_PTR = CK_SESSION_INFO*;

struct CK_TOKEN_INFO {
    CK_BYTE label[32];
    CK_CHAR manufacturerID[32];
    CK_CHAR model[16];
    CK_ULONG flags;
    CK_ULONG ulMaxSessionCount;
    CK_ULONG ulSessionCount;
    CK_ULONG ulMaxPinLen;
    CK_ULONG ulMinPinLen;
    CK_ULONG ulTotalPublicMemory;
    CK_ULONG ulFreePublicMemory;
    CK_ULONG ulTotalPrivateMemory;
    CK_ULONG ulFreePrivateMemory;
    CK_BYTE hardwareVersionMajor;
    CK_BYTE hardwareVersionMinor;
    CK_BYTE firmwareVersionMajor;
    CK_BYTE firmwareVersionMinor;
    CK_BYTE serialNumber[16];
};
using CK_TOKEN_INFO_PTR = CK_TOKEN_INFO*;

struct CK_SLOT_INFO {
    CK_BYTE slotDescription[64];
    CK_CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_BYTE hardwareVersionMajor;
    CK_BYTE hardwareVersionMinor;
    CK_BYTE firmwareVersionMajor;
    CK_BYTE firmwareVersionMinor;
};
using CK_SLOT_INFO_PTR = CK_SLOT_INFO*;

struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR pValue;
    CK_ULONG ulValueLen;
};
using CK_ATTRIBUTE_PTR = CK_ATTRIBUTE*;

struct CK_INTERFACE {
    CK_UTF8CHAR_PTR pInterfaceName;
    CK_VOID_PTR pInterface;
    CK_FLAGS flags;
};
using CK_INTERFACE_PTR_PTR = CK_INTERFACE**;

struct CK_FUNCTION_LIST;
using CK_FUNCTION_LIST_PTR_PTR = CK_FUNCTION_LIST**;

constexpr CK_RV CKR_OK = 0;                 ///< Success
constexpr CK_RV CKR_CANCEL = 1;             ///< Operation canceled
constexpr CK_RV CKR_HOST_MEMORY = 2;        ///< Host memory unavailable
constexpr CK_RV CKR_SLOT_ID_INVALID = 3;    ///< Invalid slot ID
constexpr CK_RV CKR_GENERAL_ERROR = 5;      ///< General error
constexpr CK_RV CKR_FUNCTION_FAILED = 6;    ///< Function failed
constexpr CK_RV CKR_ARGUMENTS_BAD = 7;      ///< Invalid arguments
constexpr CK_RV CKR_NO_EVENT = 8;           ///< No event available
constexpr CK_RV CKR_CANT_LOCK = 9;          ///< Can't lock mechanism
constexpr CK_RV CKR_ATTRIBUTE_READ_ONLY = 10; ///< Attribute is read-only
constexpr CK_RV CKR_ATTRIBUTE_SENSITIVE = 11; ///< Attribute is sensitive
constexpr CK_RV CKR_ATTRIBUTE_TYPE_INVALID = 12; ///< Invalid attribute type
constexpr CK_RV CKR_ATTRIBUTE_VALUE_INVALID = 13; ///< Invalid attribute value
constexpr CK_RV CKR_DATA_INVALID = 20;      ///< Invalid data
constexpr CK_RV CKR_DATA_LEN_RANGE = 21;    ///< Data length out of range
constexpr CK_RV CKR_DEVICE_ERROR = 30;      ///< Device error
constexpr CK_RV CKR_DEVICE_MEMORY = 31;     ///< Device memory unavailable
constexpr CK_RV CKR_DEVICE_REMOVED = 32;    ///< Device removed
constexpr CK_RV CKR_ENCRYPTED_DATA_INVALID = 33; ///< Encrypted data invalid
constexpr CK_RV CKR_ENCRYPTED_DATA_LEN_RANGE = 34; ///< Encrypted data length out of range
constexpr CK_RV CKR_PIN_INCORRECT = 50;     ///< PIN incorrect
constexpr CK_RV CKR_PIN_INVALID = 51;       ///< Invalid PIN
constexpr CK_RV CKR_PIN_LEN_RANGE = 52;     ///< PIN length out of range
constexpr CK_RV CKR_PIN_EXPIRED = 53;       ///< PIN expired
constexpr CK_RV CKR_PIN_LOCKED = 54;        ///< PIN locked
constexpr CK_RV CKR_SESSION_CLOSED = 60;    ///< Session closed
constexpr CK_RV CKR_SESSION_COUNT = 61;     ///< Session count exceeded
constexpr CK_RV CKR_SESSION_HANDLE_INVALID = 62; ///< Invalid session handle
constexpr CK_RV CKR_SESSION_PARALLEL_NOT_SUPPORTED = 63; ///< Parallel sessions not supported
constexpr CK_RV CKR_SESSION_READ_ONLY = 64; ///< Session read-only
constexpr CK_RV CKR_SESSION_EXISTS = 65;    ///< Session already exists
constexpr CK_RV CKR_SESSION_READ_ONLY_EXISTS = 66; ///< Read-only session exists
constexpr CK_RV CKR_SESSION_READ_WRITE_SO_EXISTS = 67; ///< R/W SO session exists
constexpr CK_RV CKR_TOKEN_NOT_PRESENT = 70; ///< Token not present
constexpr CK_RV CKR_TOKEN_NOT_RECOGNIZED = 71; ///< Token not recognized
constexpr CK_RV CKR_TOKEN_WRITE_PROTECTED = 72; ///< Token write-protected
constexpr CK_RV CKR_USER_NOT_LOGGED_IN = 80; ///< User not logged in
constexpr CK_RV CKR_USER_ANOTHER_ALREADY_LOGGED_IN = 81; ///< Another user already logged in
constexpr CK_RV CKR_USER_PIN_NOT_INITIALIZED = 82; ///< User PIN not initialized
constexpr CK_RV CKR_BUFFER_TOO_SMALL = 100; ///< Buffer too small
constexpr CK_RV CKR_CRYPTOKI_ALREADY_INITIALIZED = 101; ///< Cryptoki already initialized
constexpr CK_RV CKR_CRYPTOKI_NOT_INITIALIZED = 102; ///< Cryptoki not initialized
constexpr CK_RV CKR_FUNCTION_NOT_SUPPORTED = 103; ///< Function not supported
constexpr CK_RV CKR_KEY_HANDLE_INVALID = 110; ///< Invalid key handle
constexpr CK_RV CKR_KEY_SIZE_RANGE = 111;    ///< Key size out of range
constexpr CK_RV CKR_KEY_TYPE_INCONSISTENT = 112; ///< Key type inconsistent
constexpr CK_RV CKR_KEY_NOT_NEEDED = 113;   ///< Key not needed
constexpr CK_RV CKR_KEY_CHANGED = 114;      ///< Key changed
constexpr CK_RV CKR_KEY_NEEDED = 115;       ///< Key needed
constexpr CK_RV CKR_KEY_INDIGESTIBLE = 116; ///< Key indigestible
constexpr CK_RV CKR_KEY_FUNCTION_NOT_PERMITTED = 117; ///< Key function not permitted
constexpr CK_RV CKR_KEY_NOT_WRAPPABLE = 118; ///< Key not wrappable
constexpr CK_RV CKR_KEY_UNEXTRACTABLE = 119; ///< Key unextractable
constexpr CK_RV CKR_MECHANISM_INVALID = 120; ///< Invalid mechanism
constexpr CK_RV CKR_MECHANISM_PARAM_INVALID = 121; ///< Invalid mechanism parameter
constexpr CK_RV CKR_OBJECT_HANDLE_INVALID = 130; ///< Invalid object handle
constexpr CK_RV CKR_OPERATION_ACTIVE = 131; ///< Operation active
constexpr CK_RV CKR_OPERATION_NOT_INITIALIZED = 132; ///< Operation not initialized
constexpr CK_RV CKR_SIGNATURE_INVALID = 140; ///< Invalid signature
constexpr CK_RV CKR_SIGNATURE_LEN_RANGE = 141; ///< Signature length out of range
constexpr CK_RV CKR_TEMPLATE_INCOMPLETE = 150; ///< Template incomplete
constexpr CK_RV CKR_TEMPLATE_INCONSISTENT = 151; ///< Template inconsistent
constexpr CK_RV CKR_WRAPPING_KEY_HANDLE_INVALID = 160; ///< Invalid wrapping key handle
constexpr CK_RV CKR_WRAPPING_KEY_SIZE_RANGE = 161; ///< Wrapping key size out of range
constexpr CK_RV CKR_WRAPPING_KEY_TYPE_INCONSISTENT = 162; ///< Wrapping key type inconsistent
constexpr CK_RV CKR_UNWRAPPING_KEY_HANDLE_INVALID = 163; ///< Invalid unwrapping key handle
constexpr CK_RV CKR_UNWRAPPING_KEY_SIZE_RANGE = 164; ///< Unwrapping key size out of range
constexpr CK_RV CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT = 165; ///< Unwrapping key type inconsistent
constexpr CK_RV CKR_DOMAIN_PARAMS_INVALID = 170; ///< Invalid domain parameters
constexpr CK_RV CKR_RANDOM_SEED_NOT_SUPPORTED = 200; ///< Random seed not supported
constexpr CK_RV CKR_RANDOM_NO_RNG = 201;      ///< No random number generator available
constexpr CK_RV CKR_SAVED_STATE_INVALID = 210; ///< Saved state invalid
constexpr CK_RV CKR_INFORMATION_SENSITIVE = 211; ///< Information sensitive
constexpr CK_RV CKR_STATE_UNSAVEABLE = 212;   ///< State unsaveable
constexpr CK_RV CKR_MUTEX_BAD = 220;          ///< Bad mutex
constexpr CK_RV CKR_MUTEX_NOT_LOCKED = 221;   ///< Mutex not locked
constexpr CK_RV CKR_VENDOR_DEFINED = 0x80000000; ///< Vendor-defined error

// PKCS#11 function pointer types
typedef CK_RV (*C_GetSlotListFunc)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
typedef CK_RV (*C_InitializeFunc)(CK_VOID_PTR pInitArgs);
typedef CK_RV (*C_FinalizeFunc)(CK_VOID_PTR pReserved);
typedef CK_RV (*C_OpenSessionFunc)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
typedef CK_RV (*C_CloseSessionFunc)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*C_LoginFunc)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_CHAR_PTR pPin, CK_ULONG ulPinLen);
typedef CK_RV (*C_LogoutFunc)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*C_FindObjectsFunc)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
typedef CK_RV (*C_GetAttributeValueFunc)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
typedef CK_RV (*C_SignInitFunc)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*C_SignFunc)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*C_VerifyInitFunc)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*C_VerifyFunc)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
typedef CK_RV (*C_EncryptInitFunc)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*C_EncryptFunc)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
typedef CK_RV (*C_DecryptInitFunc)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*C_DecryptFunc)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
typedef CK_RV (*C_GenerateKeyFunc)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (*C_GenerateKeyPairFunc)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
typedef CK_RV (*C_DestroyObjectFunc)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
typedef CK_RV (*C_GetTokenInfoFunc)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
typedef CK_RV (*C_GetSlotInfoFunc)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
typedef CK_RV (*C_GetMechanismListFunc)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
typedef CK_RV (*C_GetMechanismInfoFunc)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);
typedef CK_RV (*C_InitTokenFunc)(CK_SLOT_ID slotID, CK_CHAR_PTR pPin, CK_ULONG ulPinLen, CK_CHAR_PTR pLabel);
typedef CK_RV (*C_InitPINFunc)(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pPin, CK_ULONG ulPinLen);
typedef CK_RV (*C_SetPINFunc)(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen);
typedef CK_RV (*C_GetSessionInfoFunc)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
typedef CK_RV (*C_GetObjectSizeFunc)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);
typedef CK_RV (*C_CreateObjectFunc)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
typedef CK_RV (*C_CopyObjectFunc)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject);
typedef CK_RV (*C_DeriveKeyFunc)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (*C_DigestInitFunc)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);
typedef CK_RV (*C_DigestFunc)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
typedef CK_RV (*C_DigestUpdateFunc)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef CK_RV (*C_DigestKeyFunc)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*C_SignUpdateFunc)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef CK_RV (*C_SignFinalFunc)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*C_VerifyUpdateFunc)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef CK_RV (*C_VerifyFinalFunc)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
typedef CK_RV (*C_EncryptUpdateFunc)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*C_EncryptFinalFunc)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen);
typedef CK_RV (*C_DecryptUpdateFunc)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_RV (*C_DecryptFinalFunc)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen);
typedef CK_RV (*C_SeedRandomFunc)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);
typedef CK_RV (*C_GenerateRandomFunc)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomDataLen);
typedef CK_RV (*C_WrapKeyFunc)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
typedef CK_RV (*C_UnwrapKeyFunc)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (*C_DigestEncryptUpdateFunc)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*C_DecryptDigestUpdateFunc)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_RV (*C_SignEncryptUpdateFunc)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*C_DecryptVerifyUpdateFunc)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_RV (*C_GetOperationStateFunc)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen);
typedef CK_RV (*C_SetOperationStateFunc)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
typedef CK_RV (*C_CreateMutexFunc)(CK_VOID_PTR_PTR ppMutex);
typedef CK_RV (*C_DestroyMutexFunc)(CK_VOID_PTR pMutex);
typedef CK_RV (*C_LockMutexFunc)(CK_VOID_PTR pMutex);
typedef CK_RV (*C_UnlockMutexFunc)(CK_VOID_PTR pMutex);
typedef CK_RV (*C_GetFunctionListFunc)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
typedef CK_RV (*C_GetInterfaceFunc)(CK_UTF8CHAR_PTR pInterfaceName, CK_VOID_PTR_PTR ppInterface, CK_FLAGS flags);
typedef CK_RV (*C_GetInterfaceListFunc)(CK_INTERFACE_PTR_PTR ppInterfaceList, CK_ULONG_PTR pulCount);

// ============================================================================
// ТИПЫ ДАННЫХ ДЛЯ УПРАВЛЕНИЯ СЛОТАМИ
// ============================================================================

/**
 * @brief Расширенная информация о слоте (ABI-стабильная структура)
 */
struct SlotInfoEx {
    SlotId id{0};                          ///< ID слота (PKCS#11)
    SlotState state{SlotState::EMPTY};     ///< Текущее состояние
    TokenInfo token_info{};                ///< Информация о токене
    char library_path[256]{};              ///< Путь к PKCS#11 библиотеке
    TokenType token_type{TokenType::UNKNOWN}; ///< Тип токена
    uint32_t active_sessions{0};            ///< Количество активных сессий
    int64_t last_seen_ms{0};                ///< Время последнего обнаружения
    int64_t last_used_ms{0};                ///< Время последней операции
    uint32_t error_count{0};                 ///< Счетчик ошибок подряд
    bool is_supported{true};                ///< Поддерживается ли токен
    char usb_vid_pid[32]{};                 ///< USB Vendor ID / Product ID
    char usb_serial[64]{};                  ///< USB серийный номер

    SlotInfoEx() = default;

    void set_library_path(const char* path) {
        strncpy(library_path, path, sizeof(library_path) - 1);
    }
    void set_usb_vid_pid(const char* vidpid) {
        strncpy(usb_vid_pid, vidpid, sizeof(usb_vid_pid) - 1);
    }
    void set_usb_serial(const char* serial) {
        strncpy(usb_serial, serial, sizeof(usb_serial) - 1);
    }
};

/**
 * @brief Callback для уведомления о событиях слотов
 */
using SlotEventCallback = std::function<void(SlotEventType, const SlotInfoEx&)>;

// ============================================================================
// МЕНЕДЖЕР СЛОТОВ (SINGLETON)
// ============================================================================

/**
 * @brief Центральный менеджер слотов PKCS#11
 *
 * Управляет обнаружением токенов, хотплагом, состоянием слотов.
 * Уведомляет подписчиков о событиях подключения/отключения.
 *
 * ПОТОКОБЕЗОПАСНОСТЬ:
 *   - Все публичные методы thread-safe
 *   - Внутренние потоки: hotplug listener, watchdog
 *   - Recursive mutex для защиты внутренних структур
 */
class SlotManager {
private:
    // ------------------------------------------------------------------------
    // ПОЛЯ КЛАССА
    // ------------------------------------------------------------------------

    mutable std::recursive_mutex mutex_;

    // Карта слотов: slot_id -> информация
    std::map<SlotId, SlotInfoEx> slots_;

    // Карта PKCS#11 модулей: библиотека -> инициализирована?
    std::map<std::string, bool> modules_;

    // Подписчики на события
    std::vector<SlotEventCallback> subscribers_;

    // Потоки
    std::thread hotplug_thread_;
    std::thread watchdog_thread_;
    std::atomic<bool> running_{false};
    std::condition_variable_any stop_cv_;

    // Кэш USB устройств для быстрого определения
    struct USBDeviceId {
        uint16_t vid{0};
        uint16_t pid{0};
        char serial[64]{};

        bool operator<(const USBDeviceId& other) const {
            if (vid != other.vid) return vid < other.vid;
            if (pid != other.pid) return pid < other.pid;
            return strcmp(serial, other.serial) < 0;
        }

        void set_serial(const char* s) {
            strncpy(serial, s, sizeof(serial) - 1);
        }
    };
    std::map<USBDeviceId, SlotId> usb_to_slot_;

    // Платформозависимые хендлы
#ifdef _WIN32
    HDEVNOTIFY device_notify_handle_{nullptr};
    HWND hidden_window_{nullptr};
#elif defined(__linux__)
    struct udev* udev_{nullptr};
    struct udev_monitor* monitor_{nullptr};
#elif defined(__APPLE__)
    IONotificationPortRef notification_port_{nullptr};
    io_iterator_t iterator_{0};
#endif

    // Константы
    static constexpr uint32_t MAX_SLOTS = 64;
    static constexpr int IDLE_TIMEOUT_MINUTES = 15;
    static constexpr int WATCHDOG_SLEEP_SECONDS = 30;
    static constexpr int MAX_ERROR_COUNT = 3;

    // ------------------------------------------------------------------------
    // ПРИВАТНЫЕ МЕТОДЫ
    // ------------------------------------------------------------------------

    /**
     * @brief Получить список слотов через PKCS#11
     *
     * ВХОД: library_path - путь к библиотеке
     * ВЫХОД: вектор ID слотов с токенами
     */
    std::vector<SlotId> GetSlotListFromPKCS11(const std::string& library_path) {
        std::vector<SlotId> result;

        // Загружаем библиотеку временно
#ifdef _WIN32
        HMODULE lib = LoadLibraryA(library_path.c_str());
        if (!lib) return result;

        auto pC_GetSlotList = (C_GetSlotListFunc)GetProcAddress(lib, "C_GetSlotList");
        auto pC_Initialize = (C_InitializeFunc)GetProcAddress(lib, "C_Initialize");
        auto pC_Finalize = (C_FinalizeFunc)GetProcAddress(lib, "C_Finalize");
#else
        void* lib = dlopen(library_path.c_str(), RTLD_LAZY);
        if (!lib) return result;

        auto pC_GetSlotList = (C_GetSlotListFunc)dlsym(lib, "C_GetSlotList");
        auto pC_Initialize = (C_InitializeFunc)dlsym(lib, "C_Initialize");
        auto pC_Finalize = (C_FinalizeFunc)dlsym(lib, "C_Finalize");
#endif

        if (pC_Initialize && pC_GetSlotList && pC_Finalize) {
            CK_RV rv = pC_Initialize(nullptr);
            if (rv == CKR_OK) {
                CK_SLOT_ID slots[MAX_SLOTS];
                CK_ULONG count = MAX_SLOTS;
                rv = pC_GetSlotList(CK_TRUE, slots, &count);  // CK_TRUE = токены присутствуют
                if (rv == CKR_OK) {
                    for (CK_ULONG i = 0; i < count; ++i) {
                        result.push_back(static_cast<SlotId>(slots[i]));
                    }
                }
                pC_Finalize(nullptr);
            }
        }

#ifdef _WIN32
        FreeLibrary(lib);
#else
        dlclose(lib);
#endif

        return result;
    }

    /**
     * @brief Определить USB Vendor/Product ID для слота
     *
     * ВХОД: slot_id - ID слота, library_path - путь к библиотеке
     * ВЫХОД: строка "VID:PID" или пустая строка
     */
    std::string GetUSBVIDPID(SlotId /*slot_id*/, const std::string& /*library_path*/) {
        std::string result;

        // Платформозависимое получение VID/PID
#ifdef _WIN32
        // Windows: через SetupAPI
        HDEVINFO device_info = SetupDiGetClassDevsA(
            &GUID_DEVCLASS_USB, nullptr, nullptr,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
        );

        if (device_info != INVALID_HANDLE_VALUE) {
            SP_DEVINFO_DATA dev_info_data;
            dev_info_data.cbSize = sizeof(SP_DEVINFO_DATA);

            for (DWORD i = 0; SetupDiEnumDeviceInfo(device_info, i, &dev_info_data); ++i) {
                char hardware_id[256];
                DWORD size = 0;

                if (SetupDiGetDeviceRegistryPropertyA(
                    device_info, &dev_info_data, SPDRP_HARDWAREID,
                    nullptr, (PBYTE)hardware_id, sizeof(hardware_id), &size)) {

                    std::string hwid(hardware_id);
                    if (hwid.find("VID_") != std::string::npos &&
                        hwid.find("PID_") != std::string::npos) {
                        result = hwid;
                        break;
                    }
                }
            }
            SetupDiDestroyDeviceInfoList(device_info);
        }
#elif defined(__linux__)
        // Linux: через sysfs - упрощенно
        result = "VID_1050_PID_0407";  // YubiKey для теста
#elif defined(__APPLE__)
        // macOS: через IOKit - упрощенно
        result = "VID_05AC_PID_12A8";  // Apple keyboard для теста
#endif

        return result;
    }

    /**
     * @brief Парсинг VID/PID из строки
     */
    void ParseVIDPID(const std::string& vidpid, uint16_t& vid, uint16_t& pid) {
        vid = 0;
        pid = 0;

        size_t vid_pos = vidpid.find("VID_");
        size_t pid_pos = vidpid.find("PID_");

        if (vid_pos != std::string::npos && pid_pos != std::string::npos) {
            try {
                std::string vid_str = vidpid.substr(vid_pos + 4, 4);
                std::string pid_str = vidpid.substr(pid_pos + 4, 4);
                vid = static_cast<uint16_t>(std::stoul(vid_str, nullptr, 16));
                pid = static_cast<uint16_t>(std::stoul(pid_str, nullptr, 16));
            } catch (...) {
                // Игнорируем ошибки парсинга
            }
        }
    }

    /**
     * @brief Инициализировать платформозависимый хотплаг
     *
     * ВХОД: none
     * ВЫХОД: true если успешно
     */
    bool InitHotplug() {
#ifdef _WIN32
        // Windows: скрытое окно для сообщений WM_DEVICECHANGE
        HINSTANCE hInstance = GetModuleHandleA(nullptr);

        WNDCLASSA wc = {};
        wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
            if (msg == WM_DEVICECHANGE) {
                SlotManager* self = (SlotManager*)GetWindowLongPtrA(hwnd, GWLP_USERDATA);
                if (self) {
                    self->OnWindowsDeviceChange(wParam, lParam);
                }
            }
            return DefWindowProcA(hwnd, msg, wParam, lParam);
        };
        wc.hInstance = hInstance;
        wc.lpszClassName = "SecureVaultSlotManager";
        RegisterClassA(&wc);

        hidden_window_ = CreateWindowExA(
            0, "SecureVaultSlotManager", "", WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT, CW_USEDEFAULT, 400, 300,
            nullptr, nullptr, hInstance, nullptr
        );

        SetWindowLongPtrA(hidden_window_, GWLP_USERDATA, (LONG_PTR)this);

        DEV_BROADCAST_DEVICEINTERFACE_A filter = {};
        filter.dbcc_size = sizeof(filter);
        filter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
        filter.dbcc_classguid = GUID_DEVINTERFACE_USB_DEVICE;

        device_notify_handle_ = RegisterDeviceNotificationA(
            hidden_window_, &filter, DEVICE_NOTIFY_WINDOW_HANDLE
        );

        return hidden_window_ != nullptr && device_notify_handle_ != nullptr;

#elif defined(__linux__)
        // Linux: libudev
        udev_ = udev_new();
        if (!udev_) return false;

        monitor_ = udev_monitor_new_from_netlink(udev_, "udev");
        if (!monitor_) {
            udev_unref(udev_);
            return false;
        }

        udev_monitor_filter_add_match_subsystem_devtype(monitor_, "usb", nullptr);
        udev_monitor_enable_receiving(monitor_);
        return true;

#elif defined(__APPLE__)
        // macOS: IOKit
        notification_port_ = IONotificationPortCreate(kIOMasterPortDefault);
        if (!notification_port_) return false;

        CFMutableDictionaryRef matching = IOServiceMatching(kIOUSBDeviceClassName);
        if (!matching) {
            IONotificationPortDestroy(notification_port_);
            return false;
        }

        kern_return_t kr = IOServiceAddMatchingNotification(
            notification_port_,
            kIOFirstMatchNotification,
            matching,
            [](void* refcon, io_iterator_t iterator) {
                SlotManager* self = (SlotManager*)refcon;
                self->OnMacDeviceAdded(iterator);
            },
            this,
            &iterator_
        );

        if (kr != KERN_SUCCESS) {
            IONotificationPortDestroy(notification_port_);
            return false;
        }

        // Начальное перечисление
        OnMacDeviceAdded(iterator_);

        CFRunLoopAddSource(
            CFRunLoopGetCurrent(),
            IONotificationPortGetRunLoopSource(notification_port_),
            kCFRunLoopDefaultMode
        );
        return true;
#endif

        return false;
    }

#ifdef _WIN32
    /**
     * @brief Обработчик событий устройств Windows
     *
     * ВХОД: wParam, lParam от WM_DEVICECHANGE
     * ВЫХОД: none
     */
    void OnWindowsDeviceChange(WPARAM wParam, LPARAM lParam) {
        if (wParam == DBT_DEVICEARRIVAL) {
            auto* dev_broadcast = (DEV_BROADCAST_HDR*)lParam;
            if (dev_broadcast->dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE) {
                TriggerRescan();
            }
        }
        else if (wParam == DBT_DEVICEREMOVECOMPLETE) {
            auto* dev_broadcast = (DEV_BROADCAST_HDR*)lParam;
            if (dev_broadcast->dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE) {
                TriggerRescan();
            }
        }
    }
#endif

#ifdef __linux__
    /**
     * @brief Поток мониторинга udev для Linux
     *
     * ВХОД: none
     * ВЫХОД: none (бесконечный цикл)
     */
    void UdevMonitorThread() {
        int fd = udev_monitor_get_fd(monitor_);

        while (running_) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(fd, &fds);

            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;

            int ret = select(fd + 1, &fds, nullptr, nullptr, &tv);
            if (ret > 0 && FD_ISSET(fd, &fds)) {
                struct udev_device* dev = udev_monitor_receive_device(monitor_);
                if (dev) {
                    std::string action = udev_device_get_action(dev);
                    if (action == "add" || action == "remove") {
                        TriggerRescan();
                    }
                    udev_device_unref(dev);
                }
            }
        }
    }
#endif

#ifdef __APPLE__
    /**
     * @brief Обработчик добавления USB устройства на macOS
     *
     * ВХОД: iterator - итератор IOKit
     * ВЫХОД: none
     */
    void OnMacDeviceAdded(io_iterator_t iterator) {
        io_service_t service;
        while ((service = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
            TriggerRescan();
            IOObjectRelease(service);
        }
    }
#endif

    /**
     * @brief Запустить пересканирование всех слотов
     *
     * ВХОД: none
     * ВЫХОД: none
     */
    void TriggerRescan() {
        std::lock_guard<std::recursive_mutex> lock(mutex_);

        // Собираем текущие слоты
        std::set<SlotId> current_slots;

        for (const auto& module : modules_) {
            if (module.second) {
                auto slots = GetSlotListFromPKCS11(module.first);
                current_slots.insert(slots.begin(), slots.end());
            }
        }

        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        // Проверяем, какие слоты исчезли
        for (auto it = slots_.begin(); it != slots_.end();) {
            if (current_slots.find(it->first) == current_slots.end()) {
                // Токен извлечен
                SlotInfoEx removed_info = it->second;
                removed_info.state = SlotState::REMOVED;

                // Уведомляем подписчиков
                NotifySubscribers(SlotEventType::TOKEN_REMOVED, removed_info);

                // Очищаем USB кэш
                for (auto usb_it = usb_to_slot_.begin(); usb_it != usb_to_slot_.end();) {
                    if (usb_it->second == it->first) {
                        usb_to_slot_.erase(usb_it++);
                    } else {
                        ++usb_it;
                    }
                }

                it = slots_.erase(it);
            } else {
                ++it;
            }
        }

        // Проверяем новые слоты
        for (SlotId slot_id : current_slots) {
            if (slots_.find(slot_id) == slots_.end()) {
                // Новый токен
                for (const auto& module : modules_) {
                    auto slots = GetSlotListFromPKCS11(module.first);
                    if (std::find(slots.begin(), slots.end(), slot_id) != slots.end()) {
                        SlotInfoEx new_info;
                        new_info.id = slot_id;
                        new_info.state = SlotState::PRESENT;
                        new_info.set_library_path(module.first.c_str());
                        new_info.token_type = DetectTokenType(module.first);
                        new_info.active_sessions = 0;
                        new_info.last_seen_ms = now_ms;
                        new_info.error_count = 0;
                        new_info.is_supported = true;

                        std::string vidpid = GetUSBVIDPID(slot_id, module.first);
                        new_info.set_usb_vid_pid(vidpid.c_str());

                        slots_[slot_id] = new_info;

                        // Кэшируем USB ID
                        uint16_t vid = 0, pid = 0;
                        ParseVIDPID(vidpid, vid, pid);
                        if (vid != 0 && pid != 0) {
                            USBDeviceId usb_id;
                            usb_id.vid = vid;
                            usb_id.pid = pid;
                            usb_id.set_serial("");  // TODO: получить реальный серийный номер
                            usb_to_slot_[usb_id] = slot_id;
                        }

                        // Уведомляем подписчиков
                        NotifySubscribers(SlotEventType::TOKEN_INSERTED, new_info);
                        break;
                    }
                }
            }
        }
    }

    /**
     * @brief Поток watchdog для мониторинга состояния
     *
     * ВХОД: none
     * ВЫХОД: none (бесконечный цикл)
     */
    void WatchdogThread() {
        while (running_) {
            {
                std::lock_guard<std::recursive_mutex> lock(mutex_);

                auto now = std::chrono::system_clock::now();
                auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now.time_since_epoch()).count();

                for (auto& pair : slots_) {
                    // Проверяем таймауты
                    if (pair.second.state == SlotState::INITIALIZED) {
                        auto idle_time = std::chrono::duration_cast<std::chrono::minutes>(
                            now - std::chrono::system_clock::time_point(
                                std::chrono::milliseconds(pair.second.last_used_ms))
                        ).count();

                        // Автоматический logout после 15 минут бездействия
                        if (idle_time >= IDLE_TIMEOUT_MINUTES) {
                            pair.second.state = SlotState::EMPTY;
                            NotifySubscribers(SlotEventType::SESSION_CLOSED, pair.second);
                        }
                    }

                    // Проверяем счетчики ошибок
                    if (pair.second.error_count >= MAX_ERROR_COUNT) {
                        pair.second.state = SlotState::ERROR;
                        NotifySubscribers(SlotEventType::CARD_ERROR, pair.second);
                    }
                }
            }

            // Спим 30 секунд
            for (int i = 0; i < WATCHDOG_SLEEP_SECONDS && running_; ++i) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    }

    /**
     * @brief Уведомить всех подписчиков о событии
     *
     * ВХОД: event - тип события, info - информация о слоте
     * ВЫХОД: none
     */
    void NotifySubscribers(SlotEventType event, const SlotInfoEx& info) {
        for (const auto& callback : subscribers_) {
            try {
                callback(event, info);
            } catch (const std::exception& e) {
                // Логируем ошибку, но не прерываем уведомление других
                // TODO: добавить реальное логирование
            }
        }
    }

public:
    // ------------------------------------------------------------------------
    // SINGLETON
    // ------------------------------------------------------------------------

    static SlotManager& GetInstance() {
        static SlotManager instance;
        return instance;
    }

    SlotManager(const SlotManager&) = delete;
    SlotManager& operator=(const SlotManager&) = delete;

    // ------------------------------------------------------------------------
    // КОНСТРУКТОР/ДЕСТРУКТОР
    // ------------------------------------------------------------------------

    SlotManager() = default;

    ~SlotManager() {
        Shutdown();
    }

    /**
     * @brief Инициализировать менеджер слотов
     *
     * ВХОД: none
     * ВЫХОД: true если успешно
     */
    bool Initialize() {
        std::lock_guard<std::recursive_mutex> lock(mutex_);

        if (running_) {
            return true;
        }

        running_ = true;

        // Инициализируем хотплаг
        if (!InitHotplug()) {
            // Не фатально, продолжаем работу в режиме опроса
        }

        // Запускаем потоки
        watchdog_thread_ = std::thread(&SlotManager::WatchdogThread, this);

#ifdef __linux__
        if (monitor_) {
            hotplug_thread_ = std::thread(&SlotManager::UdevMonitorThread, this);
        }
#endif

        // Первоначальное сканирование
        TriggerRescan();

        return true;
    }

    /**
     * @brief Завершить работу менеджера
     *
     * ВХОД: none
     * ВЫХОД: none
     */
    void Shutdown() {
        std::lock_guard<std::recursive_mutex> lock(mutex_);

        if (!running_) {
            return;
        }

        running_ = false;
        stop_cv_.notify_all();

        if (watchdog_thread_.joinable()) {
            watchdog_thread_.join();
        }

        if (hotplug_thread_.joinable()) {
            hotplug_thread_.join();
        }

        // Очистка платформозависимых ресурсов
#ifdef _WIN32
        if (device_notify_handle_) {
            UnregisterDeviceNotification(device_notify_handle_);
            device_notify_handle_ = nullptr;
        }
        if (hidden_window_) {
            DestroyWindow(hidden_window_);
            hidden_window_ = nullptr;
        }
#elif defined(__linux__)
        if (monitor_) {
            udev_monitor_unref(monitor_);
            monitor_ = nullptr;
        }
        if (udev_) {
            udev_unref(udev_);
            udev_ = nullptr;
        }
#elif defined(__APPLE__)
        if (notification_port_) {
            IONotificationPortDestroy(notification_port_);
            notification_port_ = nullptr;
        }
        if (iterator_) {
            IOObjectRelease(iterator_);
            iterator_ = IO_OBJECT_NULL;
        }
#endif

        slots_.clear();
        modules_.clear();
        usb_to_slot_.clear();
        subscribers_.clear();
    }

    // ------------------------------------------------------------------------
    // УПРАВЛЕНИЕ МОДУЛЯМИ
    // ------------------------------------------------------------------------

    /**
     * @brief Зарегистрировать PKCS#11 библиотеку
     *
     * ВХОД: library_path - путь к .dll/.so/.dylib
     * ВЫХОД: true если успешно
     */
    bool RegisterModule(const std::string& library_path) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        modules_[library_path] = true;
        TriggerRescan();
        return true;
    }

    /**
     * @brief Удалить регистрацию PKCS#11 библиотеки
     *
     * ВХОД: library_path - путь к библиотеке
     * ВЫХОД: none
     */
    void UnregisterModule(const std::string& library_path) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        modules_.erase(library_path);
        TriggerRescan();
    }

    // ------------------------------------------------------------------------
    // ПОЛУЧЕНИЕ ИНФОРМАЦИИ О СЛОТАХ
    // ------------------------------------------------------------------------

    /**
     * @brief Получить список всех доступных слотов
     *
     * ВХОД: none
     * ВЫХОД: вектор SlotInfoEx
     */
    std::vector<SlotInfoEx> GetAllSlots() {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        std::vector<SlotInfoEx> result;
        for (const auto& pair : slots_) {
            result.push_back(pair.second);
        }
        return result;
    }

    /**
     * @brief Получить информацию о конкретном слоте
     *
     * ВХОД: slot_id - ID слота
     * ВЫХОД: SlotInfoEx или nullptr если не найден
     */
    std::unique_ptr<SlotInfoEx> GetSlotInfo(SlotId slot_id) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = slots_.find(slot_id);
        if (it != slots_.end()) {
            return std::make_unique<SlotInfoEx>(it->second);
        }
        return nullptr;
    }

    /**
     * @brief Получить слот по USB VID/PID
     *
     * ВХОД: vid - Vendor ID, pid - Product ID, serial - серийный номер
     * ВЫХОД: ID слота или -1
     */
    SlotId FindSlotByUSB(uint16_t vid, uint16_t pid, const std::string& serial = "") {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        USBDeviceId id;
        id.vid = vid;
        id.pid = pid;
        id.set_serial(serial.c_str());

        auto it = usb_to_slot_.find(id);
        if (it != usb_to_slot_.end()) {
            return it->second;
        }
        return static_cast<SlotId>(-1);
    }

    // ------------------------------------------------------------------------
    // УПРАВЛЕНИЕ СОСТОЯНИЕМ
    // ------------------------------------------------------------------------

    /**
     * @brief Обновить состояние слота (вызывается из SessionManager)
     *
     * ВХОД: slot_id - ID слота, state - новое состояние
     * ВЫХОД: true если успешно
     */
    bool UpdateSlotState(SlotId slot_id, SlotState state) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = slots_.find(slot_id);
        if (it == slots_.end()) {
            return false;
        }

        SlotState old_state = it->second.state;
        it->second.state = state;
        it->second.last_used_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        // Уведомляем о смене состояния
        if (old_state != state) {
            switch (state) {
                case SlotState::INITIALIZED:
                    NotifySubscribers(SlotEventType::SESSION_OPENED, it->second);
                    break;
                case SlotState::EMPTY:
                    NotifySubscribers(SlotEventType::SESSION_CLOSED, it->second);
                    break;
                case SlotState::ERROR:
                    NotifySubscribers(SlotEventType::CARD_ERROR, it->second);
                    break;
                default:
                    break;
            }
        }

        return true;
    }

    /**
     * @brief Увеличить счетчик сессий для слота
     *
     * ВХОД: slot_id - ID слота
     * ВЫХОД: none
     */
    void IncrementSessionCount(SlotId slot_id) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = slots_.find(slot_id);
        if (it != slots_.end()) {
            it->second.active_sessions++;
            it->second.last_used_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        }
    }

    /**
     * @brief Уменьшить счетчик сессий для слота
     *
     * ВХОД: slot_id - ID слота
     * ВЫХОД: none
     */
    void DecrementSessionCount(SlotId slot_id) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = slots_.find(slot_id);
        if (it != slots_.end() && it->second.active_sessions > 0) {
            it->second.active_sessions--;
            it->second.last_used_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        }
    }

    /**
     * @brief Зарегистрировать ошибку для слота
     *
     * ВХОД: slot_id - ID слота
     * ВЫХОД: none
     */
    void ReportError(SlotId slot_id) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = slots_.find(slot_id);
            if (it != slots_.end()) {
                it->second.error_count++;
                if (it->second.error_count >= MAX_ERROR_COUNT) {
                    it->second.state = SlotState::ERROR;
                    NotifySubscribers(SlotEventType::CARD_ERROR, it->second);
                }
            }
    }

    // ------------------------------------------------------------------------
    // ПОДПИСКА НА СОБЫТИЯ
    // ------------------------------------------------------------------------

    /**
     * @brief Подписаться на события слотов
     *
     * ВХОД: callback - функция для вызова при событиях
     * ВЫХОД: ID подписки (для отписки)
     */
    int Subscribe(SlotEventCallback callback) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        static int next_id = 1;
        int id = next_id++;
        subscribers_.push_back(callback);
        return id;
    }

    /**
     * @brief Отписаться от событий
     *
     * ВХОД: subscription_id - ID подписки
     * ВЫХОД: true если успешно
     */
    bool Unsubscribe(int subscription_id) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (subscription_id > 0 && subscription_id <= static_cast<int>(subscribers_.size())) {
            subscribers_.erase(subscribers_.begin() + subscription_id - 1);
            return true;
        }
        return false;
    }

    // ------------------------------------------------------------------------
    // СТАТИСТИКА И ДИАГНОСТИКА
    // ------------------------------------------------------------------------

    /**
     * @brief Получить статистику работы менеджера
     *
     * ВХОД: none
     * ВЫХОД: JSON-like строка со статистикой
     */
    std::string GetStatistics() {
        std::lock_guard<std::recursive_mutex> lock(mutex_);

        std::stringstream ss;
        ss << "{\n";
        ss << "  \"total_slots\": " << slots_.size() << ",\n";

        uint32_t total_sessions = 0;
        uint32_t tokens_ready = 0;
        uint32_t tokens_error = 0;

        for (const auto& pair : slots_) {
            total_sessions += pair.second.active_sessions;
            if (pair.second.state == SlotState::INITIALIZED) {
                tokens_ready++;
            } else if (pair.second.state == SlotState::ERROR) {
                tokens_error++;
            }
        }

        ss << "  \"active_sessions\": " << total_sessions << ",\n";
        ss << "  \"tokens_ready\": " << tokens_ready << ",\n";
        ss << "  \"tokens_error\": " << tokens_error << ",\n";
        ss << "  \"registered_modules\": " << modules_.size() << "\n";
        ss << "}";

        return ss.str();
    }

    /**
     * @brief Принудительно пересканировать слоты
     *
     * ВХОД: none
     * ВЫХОД: none
     */
    void ForceRescan() {
        TriggerRescan();
    }
};

} // namespace pkcs11
} // namespace securevault