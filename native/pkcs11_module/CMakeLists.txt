# ============================================================================
# SecureVault - PKCS#11 модуль для работы с токенами и смарт-картами
# Версия: 2.0.0
# (c) 2026 SecureVault Contributors
# Лицензия: GNU GPL v3
#
# НАЗНАЧЕНИЕ:
#   Сборка кросс-платформенной библиотеки для работы с:
#     - Рутокен (Aktiv)
#     - eToken (Aladdin/SafeNet)
#     - PC/SC смарт-карты (ГОСТ, CIPF, ISO 7816)
#
# ВХОДНЫЕ ДАННЫЕ (ИЗ ВНЕШНЕГО CMAKE):
#   - SECUREVAULT_BUILD_SHARED: ON/OFF (по умолчанию ON)
#   - SECUREVAULT_ENABLE_PCSC:  ON/OFF (по умолчанию ON)
#   - SECUREVAULT_ENABLE_TESTING: ON/OFF (по умолчанию OFF)
#   - SECUREVAULT_INSTALL: ON/OFF (по умолчанию ON)
#
# ВЫХОДНЫЕ ДАННЫЕ:
#   - libsecurevault_pkcs11.so/.dylib/.dll - разделяемая библиотека
#   - libsecurevault_pkcs11_static.a/.lib - статическая библиотека
#   - Цели для тестирования (если включено)
#   - Экспортируемые хедеры для внешнего использования
#
# ЗАВИСИМОСТИ:
#   - PC/SC Lite (Linux/macOS) или Windows SDK (Windows)
#   - Threads::Threads
# ============================================================================

cmake_minimum_required(VERSION 3.20)
project(securevault_pkcs11
        VERSION 2.0.0
        DESCRIPTION "SecureVault PKCS#11 Hardware Token Module"
        LANGUAGES CXX
)

# ----------------------------------------------------------------------------
# НАСТРОЙКИ ПО УМОЛЧАНИЮ
# ----------------------------------------------------------------------------

option(SECUREVAULT_BUILD_SHARED "Build shared library" ON)
option(SECUREVAULT_ENABLE_PCSC  "Enable PC/SC smart card support" ON)
option(SECUREVAULT_ENABLE_TESTING "Build tests" OFF)
option(SECUREVAULT_INSTALL "Install library" ON)

# ----------------------------------------------------------------------------
# КОМПИЛЯТОР И ФЛАГИ
# ----------------------------------------------------------------------------

# Требуем C++17 минимум
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Компилятор и флаги (исправлено)
if(MSVC)
    # MSVC
    add_compile_options(/W4)   # /WX убрали
    add_compile_options(/utf-8)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-D_SCL_SECURE_NO_WARNINGS)

    # Release флаги
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /Oi /GL")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG")
    set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /LTCG")

    # Debug флаги
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Od /RTC1")
else()
    # GCC/Clang – убираем -Werror, добавляем -Wno-old-style-cast
    add_compile_options(-Wall -Wextra -Wpedantic -Wno-old-style-cast)
    # Можно также добавить -Wno-sign-conversion -Wno-conversion, если нужно
    # add_compile_options(-Wno-sign-conversion -Wno-conversion)

    # Release флаги
    add_compile_options(-O3 -DNDEBUG)

    # Устанавливаем флаги для Debug конфигурации
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g -fsanitize=address")
    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address")
    set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} -fsanitize=address")

endif()

# ----------------------------------------------------------------------------
# ПЛАТФОРМО-ЗАВИСИМЫЕ НАСТРОЙКИ
# ----------------------------------------------------------------------------

# Определяем макросы платформы
if(WIN32)
    add_definitions(-DSECUREVAULT_PLATFORM_WINDOWS)
elseif(APPLE)
    add_definitions(-DSECUREVAULT_PLATFORM_MACOS)
    set(CMAKE_MACOSX_RPATH ON)
elseif(UNIX)
    add_definitions(-DSECUREVAULT_PLATFORM_LINUX)
endif()

# ----------------------------------------------------------------------------
# ПОИСК ЗАВИСИМОСТЕЙ
# ----------------------------------------------------------------------------

# Threads (обязательно)
find_package(Threads REQUIRED)

# PC/SC для смарт-карт (опционально)
if(SECUREVAULT_ENABLE_PCSC)
    if(WIN32)
        # Windows: winscard.lib
        set(PCSC_LIBRARIES "winscard.lib")
        set(PCSC_FOUND ON)
        add_definitions(-DSECUREVAULT_ENABLE_PCSC)
    elseif(APPLE)
        # macOS: PCSC framework
        find_library(PCSC_FRAMEWORK PCSC)
        if(PCSC_FRAMEWORK)
            set(PCSC_LIBRARIES ${PCSC_FRAMEWORK})
            # Framework headers (pcsclite.h, winscard.h, etc.) live in the
            # Headers subdirectory of the framework bundle.
            set(PCSC_INCLUDE_DIRS "${PCSC_FRAMEWORK}/Headers")
            set(PCSC_FOUND ON)
            add_definitions(-DSECUREVAULT_ENABLE_PCSC)
        endif()
    elseif(UNIX)
        # Linux: pkg-config для libpcsclite
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(PCSC REQUIRED libpcsclite)
        set(PCSC_LIBRARIES ${PCSC_LIBRARIES})
        set(PCSC_FOUND ON)
        add_definitions(-DSECUREVAULT_ENABLE_PCSC)
    endif()

    if(NOT PCSC_FOUND)
        message(WARNING "PC/SC not found - smart card support will be disabled")
    endif()
endif()

# ----------------------------------------------------------------------------
# ИСХОДНЫЕ ФАЙЛЫ
# ----------------------------------------------------------------------------

set(PKCS11_SOURCES
        # Адаптеры токенов
        src/adapters/rutoken.cpp
        src/adapters/etoken.cpp
        src/adapters/smartcard.cpp
        src/adapters/module_factory.cpp

        # Управление сессиями и слотами
        src/session/session_manager.cpp
        src/session/slot_manager.cpp

        # Работа с сертификатами
        src/certificate_ops/certificate_import.cpp
        src/certificate_ops/certificate_export.cpp
        src/certificate_ops/x509_parse.cpp

        # Операции с ключами
        src/key_operations/key_generation.cpp
        src/key_operations/key_management.cpp

        # Детекция токенов
        src/token_detection/token_detector.cpp
)

set(PKCS11_HEADERS
        # Публичные заголовки
        include/pkcs11_api.h
        include/session_types.h
        include/token_types.h

        # Приватные заголовки (для внутреннего использования)
        src/session/session_manager.h
        src/session/slot_manager.h
        src/adapters/pkcs11_helpers.h
        src/token_detection/token_detector.h
        src/key_operations/key_generation.h
        src/key_operations/key_management.h
        src/certificate_ops/certificate_ops.h
)

# Проверяем существование файлов (для CI)
foreach(source IN LISTS PKCS11_SOURCES)
    if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${source})
        message(WARNING "Source file not found: ${source}")
    endif()
endforeach()

# ----------------------------------------------------------------------------
# СОЗДАНИЕ БИБЛИОТЕКИ
# ----------------------------------------------------------------------------

if(SECUREVAULT_BUILD_SHARED)
    add_library(securevault_pkcs11 SHARED ${PKCS11_SOURCES} ${PKCS11_HEADERS})
else()
    add_library(securevault_pkcs11 STATIC ${PKCS11_SOURCES} ${PKCS11_HEADERS})
endif()

    if(WIN32 AND SECUREVAULT_BUILD_SHARED)
        target_sources(securevault_pkcs11 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/exports.def)
        set_target_properties(securevault_pkcs11 PROPERTIES LINK_FLAGS "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/exports.def")
    endif()

    target_compile_definitions(securevault_pkcs11 PRIVATE SECUREVAULT_EXPORTS)

# Устанавливаем версию
set_target_properties(securevault_pkcs11 PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        OUTPUT_NAME "securevault_pkcs11"
        PUBLIC_HEADER "${PKCS11_HEADERS}"
)

# Включаемые директории
target_include_directories(securevault_pkcs11
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include/securevault/pkcs11>
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Линковка зависимостей
target_link_libraries(securevault_pkcs11
        PUBLIC
        Threads::Threads
        PRIVATE
)

# Добавляем PC/SC если найден
if(PCSC_FOUND)
    target_link_libraries(securevault_pkcs11 PRIVATE ${PCSC_LIBRARIES})
    target_include_directories(securevault_pkcs11 PRIVATE ${PCSC_INCLUDE_DIRS})
    target_compile_definitions(securevault_pkcs11 PRIVATE SECUREVAULT_ENABLE_PCSC)
endif()

# Платформозависимые флаги
if(WIN32)
    # Windows: дополнительная линковка
    target_link_libraries(securevault_pkcs11 PRIVATE
            setupapi.lib
            cfgmgr32.lib
    )

    # Определяем экспорт/импорт для DLL
    target_compile_definitions(securevault_pkcs11
            PUBLIC
            SECUREVAULT_PKCS11_EXPORTS
            $<$<NOT:$<BOOL:${SECUREVAULT_BUILD_SHARED}>>:SECUREVAULT_PKCS11_STATIC>
    )
endif()

# ----------------------------------------------------------------------------
# УСТАНОВКА
# ----------------------------------------------------------------------------

if(SECUREVAULT_INSTALL)
    include(GNUInstallDirs)

    # Установка библиотеки
    install(TARGETS securevault_pkcs11
            EXPORT SecureVaultPKCS11Targets
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/securevault/pkcs11
    )

    # Установка дополнительных заголовков
    install(FILES ${PKCS11_HEADERS}
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/securevault/pkcs11
    )

    # Экспорт конфигурации
    install(EXPORT SecureVaultPKCS11Targets
            FILE SecureVaultPKCS11Targets.cmake
            NAMESPACE SecureVault::
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SecureVault
    )

    # Создание конфигурационного файла для find_package
    include(CMakePackageConfigHelpers)
    write_basic_package_version_file(
            "${CMAKE_CURRENT_BINARY_DIR}/SecureVaultPKCS11ConfigVersion.cmake"
            VERSION ${PROJECT_VERSION}
            COMPATIBILITY SameMajorVersion
    )

    configure_package_config_file(
            "${CMAKE_CURRENT_SOURCE_DIR}/cmake/SecureVaultPKCS11Config.cmake.in"
            "${CMAKE_CURRENT_BINARY_DIR}/SecureVaultPKCS11Config.cmake"
            INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SecureVault
    )

    install(FILES
            "${CMAKE_CURRENT_BINARY_DIR}/SecureVaultPKCS11Config.cmake"
            "${CMAKE_CURRENT_BINARY_DIR}/SecureVaultPKCS11ConfigVersion.cmake"
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SecureVault
    )
endif()

# ----------------------------------------------------------------------------
# ТЕСТИРОВАНИЕ
# ----------------------------------------------------------------------------

if(SECUREVAULT_ENABLE_TESTING)
    enable_testing()

    # Подключаем Catch2
    include(FetchContent)
    FetchContent_Declare(
            Catch2
            GIT_REPOSITORY https://github.com/catchorg/Catch2.git
            GIT_TAG v3.4.0
    )
    FetchContent_MakeAvailable(Catch2)

    # Тест для SessionManager
    add_executable(test_session_manager
            tests/test_session.cpp
            tests/test_utils.cpp
            src/adapters/smartcard.cpp
            src/session/session_manager.cpp
    )

    target_link_libraries(test_session_manager
            PRIVATE
            securevault_pkcs11
            Catch2::Catch2WithMain
    )

    target_include_directories(test_session_manager PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

    add_test(NAME SessionManager COMMAND test_session_manager)

    # Тест для адаптеров
    if(PCSC_FOUND)
        add_executable(test_smartcard
                tests/test_smartcard.cpp
                tests/test_utils.cpp
                src/adapters/smartcard.cpp
                src/session/session_manager.cpp
        )

        target_link_libraries(test_smartcard
                PRIVATE
                securevault_pkcs11
                Catch2::Catch2WithMain
                ${PCSC_LIBRARIES}
        )

        target_include_directories(test_smartcard
                PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/include
                ${PCSC_INCLUDE_DIRS}
        )

        add_test(NAME SmartCardAdapter COMMAND test_smartcard)
    endif()

    # Тест для генерации ключей
    add_executable(test_key_operations
            tests/test_key_operations.cpp
            tests/test_utils.cpp
            src/adapters/smartcard.cpp
            src/session/session_manager.cpp
    )

    target_link_libraries(test_key_operations
            PRIVATE
            securevault_pkcs11
            Catch2::Catch2WithMain
    )

    add_test(NAME KeyOperations COMMAND test_key_operations)

    # Тест для детектора токенов
    add_executable(test_token_detection
            tests/test_token_detection.cpp
            tests/test_utils.cpp
            src/token_detection/token_detector.cpp
    )

    target_link_libraries(test_token_detection
            PRIVATE
            securevault_pkcs11
            Catch2::Catch2WithMain
    )

    target_include_directories(test_token_detection PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

    add_test(NAME TokenDetection COMMAND test_token_detection)
endif()

# ----------------------------------------------------------------------------
# ЦЕЛИ ДЛЯ РАЗРАБОТКИ
# ----------------------------------------------------------------------------

# Цель для форматирования кода (clang-format)
add_custom_target(format
        COMMAND clang-format -i -style=file ${PKCS11_SOURCES} ${PKCS11_HEADERS}
        COMMENT "Formatting source code with clang-format"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

# Цель для статического анализа (clang-tidy)
add_custom_target(tidy
        COMMAND clang-tidy ${PKCS11_SOURCES} -checks=* -- -std=c++17
        COMMENT "Running clang-tidy static analysis"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

# ----------------------------------------------------------------------------
# ИНФОРМАЦИЯ О СБОРКЕ
# ----------------------------------------------------------------------------

message(STATUS "========================================")
message(STATUS "SecureVault PKCS#11 Module Configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Build shared: ${SECUREVAULT_BUILD_SHARED}")
message(STATUS "  PC/SC support: ${PCSC_FOUND}")
message(STATUS "  Build tests: ${SECUREVAULT_ENABLE_TESTING}")
message(STATUS "  Install: ${SECUREVAULT_INSTALL}")
message(STATUS "========================================")
