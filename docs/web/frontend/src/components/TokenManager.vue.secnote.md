# 📁 TokenManager.vue

## 🎯 НАЗНАЧЕНИЕ
Vue компонент для управления аппаратными токенами
Статус подключения, PIN-диалог, список ключей

## 📥 ВХОДНЫЕ ДАННЫЕ
| Пропс | Тип | Описание |
|-------|-----|----------|
| tokenStatus | Object | Состояние токена |
| availableTokens | Array | Список устройств |

## 📤 ВЫХОДНЫЕ ДАННЫЕ
| Событие | Данные |
|---------|--------|
| @pin-submit | PIN string |
| @token-select | Token ID |

## 🧩 ЗАВИСИМОСТИ
- Vue 3 Composition API
- Pinia store
- WebAuthn API

## 🔗 СВЯЗАННЫЕ ФАЙЛЫ
- `stores/auth.store.js` — состояние
- `services/api.js` — REST calls
- `views/Tokens.vue` — страница
