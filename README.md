# SecGram для Android

Неофициальный клиент Telegram на основе [Telegram для Android](https://github.com/DrKLO/Telegram) 13.1.1 — мобильная версия [SecGram](https://github.com/voidsecurity404/secgram).

> SecGram не связан с Telegram FZ-LLC. Используются свои `api_id` / `api_hash`.

## Установка

1. Скачайте `SecGram-<версия>-android-universal.apk` со страницы [Releases](../../releases).
2. Откройте файл на телефоне и разрешите установку из этого источника.

SecGram ставится **рядом** с официальным Telegram (свой идентификатор `uz.secgram.app`).
Push-уведомления Firebase работают только в официальном приложении, поэтому SecGram получает сообщения, пока работает в фоне.

## Статус

- [x] Своё имя, иконка, идентификатор приложения, отключены проверки обновлений и Google Play Billing.
- [x] Сборка подписанного APK в GitHub Actions (`.github/workflows/android.yml`, тег `v*`).
- [ ] Функции SecGram (проверка ссылок, детектор мошенничества, удалённые сообщения в чате, ghost-режим, IOC…) — переносятся из настольной версии.

## Сборка

Нужны секреты репозитория: `API_ID`, `API_HASH`, `KEYSTORE_BASE64` (base64 файла PKCS12, псевдоним `secgram`), `KEYSTORE_PASSWORD`.

```bash
./gradlew :TMessagesProj_App:assembleAfatRelease \
  -PSECGRAM_APP_ID=<id> -PSECGRAM_APP_HASH=<hash> \
  -PRELEASE_KEY_ALIAS=secgram -PRELEASE_KEY_PASSWORD=<pass> -PRELEASE_STORE_PASSWORD=<pass>
```

## Лицензия

GNU GPL v2, как и Telegram для Android — см. [LICENSE](LICENSE).
