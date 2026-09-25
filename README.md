# Certificate Radar

Certificate Radar — веб-сервис для инвентаризации TLS-сертификатов, поиска проблем конфигурации и оценки инфраструктурных рисков. Проект создан для трека **Infrastructure Risk Radar**.

Сервис принимает DNS-имена, IP-адреса, URL и CIDR-сети, проверяет сертификаты параллельно и показывает понятные причины риска и рекомендации администратору.

## Подготовка настроек

Выполните команду из корневой папки проекта:

```bash
cp .env.example .env
```

Откройте `.env` и при необходимости заполните настройки:

```env
DATABASE_URL=sqlite+aiosqlite:///./data/radar.db
SCAN_INTERVAL_HOURS=6
TELEGRAM_BOT_TOKEN=токен_бота
TELEGRAM_CHAT_ID=id_чата_или_канала
```

Telegram можно оставить пустым: приложение продолжит работать, но не будет отправлять сообщения. Файл `.env` содержит секреты, уже добавлен в `.gitignore` и не должен попадать в Git.

## Запуск с Docker

### Требования

- установлен и запущен Docker Desktop либо Docker Engine;
- доступен `docker compose`.

### 1. Соберите и запустите проект

```bash
docker compose up --build -d
```

Команда создаст образ, установит зависимости, подключит SQLite-базу из папки `data/` и запустит FastAPI на порту 8000.

### 2. Проверьте контейнер

```bash
docker compose ps
```

В колонке состояния должно появиться `healthy`. Логи приложения:

```bash
docker compose logs -f web
```

Для выхода из просмотра логов нажмите `Ctrl+C`.

### 3. Откройте приложение

- Dashboard: [http://localhost:8000](http://localhost:8000)
- Swagger API: [http://localhost:8000/docs](http://localhost:8000/docs)
- Healthcheck: [http://localhost:8000/health](http://localhost:8000/health)

### 4. Заполните демо-данными

```bash
docker compose exec web python -m app.demo
```

После команды обновите страницу браузера. Будут созданы пять сертификатов и по пять исторических точек для каждого. Повторный запуск не создаёт дубликаты.

### 5. Запустите тесты

```bash
docker compose exec web pytest -q
```

Ожидаемый результат: все тесты завершились со статусом `passed`.

### 6. Проверьте Telegram

После заполнения `TELEGRAM_BOT_TOKEN` и `TELEGRAM_CHAT_ID` пересоздайте контейнер:

```bash
docker compose up -d --force-recreate
```

Отправьте тестовый алерт:

```bash
curl -X POST http://localhost:8000/api/test-telegram
```

Успешный ответ содержит `"sent": true`.

### Управление контейнером

```bash
# Остановить проект, сохранив базу
docker compose down

# Перезапустить
docker compose restart web

# Пересобрать после изменения кода или зависимостей
docker compose up --build -d
```

## Запуск без Docker

### Требования

- Python 3.11 или новее;
- `pip`;
- доступ к интернету для первоначальной установки зависимостей и TLS-проверок.

Если Docker-версия проекта уже работает, сначала освободите порт 8000:

```bash
docker compose down
```

### 1. Создайте виртуальное окружение

macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows PowerShell:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

После активации в начале строки терминала обычно появляется `(.venv)`.

### 2. Установите зависимости

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 3. Запустите приложение с `.env`

```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload --env-file .env
```

Откройте [http://127.0.0.1:8000](http://127.0.0.1:8000). Сервер работает, пока открыт терминал. Для остановки нажмите `Ctrl+C`.

### 4. Заполните демо-данными

Откройте второй терминал, перейдите в папку проекта и активируйте то же виртуальное окружение:

```bash
source .venv/bin/activate
python -m app.demo
```

На Windows команда активации:

```powershell
.venv\Scripts\Activate.ps1
python -m app.demo
```

### 5. Запустите тесты

```bash
python -m pytest -q
```

Интеграционные тесты используют отдельную временную SQLite-базу и не изменяют рабочие данные. Реальный доступ в интернет для тестов не требуется.

### 6. Проверьте Telegram

```bash
curl -X POST http://127.0.0.1:8000/api/test-telegram
```

SQLite-база в локальном режиме также хранится в `data/radar.db`.

## Демо-набор

Команда `python -m app.demo` создаёт или обновляет:

- `google.com`;
- `expired.badssl.com`;
- `self-signed.badssl.com`;
- `wrong.host.badssl.com`;
- `untrusted-root.badssl.com`;
- по пять исторических точек для каждого сертификата.

## Архитектура

| Компонент | Назначение |
|---|---|
| FastAPI | REST API, серверный рендеринг dashboard и lifecycle приложения |
| AsyncIO | Параллельное сканирование с ограничением количества соединений |
| `ssl` + `cryptography` + `certifi` | TLS handshake, разбор X.509 и проверка цепочки доверия |
| SQLAlchemy 2.0 + aiosqlite | Асинхронное хранение реестра и истории в SQLite |
| Risk Engine | Расчёт Risk Score 0–100, уровня риска, причин и рекомендаций |
| Background Scheduler | Повторная проверка сохранённых адресов каждые 6 часов |
| Telegram Notifier | Асинхронные алерты для Warning, Critical, Expired и Risk Score ≥ 50 |
| HTML/CSS/JavaScript | Поиск, фильтры, карточки, уведомления и управление Owner |

График истории был исключён из текущего интерфейса. Исторические точки продолжают сохраняться и доступны через REST API.

```text
Browser
   │
   ▼
FastAPI ─────► Async TLS Scanner ─────► Remote services
   │                    │
   │                    ▼
   │               Risk Engine
   │                    │
   ▼                    ▼
SQLite ◄──────── Certificate + History
   ▲
   │
Scheduler (каждые 6 часов)
```

## Что проверяет Risk Engine

- срок действия сертификата;
- соответствие Hostname полям SAN/CN;
- доверие цепочке сертификации;
- самоподписанный сертификат;
- SHA-1/MD5 в подписи;
- RSA-ключ меньше 2048 бит;
- EC-ключ меньше 256 бит;
- наличие назначенного ответственного.

Risk Level определяется по итоговому баллу:

| Risk Score | Уровень |
|---:|---|
| 0–20 | Low |
| 21–50 | Medium |
| 51–80 | High |
| 81–100 | Critical |

## REST API

| Метод | Endpoint | Назначение |
|---|---|---|
| `GET` | `/` | Web Dashboard |
| `POST` | `/api/scan` | Проверить список адресов и сохранить результаты |
| `GET` | `/api/certificates` | Получить реестр; параметры `status` и `search` |
| `PATCH` | `/api/certificates/{id}/owner` | Назначить ответственного |
| `GET` | `/api/certificates/{id}/history` | Получить историю Risk Score и Days Left |
| `GET` | `/api/scheduler/status` | Получить время следующего автосканирования |
| `POST` | `/api/test-telegram` | Отправить тестовое Telegram-уведомление |
| `GET` | `/api/export/csv` | Скачать реестр в CSV |
| `GET` | `/health` | Проверить состояние приложения |
| `GET` | `/docs` | Интерактивная документация OpenAPI |

Пример запроса на сканирование:

```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"targets":["google.com","expired.badssl.com","192.168.1.0/30"]}'
```

## Настройки

При необходимости скопируйте пример конфигурации:

```bash
cp .env.example .env
```

| Переменная | Значение по умолчанию | Назначение |
|---|---|---|
| `DATABASE_URL` | `sqlite+aiosqlite:///./data/radar.db` | Адрес базы данных |
| `SCAN_INTERVAL_HOURS` | `6` | Интервал автоматической проверки |
| `TELEGRAM_BOT_TOKEN` | пусто | Токен Telegram-бота от BotFather |
| `TELEGRAM_CHAT_ID` | пусто | ID пользователя, группы или канала для алертов |

## Частые проблемы

### Порт 8000 уже занят

Остановите Docker-контейнер или другой локальный сервер:

```bash
docker compose down
```

Либо запустите локальную версию на другом порту:

```bash
python -m uvicorn app.main:app --reload --env-file .env --port 8001
```

### Docker не увидел изменения `.env`

После сохранения `.env` пересоздайте контейнер:

```bash
docker compose up -d --force-recreate
```

### Telegram возвращает `sent: false`

Проверьте токен, Chat ID, наличие бота в группе или канале и права бота на публикацию сообщений. После исправления `.env` пересоздайте контейнер либо перезапустите локальный сервер.
