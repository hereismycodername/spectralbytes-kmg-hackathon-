# Certificate Radar

Certificate Radar — веб-сервис для инвентаризации TLS-сертификатов, поиска проблем конфигурации и оценки инфраструктурных рисков. Проект создан для трека **Infrastructure Risk Radar**.

Сервис принимает DNS-имена, IP-адреса, URL и CIDR-сети, проверяет сертификаты параллельно и показывает понятные причины риска и рекомендации администратору.

## Быстрый запуск

Требуется только Docker Desktop или Docker Engine с Compose.

```bash
docker compose up --build -d
```

Откройте [http://localhost:8000](http://localhost:8000). Проверить состояние контейнера можно командой:

```bash
docker compose ps
```

Остановка проекта:

```bash
docker compose down
```

SQLite-база хранится в локальной папке `data/` и не удаляется при пересборке контейнера.

## Демо-режим

После запуска контейнера заполните базу пятью демонстрационными сертификатами BadSSL и Google:

```bash
docker compose exec web python -m app.demo
```

Команда создаёт или обновляет:

- `google.com`;
- `expired.badssl.com`;
- `self-signed.badssl.com`;
- `wrong.host.badssl.com`;
- `untrusted-root.badssl.com`;
- по пять исторических точек для каждого сертификата.

Скрипт идемпотентный: его можно запускать повторно без появления дубликатов.

## Автоматические тесты

Запуск в Docker:

```bash
docker compose exec web pytest -q
```

Локальный запуск:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -q
```

Интеграционные тесты используют отдельную временную SQLite-базу и подменяют TLS-сканер. Для их запуска доступ в интернет не требуется.

## Архитектура

| Компонент | Назначение |
|---|---|
| FastAPI | REST API, серверный рендеринг dashboard и lifecycle приложения |
| AsyncIO | Параллельное сканирование с ограничением количества соединений |
| `ssl` + `cryptography` + `certifi` | TLS handshake, разбор X.509 и проверка цепочки доверия |
| SQLAlchemy 2.0 + aiosqlite | Асинхронное хранение реестра и истории в SQLite |
| Risk Engine | Расчёт Risk Score 0–100, уровня риска, причин и рекомендаций |
| Background Scheduler | Повторная проверка сохранённых адресов каждые 6 часов |
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
| `TELEGRAM_BOT_TOKEN` | пусто | Зарезервировано для Telegram-уведомлений |
| `TELEGRAM_CHAT_ID` | пусто | Зарезервировано для Telegram-уведомлений |

## Запуск без Docker

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Демо-данные:

```bash
python -m app.demo
```
