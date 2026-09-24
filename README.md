# Certificate Radar

Учебный прототип для проекта Hackathon Infrastructure Risk Radar.

## Запуск

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

После запуска откройте http://127.0.0.1:8000.

Проверка состояния приложения доступна по адресу http://127.0.0.1:8000/health.
