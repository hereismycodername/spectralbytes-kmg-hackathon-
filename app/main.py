from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.certificate_checker import TargetResult, scan_targets


BASE_DIR = Path(__file__).resolve().parent.parent

app = FastAPI(
    title="Certificate Radar",
    description="Учебный прототип для проверки TLS-сертификатов.",
    version="0.1.0",
)

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


@app.get("/", name="dashboard")
async def dashboard(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"title": "Certificate Radar", "results": [], "error": None, "targets": ""},
    )


@app.post("/check")
async def check(request: Request, target: str = Form(...)):
    results: list[TargetResult] = []
    error = None
    try:
        targets = [line.strip() for line in target.splitlines() if line.strip()]
        if not targets:
            raise ValueError("Введите хотя бы один адрес")
        results = await scan_targets(targets)
    except ValueError as exc:
        error = str(exc)

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"title": "Certificate Radar", "results": results, "error": error, "targets": target},
    )


@app.get("/health", tags=["system"])
async def health_check():
    return {"status": "ok"}
