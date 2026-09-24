"""Асинхронное сканирование TLS-сертификатов."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from typing import Iterable
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.x509.oid import NameOID
from pydantic import BaseModel, ConfigDict, Field


DEFAULT_PORT = 443
CONNECTION_TIMEOUT = 3.0
MAX_CONCURRENCY = 40


class TargetResult(BaseModel):
    """Результат проверки одного TLS-сервиса."""

    model_config = ConfigDict(extra="forbid")

    target: str
    host: str
    port: int
    status: str
    error: str | None = None
    explanation: str | None = None
    subject_cn: str | None = None
    san: list[str] = Field(default_factory=list)
    issuer: str | None = None
    thumbprint: str | None = None
    not_valid_after: datetime | None = None
    days_left: int | None = None
    is_self_signed: bool = False
    hostname_mismatch: bool = False


def _parse_host_port(value: str) -> tuple[str, int]:
    value = value.strip()
    if not value:
        raise ValueError("Пустой адрес")

    parsed = urlsplit(value if "://" in value else f"//{value}")
    host = parsed.hostname
    if not host:
        raise ValueError(f"Не удалось определить host: {value}")

    try:
        port = parsed.port or DEFAULT_PORT
    except ValueError as exc:
        raise ValueError(f"Некорректный порт: {value}") from exc

    if not 1 <= port <= 65535:
        raise ValueError(f"Порт вне диапазона 1-65535: {port}")
    return host, port


def _expand_target(value: str) -> list[tuple[str, int, str]]:
    value = value.strip()
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        host, port = _parse_host_port(value)
        return [(host, port, value)]
    return [(str(ip), DEFAULT_PORT, f"{ip}:{DEFAULT_PORT}") for ip in network.hosts()]


def expand_targets(targets: Iterable[str]) -> list[tuple[str, int, str]]:
    expanded: list[tuple[str, int, str]] = []
    for target in targets:
        expanded.extend(_expand_target(target))
    return expanded


def _name_value(name: x509.Name, oid: NameOID) -> str | None:
    values = name.get_attributes_for_oid(oid)
    return values[0].value if values else None


def _is_self_signed(certificate: x509.Certificate) -> bool:
    if certificate.issuer == certificate.subject:
        return True
    issuer_cn = _name_value(certificate.issuer, NameOID.COMMON_NAME)
    subject_cn = _name_value(certificate.subject, NameOID.COMMON_NAME)
    return bool(issuer_cn and subject_cn and issuer_cn == subject_cn)


def _dns_name_matches(pattern: str, host: str) -> bool:
    """Сопоставляет DNS-имя с поддержкой RFC wildcard *.domain.example."""
    pattern = pattern.rstrip(".").lower()
    host = host.rstrip(".").lower()

    if pattern == host:
        return True
    if not pattern.startswith("*.") or pattern.count("*") != 1:
        return False

    suffix = pattern[1:]
    return host.endswith(suffix) and host.count(".") == pattern.count(".")


def _hostname_matches(certificate: x509.Certificate, host: str) -> bool:
    """Проверяет CN/SAN, включая RFC wildcard и IP SAN."""
    common_name = _name_value(certificate.subject, NameOID.COMMON_NAME)
    dns_names: list[str] = []
    ip_names: list[str] = []

    try:
        extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        dns_names = extension.value.get_values_for_type(x509.DNSName)
        ip_names = [
            str(value)
            for value in extension.value.get_values_for_type(x509.IPAddress)
        ]
    except x509.ExtensionNotFound:
        pass

    # Если SAN присутствует, он является источником истины; CN используется
    # только когда сертификат не содержит SAN.
    try:
        host_ip = ipaddress.ip_address(host)
    except ValueError:
        host_ip = None

    if host_ip is not None:
        return any(
            ipaddress.ip_address(name) == host_ip
            for name in ip_names
        )

    names = dns_names or ([common_name] if common_name else [])
    return any(_dns_name_matches(name, host) for name in names)


def _status_from_risk(
    days_left: int,
    hostname_mismatch: bool,
    is_self_signed: bool,
) -> tuple[str, str]:
    if days_left < 0:
        return "Expired", "Сертификат уже истёк"
    if hostname_mismatch:
        return "Warning", "Имя сервиса не совпадает с CN/SAN сертификата"
    if is_self_signed:
        return "Warning", "Сертификат самоподписанный"
    if days_left <= 14:
        return "Critical", "Срок действия заканчивается в ближайшие 14 дней"
    if days_left <= 30:
        return "Warning", "Срок действия заканчивается в ближайшие 30 дней"
    if days_left <= 60:
        return "Information", "Срок действия заканчивается в ближайшие 60 дней"
    return "OK", "Сертификат соответствует базовым проверкам"


def _extract_certificate_fields(certificate_der: bytes, host: str) -> dict:
    certificate = x509.load_der_x509_certificate(certificate_der)
    subject_cn = _name_value(certificate.subject, NameOID.COMMON_NAME)

    try:
        extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        san = extension.value.get_values_for_type(x509.DNSName)
        san += [
            str(value)
            for value in extension.value.get_values_for_type(x509.IPAddress)
        ]
    except x509.ExtensionNotFound:
        san = []

    expires_at = certificate.not_valid_after_utc
    days_left = (expires_at - datetime.now(timezone.utc)).days
    is_self_signed = _is_self_signed(certificate)
    hostname_mismatch = not _hostname_matches(certificate, host)
    status, explanation = _status_from_risk(
        days_left, hostname_mismatch, is_self_signed
    )

    return {
        "subject_cn": subject_cn,
        "san": san,
        "issuer": certificate.issuer.rfc4514_string(),
        "thumbprint": hashlib.sha256(certificate_der).hexdigest().upper(),
        "not_valid_after": expires_at,
        "days_left": days_left,
        "is_self_signed": is_self_signed,
        "hostname_mismatch": hostname_mismatch,
        "status": status,
        "explanation": explanation,
    }


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def scan_target(
    host: str,
    port: int,
    target: str,
    semaphore: asyncio.Semaphore,
) -> TargetResult:
    writer: asyncio.StreamWriter | None = None

    async with semaphore:
        try:
            # SNI обязателен для виртуальных TLS-хостов, включая BadSSL.
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=host,
                    port=port,
                    ssl=_ssl_context(),
                    server_hostname=host,
                ),
                timeout=CONNECTION_TIMEOUT,
            )

            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None:
                raise ssl.SSLError("TLS-соединение не установлено")

            certificate_der = ssl_object.getpeercert(binary_form=True)
            if not certificate_der:
                raise ssl.SSLError("Сертификат сервера отсутствует")

            return TargetResult(
                target=target,
                host=host,
                port=port,
                **_extract_certificate_fields(certificate_der, host),
            )
        except (
            ConnectionRefusedError,
            TimeoutError,
            asyncio.TimeoutError,
            ssl.SSLError,
            socket.gaierror,
            OSError,
            ValueError,
        ) as exc:
            return TargetResult(
                target=target,
                host=host,
                port=port,
                status="Error",
                error=f"{type(exc).__name__}: {exc}",
                explanation="Сервис недоступен или TLS-соединение завершилось ошибкой",
            )
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass


async def scan_targets(
    targets: Iterable[str],
    max_concurrency: int = MAX_CONCURRENCY,
) -> list[TargetResult]:
    """Параллельно проверяет DNS, IP, URL и CIDR-сети."""
    if not 1 <= max_concurrency <= 50:
        raise ValueError("max_concurrency должен быть в диапазоне 1-50")

    expanded = expand_targets(targets)
    semaphore = asyncio.Semaphore(max_concurrency)
    tasks = [
        scan_target(host, port, target, semaphore)
        for host, port, target in expanded
    ]
    return await asyncio.gather(*tasks)
