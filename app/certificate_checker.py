"""Асинхронное сканирование и оценка рисков TLS-сертификатов."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from typing import Iterable
from urllib.parse import urlsplit

import certifi
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from pydantic import BaseModel, ConfigDict, Field


DEFAULT_PORT = 443
CONNECTION_TIMEOUT = 3.0
MAX_CONCURRENCY = 40
OWNER_REASON = "Для сервиса не назначен ответственный"
OWNER_RECOMMENDATION = "Назначьте ответственного за сертификат или сервис"


class TargetResult(BaseModel):
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
    untrusted_chain: bool = False
    weak_signature: bool = False
    weak_key: bool = False
    risk_score: int = 0
    risk_level: str = "Low"
    risk_reasons: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


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
    pattern = pattern.rstrip(".").lower()
    host = host.rstrip(".").lower()
    if pattern == host:
        return True
    if not pattern.startswith("*.") or pattern.count("*") != 1:
        return False
    return host.endswith(pattern[1:]) and host.count(".") == pattern.count(".")


def _hostname_matches(certificate: x509.Certificate, host: str) -> bool:
    common_name = _name_value(certificate.subject, NameOID.COMMON_NAME)
    dns_names: list[str] = []
    ip_names: list[str] = []
    try:
        extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        dns_names = extension.value.get_values_for_type(x509.DNSName)
        ip_names = [str(value) for value in extension.value.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass

    try:
        host_ip = ipaddress.ip_address(host)
    except ValueError:
        host_ip = None
    if host_ip is not None:
        return any(ipaddress.ip_address(name) == host_ip for name in ip_names)
    names = dns_names or ([common_name] if common_name else [])
    return any(_dns_name_matches(name, host) for name in names)


def _signature_is_weak(certificate: x509.Certificate) -> tuple[bool, str | None]:
    algorithm = certificate.signature_hash_algorithm
    hash_name = algorithm.name.lower() if algorithm else None
    oid_name = (certificate.signature_algorithm_oid._name or "").lower()
    weak = hash_name in {"sha1", "md5"} or "sha1" in oid_name or "md5" in oid_name
    return weak, hash_name or oid_name or None


def _key_is_weak(certificate: x509.Certificate) -> tuple[bool, str, int | None]:
    public_key = certificate.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return public_key.key_size < 2048, "RSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return public_key.key_size < 256, "EC", public_key.key_size
    return False, type(public_key).__name__, getattr(public_key, "key_size", None)


def risk_level_for_score(score: int) -> str:
    if score <= 20:
        return "Low"
    if score <= 50:
        return "Medium"
    if score <= 80:
        return "High"
    return "Critical"


def build_risk_assessment(
    *,
    days_left: int,
    hostname_mismatch: bool,
    untrusted_chain: bool,
    is_self_signed: bool,
    weak_signature: bool,
    weak_key: bool,
    owner_assigned: bool,
    signature_name: str | None = None,
    key_type: str | None = None,
    key_size: int | None = None,
) -> dict:
    reasons: list[str] = []
    recommendations: list[str] = []

    if days_left <= 0:
        score = 100
        reasons.append(f"Срок действия сертификата истёк ({days_left} дней)")
        recommendations.append("Срочно перевыпустите сертификат у доверенного CA")
    elif days_left <= 1:
        score = 95
        reasons.append(f"Сертификат истекает через {days_left} день")
        recommendations.append("Немедленно перевыпустите сертификат")
    elif days_left <= 7:
        score = 85
        reasons.append(f"Сертификат истекает через {days_left} дней")
        recommendations.append("Срочно запланируйте перевыпуск сертификата")
    elif days_left <= 14:
        score = 70
        reasons.append(f"Сертификат истекает через {days_left} дней")
        recommendations.append("Перевыпустите сертификат в ближайшее время")
    elif days_left <= 30:
        score = 40
        reasons.append(f"Сертификат истекает через {days_left} дней")
        recommendations.append("Запланируйте обновление сертификата")
    elif days_left <= 60:
        score = 15
        reasons.append(f"До окончания сертификата осталось {days_left} дней")
        recommendations.append("Проверьте плановое окно для обновления сертификата")
    else:
        score = 0

    if hostname_mismatch:
        score += 30
        reasons.append("DNS-имя сервиса не совпадает с CN/SAN сертификата")
        recommendations.append("Перевыпустите сертификат с корректным DNS-именем в SAN")
    if untrusted_chain or is_self_signed:
        score += 25
        if is_self_signed:
            reasons.append("Самоподписанный сертификат (Self-Signed)")
        if untrusted_chain:
            reasons.append("Цепочка сертификата не доверена системой")
        recommendations.append("Используйте сертификат доверенного CA и установите полную цепочку")
    if weak_signature or weak_key:
        score += 20
        if weak_signature:
            reasons.append(f"Используется слабый алгоритм подписи {signature_name or 'SHA-1/MD5'}")
        if weak_key:
            key_description = f"{key_type or 'ключ'} {key_size} бит" if key_size else "ключ недостаточного размера"
            reasons.append(f"Слабый {key_description}")
        recommendations.append("Перевыпустите сертификат с SHA-256 и безопасным размером ключа")
    if not owner_assigned:
        score += 10
        reasons.append(OWNER_REASON)
        recommendations.append(OWNER_RECOMMENDATION)

    score = min(score, 100)
    return {
        "risk_score": score,
        "risk_level": risk_level_for_score(score),
        "risk_reasons": list(dict.fromkeys(reasons)),
        "recommendations": list(dict.fromkeys(recommendations)),
    }


def adjust_owner_risk(
    score: int,
    reasons: list[str],
    recommendations: list[str],
    owner_assigned: bool,
) -> dict:
    reasons = list(reasons or [])
    recommendations = list(recommendations or [])
    owner_penalty_present = OWNER_REASON in reasons
    if owner_assigned and owner_penalty_present:
        score = max(0, score - 10)
        reasons.remove(OWNER_REASON)
        recommendations = [item for item in recommendations if item != OWNER_RECOMMENDATION]
    elif not owner_assigned and not owner_penalty_present:
        score = min(100, score + 10)
        reasons.append(OWNER_REASON)
        recommendations.append(OWNER_RECOMMENDATION)
    return {
        "risk_score": score,
        "risk_level": risk_level_for_score(score),
        "risk_reasons": reasons,
        "recommendations": recommendations,
    }


def status_from_days(days_left: int) -> tuple[str, str]:
    if days_left <= 0:
        return "Expired", "Сертификат истёк"
    if days_left <= 14:
        return "Critical", "Сертификат требует срочного обновления"
    if days_left <= 30:
        return "Warning", "Срок действия заканчивается в ближайшие 30 дней"
    if days_left <= 60:
        return "Information", "Срок действия заканчивается в ближайшие 60 дней"
    return "OK", "Сертификат соответствует базовым проверкам"


def _extract_certificate_fields(
    certificate_der: bytes,
    host: str,
    untrusted_chain: bool,
) -> dict:
    certificate = x509.load_der_x509_certificate(certificate_der)
    subject_cn = _name_value(certificate.subject, NameOID.COMMON_NAME)
    try:
        extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = extension.value.get_values_for_type(x509.DNSName)
        san += [str(value) for value in extension.value.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        san = []

    expires_at = certificate.not_valid_after_utc
    days_left = (expires_at - datetime.now(timezone.utc)).days
    is_self_signed = _is_self_signed(certificate)
    hostname_mismatch = not _hostname_matches(certificate, host)
    weak_signature, signature_name = _signature_is_weak(certificate)
    weak_key, key_type, key_size = _key_is_weak(certificate)
    status, explanation = status_from_days(days_left)
    assessment = build_risk_assessment(
        days_left=days_left,
        hostname_mismatch=hostname_mismatch,
        untrusted_chain=untrusted_chain,
        is_self_signed=is_self_signed,
        weak_signature=weak_signature,
        weak_key=weak_key,
        owner_assigned=False,
        signature_name=signature_name,
        key_type=key_type,
        key_size=key_size,
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
        "untrusted_chain": untrusted_chain,
        "weak_signature": weak_signature,
        "weak_key": weak_key,
        "status": status,
        "explanation": explanation,
        **assessment,
    }


def _permissive_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


async def _check_untrusted_chain(host: str, port: int) -> bool:
    writer: asyncio.StreamWriter | None = None
    context = ssl.create_default_context(cafile=certifi.where())
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=host,
                port=port,
                ssl=context,
                server_hostname=host,
            ),
            timeout=CONNECTION_TIMEOUT,
        )
        return False
    except ssl.SSLCertVerificationError:
        return True
    except ssl.SSLError as exc:
        return "CERTIFICATE_VERIFY_FAILED" in str(exc).upper()
    except (ConnectionRefusedError, TimeoutError, asyncio.TimeoutError, socket.gaierror, OSError):
        return False
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass


async def scan_target(
    host: str,
    port: int,
    target: str,
    semaphore: asyncio.Semaphore,
) -> TargetResult:
    writer: asyncio.StreamWriter | None = None
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=host,
                    port=port,
                    ssl=_permissive_ssl_context(),
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

            writer.close()
            await writer.wait_closed()
            writer = None

            untrusted_chain = await _check_untrusted_chain(host, port)
            return TargetResult(
                target=target,
                host=host,
                port=port,
                **_extract_certificate_fields(certificate_der, host, untrusted_chain),
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
                risk_score=100,
                risk_level="Critical",
                risk_reasons=["Не удалось установить TLS-соединение с сервисом", OWNER_REASON],
                recommendations=["Проверьте DNS, сетевую доступность и настройки TLS", OWNER_RECOMMENDATION],
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
    if not 1 <= max_concurrency <= 50:
        raise ValueError("max_concurrency должен быть в диапазоне 1-50")
    expanded = expand_targets(targets)
    semaphore = asyncio.Semaphore(max_concurrency)
    return await asyncio.gather(
        *(scan_target(host, port, target, semaphore) for host, port, target in expanded)
    )
