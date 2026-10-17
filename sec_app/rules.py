"""
Reguły detekcji

`evaluate(event, history, config)` dostaje bieżące zdarzenie oraz listę
wcześniejszych zdarzeń z okna czasowego i zwraca listę wykryć (`Detection`).
Zapis do bazy, deduplikacja (cooldown) i logowanie dzieją się w `detection.py`.

Katalog reguł (szczegóły: docs/DETECTION_RULES.md):

  DET-001 BRUTE_FORCE_ATTEMPT               >=3 błędne logowania (login+IP) w oknie
  DET-002 PASSWORD_SPRAYING                 >=3 różne loginy z jednego IP w oknie
  DET-003 ACCESS_DENIED                     każda odmowa dostępu (403 / nie-staff na /admin)
  DET-004 REPEATED_ACCESS_DENIED            >=3 odmowy tego samego aktora w oknie
  DET-005 SUCCESS_AFTER_FAILURES            udane logowanie po >=3 błędnych (korelacja)
  DET-006 PRIVILEGE_ESCALATION              nadanie is_staff przez /change-role
  DET-007 PRIVILEGE_ESCALATION_AFTER_DENIED odmowa na /admin, a potem nadanie is_staff (korelacja)
  DET-008 ENDPOINT_SCANNING                 >=10 odpowiedzi 404 z jednego IP w oknie
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

# --- typy zdarzeń --
LOGIN_SUCCESS = "LOGIN_SUCCESS"
LOGIN_FAILURE = "LOGIN_FAILURE"
ACCESS_DENIED = "ACCESS_DENIED"
ROLE_CHANGED = "ROLE_CHANGED"
NOT_FOUND = "NOT_FOUND"

ANONYMOUS = "anonymous"

# --- konfiguracja domyślna (progi nadpisywalne w settings.DETECTION_RULES) ---
DEFAULT_RULES = {
    "BRUTE_FORCE_ATTEMPT": dict(rule_id="DET-001", severity="CRITICAL", threshold=3, window=300, cooldown=300),
    "PASSWORD_SPRAYING": dict(rule_id="DET-002", severity="HIGH", threshold=3, window=300, cooldown=300),
    "ACCESS_DENIED": dict(rule_id="DET-003", severity="HIGH", cooldown=0),
    "REPEATED_ACCESS_DENIED": dict(rule_id="DET-004", severity="HIGH", threshold=3, window=300, cooldown=300),
    "SUCCESS_AFTER_FAILURES": dict(rule_id="DET-005", severity="HIGH", threshold=3, window=600, cooldown=600),
    "PRIVILEGE_ESCALATION": dict(rule_id="DET-006", severity="CRITICAL", cooldown=0),
    "PRIVILEGE_ESCALATION_AFTER_DENIED": dict(rule_id="DET-007", severity="CRITICAL", window=600, cooldown=0),
    "ENDPOINT_SCANNING": dict(rule_id="DET-008", severity="MEDIUM", threshold=10, window=60, cooldown=300),
}


def build_config(overrides: Optional[dict] = None) -> dict:
    overrides = overrides or {}
    return {name: {**params, **overrides.get(name, {})} for name, params in DEFAULT_RULES.items()}


def lookback_seconds(config: dict) -> int:
    """Jak daleko wstecz trzeba wczytać historię, żeby obsłużyć wszystkie reguły."""
    return max(p.get("window", 0) for p in config.values())


# --- modele --
@dataclass(frozen=True)
class Event:
    timestamp: datetime
    event_type: str
    ip: str
    username: str
    endpoint: str = ""
    status_code: Optional[int] = None
    details: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Detection:
    alert_type: str
    rule_id: str
    severity: str
    username: str
    description: str
    cooldown: int


def _det(config, alert_type, username, description) -> Detection:
    p = config[alert_type]
    return Detection(alert_type, p["rule_id"], p["severity"], username, description, p.get("cooldown", 0))


def _in_window(h: Event, now: datetime, window: int) -> bool:
    return h.timestamp >= now - timedelta(seconds=window)


def _last_success(history, username, ip=None) -> Optional[datetime]:
    times = [h.timestamp for h in history
             if h.event_type == LOGIN_SUCCESS and h.username == username and (ip is None or h.ip == ip)]
    return max(times) if times else None


# --- reguły --
def _brute_force(ev, history, cfg):
    p = cfg["BRUTE_FORCE_ATTEMPT"]
    reset = _last_success(history, ev.username, ev.ip)  # z rzędu, sukces zeruje licznik
    fails = [h for h in history
             if h.event_type == LOGIN_FAILURE and h.username == ev.username and h.ip == ev.ip
             and _in_window(h, ev.timestamp, p["window"]) and (reset is None or h.timestamp > reset)]
    n = len(fails) + 1
    if n >= p["threshold"]:
        return _det(cfg, "BRUTE_FORCE_ATTEMPT", ev.username,
                    f"Wykryto {n} nieudanych prób logowania z rzędu na konto '{ev.username}' pochodzących z IP {ev.ip} "
                    f"w ciągu {p['window']} s.")


def _password_spraying(ev, history, cfg):
    p = cfg["PASSWORD_SPRAYING"]
    names = {h.username for h in history
             if h.event_type == LOGIN_FAILURE and h.ip == ev.ip and _in_window(h, ev.timestamp, p["window"])}
    names.add(ev.username)
    if len(names) >= p["threshold"]:
        sample = ", ".join(sorted(names)[:5])
        return _det(cfg, "PASSWORD_SPRAYING", "multiple",
                    f"Nieudane próby logowania na {len(names)} różnych kont w ciągu {p['window']} s pochodzących z IP {ev.ip} "
                    f"(m.in.: {sample}).")


def _success_after_failures(ev, history, cfg):
    p = cfg["SUCCESS_AFTER_FAILURES"]
    reset = _last_success(history, ev.username)
    fails = [h for h in history
             if h.event_type == LOGIN_FAILURE and h.username == ev.username
             and _in_window(h, ev.timestamp, p["window"]) and (reset is None or h.timestamp > reset)]
    if len(fails) >= p["threshold"]:
        ips = sorted({h.ip for h in fails})
        return _det(cfg, "SUCCESS_AFTER_FAILURES", ev.username,
                    f"Udane logowanie konta '{ev.username}' z IP {ev.ip} po {len(fails)} nieudanych próbach "
                    f"(IP błędnych prób: {', '.join(ips)}) - możliwe przejęcie konta.")


def _access_denied(ev, history, cfg):
    return _det(cfg, "ACCESS_DENIED", ev.username,
                f"Odmowa dostępu: użytkownik '{ev.username}' ({ev.ip}) -> {ev.endpoint} "
                f"(status {ev.status_code}).")


def _repeated_access_denied(ev, history, cfg):
    p = cfg["REPEATED_ACCESS_DENIED"]
    by_user = ev.username != ANONYMOUS
    same = [h for h in history
            if h.event_type == ACCESS_DENIED and _in_window(h, ev.timestamp, p["window"])
            and ((h.username == ev.username) if by_user else (h.username == ANONYMOUS and h.ip == ev.ip))]
    n = len(same) + 1
    if n >= p["threshold"]:
        actor = ev.username if by_user else f"anonymous@{ev.ip}"
        return _det(cfg, "REPEATED_ACCESS_DENIED", ev.username,
                    f"{n} odmów dostępu dla {actor} w ciągu {p['window']} s - możliwe skanowanie uprawnień.")


def _privilege_escalation(ev, history, cfg):
    d = ev.details
    if not (d.get("is_staff") is True and d.get("previous_is_staff") is False):
        return None
    chain = cfg["PRIVILEGE_ESCALATION_AFTER_DENIED"]
    denied = [h for h in history
              if h.event_type == ACCESS_DENIED and h.username == ev.username
              and h.endpoint.startswith("/admin") and _in_window(h, ev.timestamp, chain["window"])]
    if denied:
        return _det(cfg, "PRIVILEGE_ESCALATION_AFTER_DENIED", ev.username,
                    f"Użytkownik '{ev.username}' dostał odmowę dla /admin ({len(denied)}x), a w ciągu "
                    f"{chain['window']} s nadał sobie uprawnienia staff (/change-role) - eskalacja uprawnień.")
    return _det(cfg, "PRIVILEGE_ESCALATION", ev.username,
                f"Użytkownik '{ev.username}' ({ev.ip}) zmienił swoją rolę na staff (is_staff False -> True).")


def _endpoint_scanning(ev, history, cfg):
    p = cfg["ENDPOINT_SCANNING"]
    n = 1 + sum(1 for h in history
                if h.event_type == NOT_FOUND and h.ip == ev.ip and _in_window(h, ev.timestamp, p["window"]))
    if n >= p["threshold"]:
        return _det(cfg, "ENDPOINT_SCANNING", ev.username,
                    f"{n} odpowiedzi 404 dla IP {ev.ip} w ciągu {p['window']} s - możliwe skanowanie endpointów.")


RULES_BY_EVENT = {
    LOGIN_FAILURE: (_brute_force, _password_spraying),
    LOGIN_SUCCESS: (_success_after_failures,),
    ACCESS_DENIED: (_access_denied, _repeated_access_denied),
    ROLE_CHANGED: (_privilege_escalation,),
    NOT_FOUND: (_endpoint_scanning,),
}


def evaluate(event: Event, history, config: Optional[dict] = None) -> list:
    """Zwraca listę wykryć dla `event`. `history` = wcześniejsze zdarzenia (bez bieżącego)."""
    cfg = config or build_config()
    out = []
    for rule in RULES_BY_EVENT.get(event.event_type, ()):
        res = rule(event, history, cfg)
        if res:
            out.append(res)
    return out
