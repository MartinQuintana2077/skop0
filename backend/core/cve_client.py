import os
import re
import time
import json
import datetime
import threading
from collections import deque
import requests
from core.local_db import LocalDBManager


# Nombres genéricos de protocolo que NUNCA deben buscarse por texto libre sin un producto concreto
GENERIC_PROTOCOL_NAMES = {
    "", "http", "https", "http-proxy", "http-alt", "https-alt", "ssl", "tls",
    "tcpwrapped", "unknown", "msrpc", "netbios-ssn", "microsoft-ds", "domain",
    "ftp", "ssh", "telnet", "smtp", "pop3", "imap", "rtsp", "sip", "ipp",
    "printer", "jetdirect", "upnp", "ssdp", "mdns", "snmp", "ntp", "ldap",
    "mysql", "postgresql", "ms-sql-s", "mongodb", "redis", "rdp", "ms-wbt-server",
    "vnc", "smb", "rpcbind", "nfs", "mqtt", "coap", "ajp13", "socks",
}


class CVEClient:
    """
    Cliente HTTP thread-safe para la API oficial NVD 2.0 (National Vulnerability Database).
    Mejoras Plan 2:
      1. Consultas precisas por CPE 2.3 oficial (`cpeName`) a partir de los CPE extraídos por Nmap XML.
      2. Fallback estricto por `producto + versión` (rechazando protocolos genéricos y CPEs sin versión).
      3. Rate-limiter global por ventana deslizante (cumple cuotas NVD: 5 req/30s sin API key, 45/30s con NVD_API_KEY).
      4. Deduplicación en vuelo (`in-flight`): si N hilos consultan el mismo software a la vez, solo 1 llama al NVD.
      5. Caché SQLite con TTL (7 días con CVEs / 24h sin CVEs) y sin cachear errores de red.
      6. Traducción por lotes cacheada con timeout estricto (2.5s) y ordenamiento por severidad CVSS descendente.
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # TTL de caché en segundos
    CACHE_TTL_WITH_CVES = 7 * 24 * 3600    # 7 días
    CACHE_TTL_EMPTY = 24 * 3600            # 24 horas

    # Rate-limiter global compartido entre todas las instancias y hilos
    _rate_lock = threading.Lock()
    _request_timestamps = deque()

    # Deduplicación de consultas simultáneas en vuelo (sin fugas de memoria)
    _inflight_lock = threading.Lock()
    _inflight_entries = {}

    # Caché en memoria de traducciones EN->ES
    _translation_lock = threading.Lock()
    _translation_cache = {}

    def __init__(self, api_key: str = None, db_manager=None):
        self.api_key = (api_key if api_key is not None else os.environ.get("NVD_API_KEY", "")).strip()
        self._db_manager = db_manager

    def _get_db(self):
        return self._db_manager if self._db_manager is not None else LocalDBManager()

    @staticmethod
    def cpe_to_v23(cpe_str: str):
        """
        Convierte un CPE 2.2 de Nmap (ej. 'cpe:/a:apache:http_server:2.4.49') o CPE 2.3
        al formato canónico CPE 2.3 de 13 campos aceptado por NVD API 2.0.
        Rechaza CPEs sin versión concreta (ej. 'cpe:/o:microsoft:windows') para evitar
        falsos positivos masivos.
        """
        if not cpe_str or not isinstance(cpe_str, str):
            return None
        raw = cpe_str.strip()
        if not raw:
            return None

        if raw.startswith("cpe:2.3:"):
            parts = raw.split(":")
            if len(parts) < 6:
                return None
            part_type = parts[2].lower()
            vendor = parts[3]
            product = parts[4]
            version = parts[5]
            if part_type not in ("a", "h", "o"):
                return None
            if not vendor or vendor in ("*", "-") or not product or product in ("*", "-"):
                return None
            # Exigir versión concreta con al menos un dígito (evita OS genéricos tipo 'windows')
            if not version or version in ("*", "-") or not any(ch.isdigit() for ch in version):
                return None
            padded = parts[:13] + ["*"] * max(0, 13 - len(parts))
            return ":".join(padded)

        if raw.startswith("cpe:/"):
            body = raw[5:]
            tokens = body.split(":")
            if len(tokens) < 4:
                return None
            part_type = tokens[0].lower()
            vendor = tokens[1]
            product = tokens[2]
            version = tokens[3]
            if part_type not in ("a", "h", "o"):
                return None
            if not vendor or vendor in ("*", "-") or not product or product in ("*", "-"):
                return None
            if not version or version in ("*", "-") or not any(ch.isdigit() for ch in version):
                return None
            update = tokens[4] if len(tokens) > 4 and tokens[4] else "*"
            edition = tokens[5] if len(tokens) > 5 and tokens[5] else "*"
            lang = tokens[6] if len(tokens) > 6 and tokens[6] else "*"
            fields = ["cpe", "2.3", part_type, vendor, product, version, update, edition, lang, "*", "*", "*", "*"]
            return ":".join(fields)

        return None

    @classmethod
    def select_best_query(cls, nombre_servicio: str = "", version: str = "", producto: str = "", cpes: list = None):
        """
        Determina la estrategia óptima de consulta al NVD:
          1. Preferencia absoluta: CPE 2.3 versionado de aplicación (`a`) o hardware (`h`), luego OS (`o`) versionado.
          2. Fallback controlado: `producto + versión` cuando `producto` es específico y `version` contiene dígitos.
          3. Fallback legacy: `nombre_servicio + versión` únicamente si `nombre_servicio` NO es un protocolo genérico.
        Retorna tupla `(query_type, query_value, cache_key)` o `None` si no hay evidencia suficiente.
        """
        # 1. Buscar mejor CPE versionado (priorizando 'a' aplicación > 'h' hardware > 'o' sistema operativo)
        if cpes and isinstance(cpes, (list, tuple)):
            valid_cpes = []
            for raw_cpe in cpes:
                v23 = cls.cpe_to_v23(raw_cpe)
                if v23:
                    ptype = v23.split(":")[2]
                    priority = 0 if ptype == "a" else (1 if ptype == "h" else 2)
                    valid_cpes.append((priority, v23))
            if valid_cpes:
                valid_cpes.sort(key=lambda x: x[0])
                best_cpe = valid_cpes[0][1]
                return ("cpe", best_cpe, f"cpe|{best_cpe}")

        clean_ver = (version or "").strip()
        if not clean_ver or not any(ch.isdigit() for ch in clean_ver):
            return None

        clean_prod = (producto or "").strip()
        clean_svc = (nombre_servicio or "").strip()

        # 2. Fallback por producto concreto + versión (ej. "Apache httpd 2.4.49", "OpenSSH 8.9p1")
        if clean_prod and clean_prod.lower() not in GENERIC_PROTOCOL_NAMES and len(clean_prod) >= 2:
            # Limpiar ruido común de Nmap como "httpd" duplicado o paréntesis largos
            kw = re.sub(r'\s+', ' ', f"{clean_prod} {clean_ver}").strip()
            return ("keyword", kw, f"kw|{kw.lower()}")

        # 3. Fallback por nombre de servicio solo si NO es un protocolo genérico (ej. "openssh", "nginx", "vsftpd")
        if clean_svc and clean_svc.lower() not in GENERIC_PROTOCOL_NAMES and len(clean_svc) >= 3:
            kw = re.sub(r'\s+', ' ', f"{clean_svc} {clean_ver}").strip()
            return ("keyword", kw, f"kw|{kw.lower()}")

        return None

    def _acquire_rate_slot(self):
        """Rate-limiter thread-safe por ventana deslizante respetando cuotas oficiales de NVD 2.0."""
        max_requests = 45 if self.api_key else 5
        window_seconds = 30.5
        min_spacing = 0.65 if self.api_key else 1.6

        while True:
            wait_for = 0.0
            with self._rate_lock:
                now = time.monotonic()
                while self._request_timestamps and (now - self._request_timestamps[0]) >= window_seconds:
                    self._request_timestamps.popleft()

                if len(self._request_timestamps) >= max_requests:
                    wait_for = (self._request_timestamps[0] + window_seconds) - now + 0.05
                elif self._request_timestamps and (now - self._request_timestamps[-1]) < min_spacing:
                    wait_for = min_spacing - (now - self._request_timestamps[-1])
                else:
                    self._request_timestamps.append(now)
                    return

            if wait_for > 0:
                time.sleep(min(wait_for, 5.0))

    @classmethod
    def _traducir_lote_al_espanol(cls, textos: list) -> list:
        """Traduce múltiples descripciones EN->ES en una sola petición HTTP cacheada (timeout 2.5s)."""
        if not textos:
            return []

        results = [None] * len(textos)
        pending_indices = []
        pending_texts = []

        with cls._translation_lock:
            for idx, txt in enumerate(textos):
                clean = (txt or "").strip()
                if not clean or clean in ("Sin descripción", "No description available"):
                    results[idx] = "Sin descripción disponible."
                elif clean in cls._translation_cache:
                    results[idx] = cls._translation_cache[clean]
                else:
                    pending_indices.append(idx)
                    pending_texts.append(clean[:650])  # Acotar textos muy largos

        if pending_texts:
            sep = "\n[[SECSCAN_SEP]]\n"
            joined = sep.join(pending_texts)
            translated_batch = None
            try:
                import urllib.parse
                import urllib.request
                url = "https://translate.googleapis.com/translate_a/single?client=gtx&sl=en&tl=es&dt=t&q=" + urllib.parse.quote(joined)
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
                with urllib.request.urlopen(req, timeout=2.5) as response:
                    raw_res = json.loads(response.read().decode("utf-8"))
                    if raw_res and raw_res[0]:
                        full_trans = "".join([part[0] for part in raw_res[0] if part and part[0]])
                        parts = [p.strip() for p in full_trans.split("[[SECSCAN_SEP]]")]
                        if len(parts) == len(pending_texts):
                            translated_batch = parts
            except Exception:
                translated_batch = None

            with cls._translation_lock:
                for i, orig_idx in enumerate(pending_indices):
                    orig_txt = textos[orig_idx].strip()
                    final_txt = translated_batch[i] if (translated_batch and translated_batch[i]) else orig_txt
                    cls._translation_cache[orig_txt] = final_txt
                    results[orig_idx] = final_txt

        return [r if r is not None else "Sin descripción disponible." for r in results]

    @classmethod
    def _traducir_al_espanol(cls, texto: str) -> str:
        """Wrapper compatible de traducción individual apoyado en el traductor por lotes cacheado."""
        res = cls._traducir_lote_al_espanol([texto])
        return res[0] if res else (texto or "Sin descripción disponible.")

    def _read_cache(self, cache_key: str):
        """Lee caché local SQLite validando TTL (7 días con CVEs / 24h vacío). Retorna None si expiró o no existe."""
        try:
            local_db = self._get_db()
            rows = local_db.execute_read(
                "SELECT cves_json, cached_at FROM cve_cache WHERE keyword = ?",
                (cache_key,)
            )
            if not rows:
                return None

            cves = json.loads(rows[0]["cves_json"])
            cached_at_str = rows[0].get("cached_at") or ""
            if cached_at_str:
                try:
                    cached_dt = datetime.datetime.fromisoformat(cached_at_str.replace("Z", ""))
                    age_sec = (datetime.datetime.utcnow() - cached_dt).total_seconds()
                    ttl = self.CACHE_TTL_WITH_CVES if len(cves) > 0 else self.CACHE_TTL_EMPTY
                    if age_sec > ttl:
                        return None
                except Exception:
                    return None
            return cves
        except Exception as e:
            print(f"[CVE CACHE ERROR] Falló lectura de caché local: {e}")
            return None

    def _write_cache(self, cache_key: str, vulnerabilidades: list):
        try:
            local_db = self._get_db()
            local_db.execute_write(
                "INSERT OR REPLACE INTO cve_cache (keyword, cves_json, cached_at) VALUES (?, ?, ?)",
                (cache_key, json.dumps(vulnerabilidades), datetime.datetime.utcnow().isoformat())
            )
        except Exception as ex:
            print(f"[CVE CACHE ERROR] Falló escritura de caché local: {ex}")

    def _query_nvd_api(self, query_type: str, query_value: str) -> list:
        """
        Ejecuta la consulta HTTP al NVD 2.0 respetando el rate-limiter global, con reintento
        único ante 429/503. Lanza excepción en fallo de red para NO contaminar la caché.
        """
        params = {"resultsPerPage": 8}
        if query_type == "cpe":
            params["cpeName"] = query_value
        else:
            params["keywordSearch"] = query_value

        headers = {"User-Agent": "Skop0-Auditor/1.3"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        last_status = None
        for attempt in range(2):
            self._acquire_rate_slot()
            resp = requests.get(self.BASE_URL, params=params, headers=headers, timeout=18)
            last_status = resp.status_code

            if resp.status_code == 200:
                datos = resp.json()
                raw_items = datos.get("vulnerabilities", [])
                parsed = []
                en_to_translate_idx = []
                en_to_translate_txt = []

                for item in raw_items:
                    cve_data = item.get("cve", {})
                    cve_id = cve_data.get("id", "Desconocido")

                    desc_es = ""
                    desc_en = ""
                    for desc in cve_data.get("descriptions", []):
                        lang = desc.get("lang")
                        if lang == "es" and not desc_es:
                            desc_es = desc.get("value", "")
                        elif lang == "en" and not desc_en:
                            desc_en = desc.get("value", "")

                    severidad = "No disponible"
                    score = 0.0
                    metricas = cve_data.get("metrics", {})
                    metricas_v3 = metricas.get("cvssMetricV31") or metricas.get("cvssMetricV30") or []
                    metricas_v2 = metricas.get("cvssMetricV2") or []

                    if metricas_v3:
                        cvss_data = metricas_v3[0].get("cvssData", {})
                        score = float(cvss_data.get("baseScore", 0.0) or 0.0)
                        severidad = cvss_data.get("baseSeverity", "No disponible")
                    elif metricas_v2:
                        cvss_data = metricas_v2[0].get("cvssData", {})
                        score = float(cvss_data.get("baseScore", 0.0) or 0.0)
                        severidad = metricas_v2[0].get("baseSeverity", "")
                        if not severidad:
                            if score >= 7.0:
                                severidad = "HIGH"
                            elif score >= 4.0:
                                severidad = "MEDIUM"
                            else:
                                severidad = "LOW"

                    parsed.append({
                        "cve_id": cve_id,
                        "descripcion": desc_es if desc_es else (desc_en or "Sin descripción disponible."),
                        "severidad": severidad,
                        "score": score,
                        "match_source": query_type,
                        "_needs_es": bool((not desc_es) and desc_en),
                    })

                # Ordenar por severidad CVSS descendente y conservar top 5 más críticos
                parsed.sort(key=lambda v: v["score"], reverse=True)
                top5 = parsed[:5]

                for idx, v in enumerate(top5):
                    if v.get("_needs_es"):
                        en_to_translate_idx.append(idx)
                        en_to_translate_txt.append(v["descripcion"])

                if en_to_translate_txt:
                    translated_list = self._traducir_lote_al_espanol(en_to_translate_txt)
                    for pos, tr_txt in zip(en_to_translate_idx, translated_list):
                        top5[pos]["descripcion"] = tr_txt

                for v in top5:
                    v.pop("_needs_es", None)

                return top5

            if resp.status_code in (429, 503) and attempt == 0:
                retry_after = resp.headers.get("Retry-After")
                try:
                    sleep_s = min(max(float(retry_after), 2.0), 10.0) if retry_after else 6.0
                except Exception:
                    sleep_s = 6.0
                print(f"[CVE WARN] NVD rate-limit/temporal ({resp.status_code}). Reintentando en {sleep_s:.1f}s...")
                time.sleep(sleep_s)
                continue

            if resp.status_code == 404:
                # CPE no registrado en NVD -> resultado legítimo vacío
                return []

            raise RuntimeError(f"NVD HTTP {resp.status_code}")

        raise RuntimeError(f"NVD HTTP {last_status}")

    def buscar_vulnerabilidades(self, nombre_servicio: str, version: str = "", producto: str = "", cpes: list = None) -> list:
        """
        Busca vulnerabilidades conocidas (CVEs) en NVD 2.0 usando CPE oficial (preferido)
        o `producto + versión` (fallback controlado), con caché TTL y deduplicación concurrente.
        """
        query = self.select_best_query(
            nombre_servicio=nombre_servicio,
            version=version,
            producto=producto,
            cpes=cpes,
        )
        if not query:
            return []

        query_type, query_value, cache_key = query

        # 1. Revisar caché local SQLite (con TTL)
        cached = self._read_cache(cache_key)
        if cached is not None:
            print(f"[CVE CACHE] hit local para '{cache_key}' ({len(cached)} CVEs)")
            return cached

        # 2. Deduplicación en vuelo: si otro hilo ya está consultando la misma clave, esperar su resultado
        is_owner = False
        with self._inflight_lock:
            entry = self._inflight_entries.get(cache_key)
            if entry is None:
                entry = {"event": threading.Event(), "result": []}
                self._inflight_entries[cache_key] = entry
                is_owner = True

        if not is_owner:
            entry["event"].wait(timeout=35.0)
            return list(entry["result"])

        # 3. Este hilo ejecuta la consulta real al NVD
        vulnerabilidades = []
        should_cache = False
        try:
            print(f"[CVE NVD] Consultando NVD ({query_type}) para: {query_value}...")
            vulnerabilidades = self._query_nvd_api(query_type, query_value)
            should_cache = True
            print(f"[CVE OK] Se encontraron {len(vulnerabilidades)} CVEs para '{query_value}'")
        except requests.exceptions.Timeout:
            print(f"[CVE TIMEOUT] Timeout al consultar NVD para '{query_value}' (no cacheado)")
        except Exception as e:
            print(f"[CVE ERROR] Error consultando NVD para '{query_value}': {e} (no cacheado)")
        finally:
            if should_cache:
                self._write_cache(cache_key, vulnerabilidades)
            entry["result"] = list(vulnerabilidades)
            with self._inflight_lock:
                self._inflight_entries.pop(cache_key, None)
            entry["event"].set()

        return vulnerabilidades
