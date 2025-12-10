import time
import re
import io
import json
import asyncio
import requests
import pandas as pd
import streamlit as st
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

# ─────────────────────────────────────────────────────────────
# Seguridad: contraseña y rate-limit
# ─────────────────────────────────────────────────────────────
def auth_gate():
    """Bloquea la app con una contraseña guardada en st.secrets['APP_PASSWORD']."""
    if "auth_ok" not in st.session_state:
        st.session_state.auth_ok = False
    if st.session_state.auth_ok:
        return
    st.title("🔒 Acceso")
    pwd = st.text_input("Contraseña", type="password")
    if st.button("Entrar"):
        if pwd and pwd == st.secrets.get("APP_PASSWORD", ""):
            st.session_state.auth_ok = True
            st.rerun()
        else:
            st.error("Contraseña incorrecta.")
    st.stop()

def rate_limit(max_per_min=4):
    """Limita las búsquedas por sesión a X por minuto."""
    now = time.time()
    window = 60
    hist = st.session_state.get("req_hist", [])
    hist = [t for t in hist if now - t < window]
    if len(hist) >= max_per_min:
        st.warning("Has alcanzado el límite de búsquedas por minuto. Espera unos segundos y vuelve a intentarlo.")
        st.stop()
    hist.append(now)
    st.session_state["req_hist"] = hist

# ─────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────
DEFAULT_GOOGLE_API_KEY = ""  # ahora la leemos de st.secrets
LANG = "es"
TEXT_SEARCH_URL = "https://maps.googleapis.com/maps/api/place/textsearch/json"
DETAILS_URL     = "https://maps.googleapis.com/maps/api/place/details/json"

# ─────────────────────────────────────────────────────────────
# CONSTANTES - Columnas esperadas del DataFrame
# ─────────────────────────────────────────────────────────────
EXPECTED_COLUMNS = ["name", "address", "phone", "website", "source_city_query"]
ALL_COLUMNS = ["place_id", "name", "address", "phone", "website", "lat", "lng", "source_city_query"]

# ─────────────────────────────────────────────────────────────
# Utilidades de validación de DataFrame
# ─────────────────────────────────────────────────────────────
def safe_dataframe_display(df: pd.DataFrame, columns: list[str], fallback_message: str = "No hay datos para mostrar.") -> bool:
    """
    Muestra un DataFrame de forma segura, verificando que las columnas existan.
    
    Args:
        df: DataFrame a mostrar
        columns: Lista de columnas deseadas
        fallback_message: Mensaje si no hay datos
    
    Returns:
        True si se mostró el DataFrame, False si hubo problemas
    """
    if df is None or df.empty:
        st.warning(fallback_message)
        return False
    
    # Filtrar solo las columnas que existen
    available_columns = [col for col in columns if col in df.columns]
    
    if not available_columns:
        st.error(f"❌ Error: El DataFrame no tiene las columnas esperadas.")
        st.write("**Columnas esperadas:**", columns)
        st.write("**Columnas disponibles:**", df.columns.tolist())
        return False
    
    # Mostrar advertencia si faltan columnas
    missing_columns = [col for col in columns if col not in df.columns]
    if missing_columns:
        st.info(f"ℹ️ Algunas columnas no están disponibles: {missing_columns}")
    
    st.dataframe(df[available_columns], use_container_width=True)
    return True

def create_empty_dataframe_with_columns(columns: list[str]) -> pd.DataFrame:
    """Crea un DataFrame vacío con las columnas especificadas."""
    return pd.DataFrame(columns=columns)

def validate_api_response(data: dict, operation: str) -> tuple[bool, str]:
    """
    Valida la respuesta de la API de Google Places.
    
    Returns:
        (is_valid, error_message)
    """
    if not data:
        return False, f"{operation}: Respuesta vacía de la API"
    
    status = data.get("status", "UNKNOWN")
    
    if status == "OK":
        return True, ""
    elif status == "ZERO_RESULTS":
        return True, ""  # Válido pero sin resultados
    elif status == "OVER_QUERY_LIMIT":
        return False, f"{operation}: Has excedido el límite de consultas de la API. Espera unos minutos."
    elif status == "REQUEST_DENIED":
        return False, f"{operation}: Solicitud denegada. Verifica tu API Key y que Places API esté habilitada."
    elif status == "INVALID_REQUEST":
        return False, f"{operation}: Solicitud inválida. Verifica los parámetros."
    else:
        error_msg = data.get("error_message", "Error desconocido")
        return False, f"{operation}: {status} - {error_msg}"

# ─────────────────────────────────────────────────────────────
# Utilidades web / emails
# ─────────────────────────────────────────────────────────────
def normalize_url(u: str | None) -> str | None:
    if not u: return None
    u = u.strip()
    if not u or u.startswith(("mailto:", "tel:")): return None
    if not u.startswith(("http://", "https://")):
        u = "http://" + u
    return u.rstrip("/")

def same_domain(base: str, candidate: str) -> bool:
    try:
        bd = urlparse(base).netloc
        cd = urlparse(candidate).netloc
        return bd == cd or cd.endswith("." + bd) or bd.endswith("." + cd)
    except:
        return False

EMAIL_REGEX = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.I)
OBFUSCATED_REGEX = re.compile(
    r"""([A-Za-z0-9._%+-]+)\s*(?:\(|\[|{)?\s*(?:at|arroba|@)\s*(?:\)|\]|})?\s*([A-Za-z0-9.-]+)\s*(?:\(|\[|{)?\s*(?:dot|punto|\.)\s*(?:\)|\]|})?\s*([A-Za-z]{2,})""",
    re.IGNORECASE
)

def extract_obfuscated(text: str) -> set[str]:
    emails = set()
    for left, mid, tld in OBFUSCATED_REGEX.findall(text):
        emails.add(f"{left}@{mid}.{tld}".replace(" ", ""))
    return emails

def extract_emails_jsonld(soup: BeautifulSoup) -> set[str]:
    found = set()
    for tag in soup.find_all("script", type="application/ld+json"):
        try:
            data = json.loads(tag.string or "")
            items = data if isinstance(data, list) else [data]
            for obj in items:
                if not isinstance(obj, dict):
                    continue
                e = obj.get("email")
                if isinstance(e, str) and "@" in e:
                    found.add(e.strip())
                cp = obj.get("contactPoint")
                if isinstance(cp, dict):
                    e2 = cp.get("email")
                    if isinstance(e2, str) and "@" in e2:
                        found.add(e2.strip())
                elif isinstance(cp, list):
                    for c in cp:
                        if isinstance(c, dict):
                            e3 = c.get("email")
                            if isinstance(e3, str) and "@" in e3:
                                found.add(e3.strip())
        except Exception:
            continue
    return found

def find_emails_on_page(url: str, timeout: int = 5) -> tuple[set[str], list[str]]:
    """Devuelve (emails_encontrados, enlaces_internos_descubiertos) de una página."""
    try:
        r = requests.get(
            url, timeout=timeout, stream=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36"},
        )
        if r.status_code != 200:
            return set(), []

        # Limitar tamaño de descarga a 1MB
        content = b""
        for chunk in r.iter_content(chunk_size=8192):
            content += chunk
            if len(content) > 1_000_000:
                break

        if not content:
            return set(), []

        soup = BeautifulSoup(content, "html.parser")

        text = soup.get_text(" ", strip=True)
        found = set(EMAIL_REGEX.findall(text))
        found |= extract_emails_jsonld(soup)

        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.lower().startswith("mailto:"):
                addr = href.split("mailto:", 1)[1].split("?", 1)[0]
                for part in addr.replace(";", ",").split(","):
                    part = part.strip()
                    if part:
                        found.add(part)

        found |= extract_obfuscated(text)
        found = {e for e in found if "@" in e and not e.lower().endswith("@google.com")}

        links = []
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith("#") or href.lower().startswith("tel:"):
                continue
            links.append(urljoin(url, href))

        return found, links
    except requests.RequestException:
        return set(), []

def seed_candidate_urls(base_url: str) -> list[str]:
    paths = [
        "/", "/contacto", "/contact", "/contact-us", "/contacto/", "/contact/",
        "/aviso-legal", "/aviso_legal", "/legal", "/aviso-legal/",
        "/privacidad", "/politica-privacidad", "/politica_de_privacidad", "/privacy", "/privacy-policy", "/privacy/",
        "/about", "/about-us", "/quienes-somos", "/quienessomos", "/empresa", "/about/",
        "/sitemap.xml"
    ]
    return [urljoin(base_url, p) for p in paths]

def parse_sitemap_for_contacts(sitemap_url: str, timeout: int = 5) -> list[str]:
    try:
        r = requests.get(sitemap_url, timeout=timeout, headers={"User-Agent":"Mozilla/5.0"})
        if r.status_code != 200 or not r.content:
            return []
        soup = BeautifulSoup(r.content, "xml")
        urls = [loc.get_text(strip=True) for loc in soup.find_all("loc")]
        keys = ("contact", "contacto", "aviso", "legal", "privacy", "privacidad", "about", "quien", "quién", "mail")
        return [u for u in urls if any(k in u.lower() for k in keys)]
    except Exception:
        return []

def crawl_site_for_emails(start_url: str, max_pages: int = 8, delay: float = 0.3) -> set[str]:
    """Rastrea home + contacto/privacidad/legal/about y sitemap si existe (mismo dominio)."""
    start = normalize_url(start_url)
    if not start:
        return set()

    seen: set[str] = set()
    queue: list[str] = seed_candidate_urls(start)
    found: set[str] = set()
    base = start

    sm = normalize_url(urljoin(start, "/sitemap.xml"))
    if sm and sm not in queue:
        queue.append(sm)

    while queue and len(seen) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue

        if url.endswith("/sitemap.xml"):
            for u in parse_sitemap_for_contacts(url, timeout=5):
                if u not in seen:
                    queue.append(u)
            seen.add(url)
            continue

        if not same_domain(base, url):
            continue

        seen.add(url)
        emails, links = find_emails_on_page(url, timeout=5)
        found.update(emails)

        prioritized = [l for l in links if any(x in l.lower() for x in
            ["contact", "contacto", "aviso", "legal", "privacy", "privacidad", "about", "quien", "quién", "info", "mail"])]
        if len(prioritized) < 2:
            for l in links:
                if l not in prioritized and same_domain(base, l):
                    prioritized.append(l)
                if len(prioritized) >= 6:
                    break

        for l in prioritized:
            if l not in seen and len(seen) + len(queue) < max_pages + 10:
                queue.append(l)

        # Delay solo dentro del mismo sitio (reducido)
        time.sleep(delay)

    return found

def crawl_multiple_sites_parallel(websites: list[str], max_pages: int = 8, delay: float = 0.3, max_workers: int = 10) -> list[set[str]]:
    """
    Procesa múltiples sitios web en paralelo usando ThreadPoolExecutor.

    Args:
        websites: Lista de URLs de sitios web a rastrear
        max_pages: Número máximo de páginas por sitio
        delay: Delay entre páginas del mismo sitio
        max_workers: Número máximo de threads paralelos

    Returns:
        Lista de sets de emails, en el mismo orden que websites
    """
    results = [set() for _ in websites]

    # Crear diccionario de índice a website (solo los que tienen URL)
    site_tasks = {}
    for idx, site in enumerate(websites):
        if site:
            site_tasks[idx] = site

    # Procesar en paralelo
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Enviar todas las tareas
        future_to_idx = {
            executor.submit(crawl_site_for_emails, site, max_pages, delay): idx
            for idx, site in site_tasks.items()
        }

        # Recolectar resultados a medida que se completan
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception as e:
                # En caso de error, devolver set vacío
                results[idx] = set()

    return results

# ─────────────────────────────────────────────────────────────
# ASYNCIO - Versión asíncrona (10-30x más rápida)
# ─────────────────────────────────────────────────────────────

if AIOHTTP_AVAILABLE:
    async def find_emails_on_page_async(session: aiohttp.ClientSession, url: str, timeout: int = 5) -> tuple[set[str], list[str]]:
        """Versión asíncrona de find_emails_on_page."""
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                if response.status != 200:
                    return set(), []

                # Limitar tamaño de descarga a 1MB
                content = await response.content.read(1_000_000)

                if not content:
                    return set(), []

                soup = BeautifulSoup(content, "html.parser")

                text = soup.get_text(" ", strip=True)
                found = set(EMAIL_REGEX.findall(text))
                found |= extract_emails_jsonld(soup)

                # Buscar enlaces mailto
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if href.lower().startswith("mailto:"):
                        addr = href.split("mailto:", 1)[1].split("?", 1)[0]
                        for part in addr.replace(";", ",").split(","):
                            part = part.strip()
                            if part:
                                found.add(part)

                found |= extract_obfuscated(text)
                found = {e for e in found if "@" in e and not e.lower().endswith("@google.com")}

                # Extraer enlaces
                links = []
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if href.startswith("#") or href.lower().startswith("tel:"):
                        continue
                    links.append(urljoin(url, href))

                return found, links
        except Exception:
            return set(), []

    async def parse_sitemap_for_contacts_async(session: aiohttp.ClientSession, sitemap_url: str, timeout: int = 5) -> list[str]:
        """Versión asíncrona de parse_sitemap_for_contacts."""
        try:
            async with session.get(sitemap_url, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                if response.status != 200:
                    return []
                content = await response.read()
                if not content:
                    return []

                soup = BeautifulSoup(content, "xml")
                urls = [loc.get_text(strip=True) for loc in soup.find_all("loc")]
                keys = ("contact", "contacto", "aviso", "legal", "privacy", "privacidad", "about", "quien", "quién", "mail")
                return [u for u in urls if any(k in u.lower() for k in keys)]
        except Exception:
            return []

    async def crawl_site_for_emails_async(session: aiohttp.ClientSession, start_url: str, max_pages: int = 8, delay: float = 0.1) -> set[str]:
        """Versión asíncrona de crawl_site_for_emails - mucho más rápida."""
        start = normalize_url(start_url)
        if not start:
            return set()

        seen: set[str] = set()
        queue: list[str] = seed_candidate_urls(start)
        found: set[str] = set()
        base = start

        sm = normalize_url(urljoin(start, "/sitemap.xml"))
        if sm and sm not in queue:
            queue.append(sm)

        while queue and len(seen) < max_pages:
            url = queue.pop(0)
            if url in seen:
                continue

            if url.endswith("/sitemap.xml"):
                sitemap_urls = await parse_sitemap_for_contacts_async(session, url, timeout=5)
                for u in sitemap_urls:
                    if u not in seen:
                        queue.append(u)
                seen.add(url)
                continue

            if not same_domain(base, url):
                continue

            seen.add(url)
            emails, links = await find_emails_on_page_async(session, url, timeout=5)
            found.update(emails)

            prioritized = [l for l in links if any(x in l.lower() for x in
                ["contact", "contacto", "aviso", "legal", "privacy", "privacidad", "about", "quien", "quién", "info", "mail"])]
            if len(prioritized) < 2:
                for l in links:
                    if l not in prioritized and same_domain(base, l):
                        prioritized.append(l)
                    if len(prioritized) >= 6:
                        break

            for l in prioritized:
                if l not in seen and len(seen) + len(queue) < max_pages + 10:
                    queue.append(l)

            # Delay muy pequeño (asyncio maneja la concurrencia mejor)
            if delay > 0:
                await asyncio.sleep(delay)

        return found

    async def crawl_multiple_sites_async(websites: list[str], max_pages: int = 8, delay: float = 0.1, max_concurrent: int = 20) -> list[set[str]]:
        """
        Procesa múltiples sitios web de forma asíncrona (MUCHO MÁS RÁPIDO).

        Args:
            websites: Lista de URLs de sitios web a rastrear
            max_pages: Número máximo de páginas por sitio
            delay: Delay entre páginas del mismo sitio (puede ser muy bajo con asyncio)
            max_concurrent: Número máximo de sitios procesándose simultáneamente

        Returns:
            Lista de sets de emails, en el mismo orden que websites
        """
        results = [set() for _ in websites]

        # Configurar session con headers
        connector = aiohttp.TCPConnector(limit=max_concurrent, limit_per_host=5)
        timeout = aiohttp.ClientTimeout(total=60, connect=10, sock_read=10)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36"}
        ) as session:
            # Crear tareas para todos los sitios
            tasks = []
            for idx, site in enumerate(websites):
                if site:
                    task = crawl_site_for_emails_async(session, site, max_pages, delay)
                    tasks.append((idx, task))

            # Ejecutar todas las tareas en paralelo con asyncio.gather
            task_list = [task for idx, task in tasks]
            completed_results = await asyncio.gather(*task_list, return_exceptions=True)

            # Mapear resultados a los índices correctos
            for i, (idx, _) in enumerate(tasks):
                result = completed_results[i]
                if isinstance(result, set):
                    results[idx] = result
                else:
                    results[idx] = set()

        return results

# ─────────────────────────────────────────────────────────────
# Google Places - CON VALIDACIÓN MEJORADA
# ─────────────────────────────────────────────────────────────
def places_text_search_all(query: str, api_key: str, lang: str = "es", sleep_between_pages: float = 2.0) -> tuple[list[dict], str | None]:
    """
    Busca lugares usando Google Places Text Search API.
    
    Returns:
        (results, error_message) - results es la lista de lugares, error_message es None si OK
    """
    try:
        params = {"query": query, "key": api_key, "language": lang}
        r = requests.get(TEXT_SEARCH_URL, params=params, timeout=20)
        r.raise_for_status()
        data = r.json()
        
        # Validar respuesta
        is_valid, error_msg = validate_api_response(data, "TextSearch")
        if not is_valid:
            return [], error_msg
        
        results = list(data.get("results", []))

        # Paginación
        page_count = 1
        max_pages = 3  # Límite de seguridad
        
        while page_count < max_pages:
            token = data.get("next_page_token")
            if not token:
                break
            time.sleep(sleep_between_pages)
            
            try:
                r = requests.get(TEXT_SEARCH_URL, params={"pagetoken": token, "key": api_key}, timeout=20)
                r.raise_for_status()
                data = r.json()
                
                is_valid, _ = validate_api_response(data, "TextSearch (página)")
                if not is_valid:
                    break
                    
                results.extend(data.get("results", []))
                page_count += 1
            except requests.RequestException:
                break
        
        return results, None
        
    except requests.Timeout:
        return [], "TextSearch: Tiempo de espera agotado. Intenta de nuevo."
    except requests.RequestException as e:
        return [], f"TextSearch: Error de conexión - {str(e)}"
    except Exception as e:
        return [], f"TextSearch: Error inesperado - {str(e)}"

def place_details(place_id: str, api_key: str, lang: str = "es") -> tuple[dict, str | None]:
    """
    Obtiene detalles de un lugar específico.
    
    Returns:
        (result, error_message) - result es el diccionario de detalles, error_message es None si OK
    """
    try:
        params = {
            "place_id": place_id, "key": api_key, "language": lang,
            "fields": "name,formatted_address,international_phone_number,website,geometry/location"
        }
        r = requests.get(DETAILS_URL, params=params, timeout=20)
        r.raise_for_status()
        data = r.json()
        
        status = data.get("status", "UNKNOWN")
        if status == "OK":
            return data.get("result", {}), None
        elif status in ("ZERO_RESULTS", "NOT_FOUND"):
            return {}, None  # No es error, simplemente no existe
        else:
            error_msg = data.get("error_message", "")
            return {}, f"Details ({status}): {error_msg}"
            
    except requests.Timeout:
        return {}, "Details: Tiempo de espera agotado"
    except requests.RequestException as e:
        return {}, f"Details: Error de conexión - {str(e)}"
    except Exception as e:
        return {}, f"Details: Error inesperado - {str(e)}"

# ─────────────────────────────────────────────────────────────
# UI
# ─────────────────────────────────────────────────────────────
st.set_page_config(page_title="DE0A10K RASTREATOR", layout="wide")
st.title("🔎 DE0A10K RASTREATOR")

# Autenticación obligatoria
auth_gate()

with st.sidebar:
    st.header("Configuración")
    default_key = st.secrets.get("DEFAULT_GOOGLE_API_KEY", "")
    api_key = st.text_input("Google API Key", type="password", value=default_key, help="Places API habilitada.")
    business_query = st.text_input("¿Qué negocio buscas?", value="peluquerías", help="Ej.: dentistas, autoescuelas, fisioterapia, abogados, etc.")
    city = st.text_input("Ciudad", value="Cádiz")
    search_lang = st.selectbox("Idioma de resultados", ["es", "en"], index=0)

    st.divider()
    st.subheader("Emails (opcional)")
    do_emails = st.checkbox("Buscar emails en webs oficiales", value=True)

    # Solo mostrar opción AsyncIO si está disponible
    if AIOHTTP_AVAILABLE:
        use_async = st.checkbox("Usar modo AsyncIO (10-30x más rápido)", value=True, help="Recomendado: usa asyncio para máxima velocidad.")
    else:
        use_async = False
        st.info("💡 Para mejor rendimiento, instala aiohttp: `pip install aiohttp`")

    max_email_pages = st.slider("Páginas máximo por web", 1, 20, 8, help="Más páginas = más probabilidad (pero más lento).")

    if use_async:
        email_delay = st.slider("Pausa entre páginas (seg.)", 0.0, 1.0, 0.1, 0.05, help="Con AsyncIO puede ser muy bajo.")
        max_workers = st.slider("Conexiones concurrentes", 5, 50, 20, help="AsyncIO puede manejar muchas más conexiones simultáneas.")
    else:
        email_delay = st.slider("Pausa entre páginas (seg.)", 0.0, 3.0, 0.3, 0.1, help="Delay entre páginas del mismo sitio.")
        max_workers = st.slider("Sitios en paralelo", 1, 20, 10, help="Cuántos sitios web procesar simultáneamente.")

    st.divider()
    st.subheader("Avanzado")
    details_delay = st.slider("Pausa entre 'Place Details' (seg.)", 0.05, 0.5, 0.10, 0.05)
    page_sleep = st.slider("Pausa entre páginas de Text Search (seg.)", 1.0, 4.0, 2.0, 0.5)

    run_btn = st.button("🔍 Buscar")

if run_btn:
    # ─────────────────────────────────────────────────────────────
    # VALIDACIÓN DE ENTRADA
    # ─────────────────────────────────────────────────────────────
    if not api_key:
        st.error("❌ Falta Google API Key.")
        st.stop()
    if not business_query.strip() or not city.strip():
        st.error("❌ Escribe el tipo de negocio y la ciudad.")
        st.stop()

    # Rate-limit
    rate_limit(max_per_min=4)

    q = f"{business_query.strip()} en {city.strip()}"
    st.info(f"🔍 Buscando: **{q}**")
    
    # ─────────────────────────────────────────────────────────────
    # BÚSQUEDA DE LUGARES - CON MANEJO DE ERRORES
    # ─────────────────────────────────────────────────────────────
    raw, search_error = places_text_search_all(q, api_key=api_key, lang=search_lang, sleep_between_pages=page_sleep)
    
    if search_error:
        st.error(f"❌ {search_error}")
        st.stop()
    
    if not raw:
        st.warning(f"⚠️ No se encontraron resultados para '{q}'. Prueba con otra búsqueda o ciudad.")
        st.stop()

    st.write(f"📍 Resultados preliminares: **{len(raw)}**")
    
    # ─────────────────────────────────────────────────────────────
    # OBTENER DETALLES - CON VALIDACIÓN
    # ─────────────────────────────────────────────────────────────
    rows, seen = [], set()
    errors_count = 0
    progress = st.progress(0.0, text="Pidiendo detalles…")
    total = max(len(raw), 1)

    for i, it in enumerate(raw, start=1):
        pid = it.get("place_id")
        if not pid or pid in seen:
            progress.progress(i/total, text=f"Saltando duplicados… {i}/{total}")
            continue
        seen.add(pid)
        
        det, detail_error = place_details(pid, api_key=api_key, lang=search_lang)
        
        if detail_error:
            errors_count += 1
            # Si hay muchos errores seguidos, probablemente hay un problema con la API
            if errors_count > 5:
                st.warning(f"⚠️ Demasiados errores al obtener detalles. Último error: {detail_error}")
                break
        
        # Crear fila con valores por defecto para evitar KeyError
        rows.append({
            "place_id": pid,
            "name": det.get("name") or it.get("name", "Sin nombre"),
            "address": det.get("formatted_address") or it.get("formatted_address", ""),
            "phone": det.get("international_phone_number", ""),
            "website": normalize_url(det.get("website")),
            "lat": (det.get("geometry", {}) or {}).get("location", {}).get("lat"),
            "lng": (det.get("geometry", {}) or {}).get("location", {}).get("lng"),
            "source_city_query": q
        })
        progress.progress(i/total, text=f"Detalles {i}/{total}")
        time.sleep(details_delay)

    # ─────────────────────────────────────────────────────────────
    # CREAR DATAFRAME - CON VALIDACIÓN
    # ─────────────────────────────────────────────────────────────
    if not rows:
        st.warning("⚠️ No se pudieron obtener detalles de ningún negocio.")
        # Crear DataFrame vacío con columnas correctas para evitar errores posteriores
        df = create_empty_dataframe_with_columns(ALL_COLUMNS)
    else:
        df = pd.DataFrame(rows)
        
        # Asegurar que todas las columnas esperadas existan
        for col in ALL_COLUMNS:
            if col not in df.columns:
                df[col] = ""
        
        # Eliminar duplicados solo si hay datos
        if not df.empty and "name" in df.columns and "address" in df.columns:
            df.drop_duplicates(subset=["name", "address"], inplace=True)

    # ─────────────────────────────────────────────────────────────
    # MOSTRAR RESULTADOS PARCIALES - CON VALIDACIÓN
    # ─────────────────────────────────────────────────────────────
    if df.empty:
        st.warning("⚠️ No hay negocios para mostrar.")
    else:
        st.success(f"✅ Con detalles: **{len(df)}** negocios únicos.")
        safe_dataframe_display(df, EXPECTED_COLUMNS, "No hay datos para mostrar.")

    # ─────────────────────────────────────────────────────────────
    # EMAILS (OPCIONAL) - CON VALIDACIÓN
    # ─────────────────────────────────────────────────────────────
    if do_emails and not df.empty and "website" in df.columns:
        # Obtener lista de websites de forma segura
        websites = df["website"].fillna("").tolist()
        total_sites = len([s for s in websites if s])
        
        if total_sites == 0:
            st.info("ℹ️ Ningún negocio tiene website para buscar emails.")
            df["emails"] = ""
        elif use_async and AIOHTTP_AVAILABLE:
            # ⚡ MODO ASYNCIO - SUPER RÁPIDO
            st.info(f"⚡ Buscando emails (AsyncIO: {max_workers} conexiones concurrentes)…")
            prog2 = st.progress(0.0, text="Rastreando emails con AsyncIO…")

            # Ejecutar asyncio de forma segura en Streamlit
            try:
                # Intentar obtener el loop existente o crear uno nuevo
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_closed():
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)

                email_results_sets = loop.run_until_complete(
                    crawl_multiple_sites_async(websites, max_email_pages, email_delay, max_workers)
                )
                email_results = [", ".join(sorted(emails)) if emails else "" for emails in email_results_sets]
                prog2.progress(1.0, text=f"✅ Completado: {total_sites} sitios")
            except Exception as e:
                st.error(f"❌ Error en AsyncIO: {e}")
                email_results = [""] * len(websites)

            df["emails"] = email_results

        else:
            # 🔄 MODO THREADING - Compatible pero más lento
            st.info(f"🚀 Buscando emails (Threading: {max_workers} sitios en paralelo)…")
            prog2 = st.progress(0.0, text="Rastreando emails en paralelo…")

            # Procesar en paralelo usando ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Enviar todas las tareas
                future_to_idx = {
                    executor.submit(crawl_site_for_emails, site, max_email_pages, email_delay): idx
                    for idx, site in enumerate(websites) if site
                }

                # Preparar resultados
                email_results = [""] * len(websites)
                completed = 0

                # Recolectar resultados a medida que se completan
                for future in as_completed(future_to_idx):
                    idx = future_to_idx[future]
                    try:
                        found = future.result()
                        email_results[idx] = ", ".join(sorted(found)) if found else ""
                    except Exception:
                        email_results[idx] = ""

                    completed += 1
                    prog2.progress(completed / max(total_sites, 1), text=f"Emails {completed}/{total_sites} sitios completados")

            df["emails"] = email_results
        
        emails_found = sum(1 for e in df["emails"] if e)
        st.success(f"✅ Rastreo completado: {emails_found} sitios con emails encontrados")
    else:
        if "emails" not in df.columns:
            df["emails"] = ""

    # ─────────────────────────────────────────────────────────────
    # PREPARAR RESULTADOS FINALES - CON VALIDACIÓN
    # ─────────────────────────────────────────────────────────────
    # Quitar columnas técnicas antes de mostrar/descargar
    columns_to_drop = ["place_id", "lat", "lng"]
    for c in columns_to_drop:
        if c in df.columns:
            df.drop(columns=[c], inplace=True)

    st.subheader("📊 Resultados Finales")
    
    if df.empty:
        st.warning("⚠️ No hay resultados para mostrar.")
    else:
        st.dataframe(df, use_container_width=True)

        # ─────────────────────────────────────────────────────────────
        # DESCARGA CSV - CON VALIDACIÓN
        # ─────────────────────────────────────────────────────────────
        try:
            csv_buf = io.StringIO()
            df.to_csv(csv_buf, index=False, encoding="utf-8-sig")
            
            # Sanitizar nombre de archivo
            safe_business = re.sub(r'[^\w\s-]', '', business_query.strip())[:30]
            safe_city = re.sub(r'[^\w\s-]', '', city.strip())[:30]
            filename = f"{safe_business}_{safe_city}.csv"
            
            st.download_button(
                "⬇️ Descargar CSV",
                data=csv_buf.getvalue().encode("utf-8-sig"),
                file_name=filename,
                mime="text/csv"
            )
        except Exception as e:
            st.error(f"❌ Error al generar CSV: {e}")

    st.caption("📝 Nota: algunas webs no publican correo o lo ocultan; aun así rastreamos contacto/privacidad/legal/about y sitemap si existe.")