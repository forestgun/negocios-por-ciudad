import time, re, io, json, requests, pandas as pd, streamlit as st
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

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

def find_emails_on_page(url: str, timeout: int = 15) -> tuple[set[str], list[str]]:
    """Devuelve (emails_encontrados, enlaces_internos_descubiertos) de una página."""
    try:
        r = requests.get(
            url, timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36"},
        )
        if r.status_code != 200 or not r.content:
            return set(), []
        soup = BeautifulSoup(r.content, "html.parser")

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

def parse_sitemap_for_contacts(sitemap_url: str, timeout: int = 15) -> list[str]:
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

def crawl_site_for_emails(start_url: str, max_pages: int = 8, delay: float = 1.0) -> set[str]:
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
            for u in parse_sitemap_for_contacts(url, timeout=15):
                if u not in seen:
                    queue.append(u)
            seen.add(url)
            continue

        if not same_domain(base, url):
            continue

        seen.add(url)
        emails, links = find_emails_on_page(url, timeout=15)
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

        time.sleep(delay)

    return found

# ─────────────────────────────────────────────────────────────
# Google Places
# ─────────────────────────────────────────────────────────────
def places_text_search_all(query: str, api_key: str, lang: str = "es", sleep_between_pages: float = 2.0) -> list[dict]:
    params = {"query": query, "key": api_key, "language": lang}
    r = requests.get(TEXT_SEARCH_URL, params=params, timeout=20)
    r.raise_for_status()
    data = r.json()
    if data.get("status") not in ("OK", "ZERO_RESULTS"):
        raise RuntimeError(f"TextSearch fallo: {data.get('status')} - {data.get('error_message')}")
    results = list(data.get("results", []))

    while True:
        token = data.get("next_page_token")
        if not token:
            break
        time.sleep(sleep_between_pages)
        r = requests.get(TEXT_SEARCH_URL, params={"pagetoken": token, "key": api_key}, timeout=20)
        r.raise_for_status()
        data = r.json()
        if data.get("status") not in ("OK", "ZERO_RESULTS"):
            break
        results.extend(data.get("results", []))
    return results

def place_details(place_id: str, api_key: str, lang: str = "es") -> dict:
    params = {
        "place_id": place_id, "key": api_key, "language": lang,
        "fields": "name,formatted_address,international_phone_number,website,geometry/location"
    }
    r = requests.get(DETAILS_URL, params=params, timeout=20)
    r.raise_for_status()
    data = r.json()
    if data.get("status") not in ("OK", "ZERO_RESULTS", "NOT_FOUND"):
        raise RuntimeError(f"Details fallo: {data.get('status')} - {data.get('error_message')}")
    return data.get("result", {}) or {}

# ─────────────────────────────────────────────────────────────
# UI
# ─────────────────────────────────────────────────────────────
st.set_page_config(page_title="DE0A10K RASTREATOR", layout="wide")
st.title("🔎 DE0A10K RASTREATOR")

# Autenticación obligatoria
auth_gate()

with st.sidebar:
    st.header("Configuración")
    api_key = st.secrets

    business_query = st.text_input("¿Qué negocio buscas?", value="peluquerías", help="Ej.: dentistas, autoescuelas, fisioterapia, abogados, etc.")
    city = st.text_input("Ciudad", value="Cádiz")
    search_lang = st.selectbox("Idioma de resultados", ["es", "en"], index=0)

    st.divider()
    st.subheader("Emails (opcional)")
    do_emails = st.checkbox("Buscar emails en webs oficiales", value=True)
    max_email_pages = st.slider("Páginas máximo por web", 1, 20, 10, help="Más páginas = más probabilidad (pero más lento).")
    email_delay = st.slider("Pausa entre páginas (seg.)", 0.0, 3.0, 0.8, 0.1)

    st.divider()
    st.subheader("Avanzado")
    details_delay = st.slider("Pausa entre 'Place Details' (seg.)", 0.05, 0.5, 0.10, 0.05)
    page_sleep = st.slider("Pausa entre páginas de Text Search (seg.)", 1.0, 4.0, 2.0, 0.5)

    run_btn = st.button("🔍 Buscar")

if run_btn:
    if not api_key:
        st.error("Falta Google API Key.")
        st.stop()
    if not business_query.strip() or not city.strip():
        st.error("Escribe el tipo de negocio y la ciudad.")
        st.stop()

    # Rate-limit
    rate_limit(max_per_min=4)

    q = f"{business_query.strip()} en {city.strip()}"
    st.info(f"Buscando: **{q}**")
    try:
        raw = places_text_search_all(q, api_key=api_key, lang=search_lang, sleep_between_pages=page_sleep)
    except Exception as e:
        st.error(f"Error en Text Search: {e}")
        st.stop()

    st.write(f"Resultados preliminares: **{len(raw)}**")
    rows, seen = [], set()
    progress = st.progress(0.0, text="Pidiendo detalles…")
    total = max(len(raw), 1)

    for i, it in enumerate(raw, start=1):
        pid = it.get("place_id")
        if not pid or pid in seen:
            progress.progress(i/total, text=f"Saltando duplicados… {i}/{total}")
            continue
        seen.add(pid)
        try:
            det = place_details(pid, api_key=api_key, lang=search_lang)
        except Exception:
            det = {}
        rows.append({
            "place_id": pid,
            "name": det.get("name"),
            "address": det.get("formatted_address"),
            "phone": det.get("international_phone_number"),
            "website": normalize_url(det.get("website")),
            "lat": (det.get("geometry", {}) or {}).get("location", {}).get("lat"),
            "lng": (det.get("geometry", {}) or {}).get("location", {}).get("lng"),
            "source_city_query": q
        })
        progress.progress(i/total, text=f"Detalles {i}/{total}")
        time.sleep(details_delay)

    df = pd.DataFrame(rows)
    if not df.empty:
        df.drop_duplicates(subset=["name", "address"], inplace=True)

    st.success(f"Con detalles: **{len(df)}** negocios únicos.")
    st.dataframe(df[["name","address","phone","website","source_city_query"]], use_container_width=True)

    # Emails (opcional)
    if do_emails and not df.empty:
        st.info("Buscando emails en webs oficiales (contacto/privacidad/aviso legal/about/sitemap)…")
        emails = []
        prog2 = st.progress(0.0, text="Rastreando emails…")
        n = len(df)
        for i, (_, row) in enumerate(df.iterrows(), start=1):
            site = row.get("website")
            if site:
                found = crawl_site_for_emails(site, max_pages=max_email_pages, delay=email_delay)
                emails.append(", ".join(sorted(found)) if found else "")
            else:
                emails.append("")
            prog2.progress(i/n, text=f"Emails {i}/{n}")
        df["emails"] = emails
    else:
        df["emails"] = ""

    # Quitar columnas técnicas antes de mostrar/descargar
    for c in ("place_id", "lat", "lng"):
        if c in df.columns:
            df.drop(columns=[c], inplace=True)

    st.subheader("Resultados")
    st.dataframe(df, use_container_width=True)

    csv_buf = io.StringIO()
    df.to_csv(csv_buf, index=False, encoding="utf-8-sig")
    st.download_button(
        "⬇️ Descargar CSV",
        data=csv_buf.getvalue().encode("utf-8-sig"),
        file_name=f"{business_query.strip()}_{city.strip()}.csv",
        mime="text/csv"
    )

    st.caption("Nota: algunas webs no publican correo o lo ocultan; aun así rastreamos contacto/privacidad/legal/about y sitemap si existe.")


