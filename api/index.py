import time
import asyncio
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(
    title="LEAK-API",
    description="Vérifiez si vos données ont été compromises dans un data breach.",
    version="2.0.0",
    docs_url="/docs",
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class BreachRecord(BaseModel):
    breach_name: str
    breach_date: str
    description: str
    compromised_fields: list[str]
    affected_accounts: Optional[int] = None
    verified: bool
    severity: str


class SearchResponse(BaseModel):
    query: str
    timestamp: str
    breach_count: int
    breaches: list[BreachRecord]
    meta: dict


class ErrorResponse(BaseModel):
    error: str
    detail: str
    status: int


async def lookup_breaches(query: str) -> list[BreachRecord]:
    """
    ═══════════════════════════════════════════════════════════
     CONNECT YOUR DATA SOURCE HERE
     Remplace cette fonction par ta vraie source de données :

     • Elasticsearch : client.search(index="breaches", ...)
     • PostgreSQL    : await db.fetch("SELECT * FROM breaches WHERE ...")
     • MongoDB       : await collection.find({"emails": query})
     • API HIBP      : httpx.get("https://haveibeenpwned.com/api/v3/...")
    ═══════════════════════════════════════════════════════════
    """
    await asyncio.sleep(0.04)

    q = query.lower().strip()

    KNOWN_BREACHES = [
        BreachRecord(
            breach_name="LinkedIn 2021",
            breach_date="2021-04-06",
            description="Scraping massif de 700 millions de profils LinkedIn. Les données incluent emails, numéros de téléphone, adresses et informations professionnelles.",
            compromised_fields=["email", "phone", "full_name", "location", "job_title"],
            affected_accounts=700_000_000,
            verified=True,
            severity="high",
        ),
        BreachRecord(
            breach_name="Facebook 2019",
            breach_date="2019-09-04",
            description="Exposition de 419 millions de numéros de téléphone liés à des comptes Facebook via une base non sécurisée.",
            compromised_fields=["phone", "facebook_id", "full_name", "gender"],
            affected_accounts=419_000_000,
            verified=True,
            severity="high",
        ),
        BreachRecord(
            breach_name="Adobe 2013",
            breach_date="2013-10-03",
            description="Breach d'Adobe exposant des identifiants chiffrés, questions de sécurité et données de cartes partielles.",
            compromised_fields=["email", "username", "encrypted_password", "hint"],
            affected_accounts=153_000_000,
            verified=True,
            severity="critical",
        ),
        BreachRecord(
            breach_name="Canva 2019",
            breach_date="2019-05-24",
            description="Accès non autorisé aux serveurs de Canva exposant des données utilisateurs.",
            compromised_fields=["email", "username", "full_name", "hashed_password"],
            affected_accounts=137_000_000,
            verified=True,
            severity="medium",
        ),
        BreachRecord(
            breach_name="Dropbox 2012",
            breach_date="2012-07-01",
            description="Des identifiants volés depuis d'autres sites ont été utilisés pour accéder à Dropbox, exposant 68M d'emails et mots de passe hashés.",
            compromised_fields=["email", "hashed_password"],
            affected_accounts=68_648_009,
            verified=True,
            severity="high",
        ),
    ]

    if "@" in q or any(domain in q for domain in [".com", ".fr", ".net", ".org", ".ca"]):
        return KNOWN_BREACHES[:3]
    if len(q) > 5:
        return KNOWN_BREACHES[1:4]
    return []


UI_HTML = open("index.html").read() if False else ""


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def ui():
    return HTMLResponse(content=_UI_HTML)


@app.get(
    "/search",
    response_model=SearchResponse,
    responses={
        400: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
    summary="Rechercher des breaches par email / username / domaine",
    tags=["Search"],
)
async def search(
    q: str = Query(
        ...,
        min_length=3,
        description="Email, username ou domaine à vérifier.",
        example="john.doe@example.com",
    )
):
    if len(q.strip()) < 3:
        raise HTTPException(status_code=400, detail={
            "error": "query_too_short",
            "detail": "Le paramètre 'q' doit contenir au moins 3 caractères.",
            "status": 400,
        })

    start = time.perf_counter()

    try:
        breaches = await lookup_breaches(q.strip())
    except Exception as exc:
        raise HTTPException(status_code=500, detail={
            "error": "internal_server_error",
            "detail": str(exc),
            "status": 500,
        })

    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

    if not breaches:
        raise HTTPException(status_code=404, detail={
            "error": "not_found",
            "detail": f"Aucun breach trouvé pour : '{q}'",
            "status": 404,
        })

    return SearchResponse(
        query=q.strip(),
        timestamp=datetime.now(timezone.utc).isoformat(),
        breach_count=len(breaches),
        breaches=breaches,
        meta={
            "execution_time_ms": elapsed_ms,
            "api_status": "operational",
            "note": "Les mots de passe en clair ne sont jamais exposés.",
        },
    )


_UI_HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>LEAK-API — Breach Lookup</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=JetBrains+Mono:wght@300;400;500&display=swap" rel="stylesheet">
<style>
:root {
  --bg:#05060a; --surface:#0d0f17; --surface2:#141720; --border:#1e2235;
  --accent:#e63946; --accent2:#ff6b6b; --safe:#2ecc71; --warn:#f39c12;
  --text:#e8eaf0; --muted:#6b7080;
  --mono:'JetBrains Mono',monospace; --sans:'Syne',sans-serif;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh;overflow-x:hidden}
.noise{position:fixed;inset:0;pointer-events:none;z-index:0;background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.035'/%3E%3C/svg%3E");opacity:0.4}
.grid-bg{position:fixed;inset:0;pointer-events:none;z-index:0;background-image:linear-gradient(var(--border) 1px,transparent 1px),linear-gradient(90deg,var(--border) 1px,transparent 1px);background-size:48px 48px;opacity:0.3}
.glow{position:fixed;top:-20vh;left:50%;transform:translateX(-50%);width:60vw;height:40vh;background:radial-gradient(ellipse,rgba(230,57,70,.12) 0%,transparent 70%);pointer-events:none;z-index:0}
.container{position:relative;z-index:1;max-width:860px;margin:0 auto;padding:64px 24px 80px}
header{text-align:center;margin-bottom:56px;animation:fadeDown .6s ease both}
.badge{display:inline-flex;align-items:center;gap:6px;background:rgba(230,57,70,.1);border:1px solid rgba(230,57,70,.3);color:var(--accent2);font-family:var(--mono);font-size:11px;letter-spacing:.1em;padding:4px 12px;border-radius:2px;margin-bottom:20px;text-transform:uppercase}
.badge::before{content:'●';animation:blink 1.4s ease infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
h1{font-size:clamp(2.4rem,6vw,4rem);font-weight:800;letter-spacing:-.03em;line-height:1;margin-bottom:12px}
h1 span{color:var(--accent)}
.subtitle{color:var(--muted);font-family:var(--mono);font-size:13px;letter-spacing:.04em}
.search-wrap{display:flex;background:var(--surface);border:1px solid var(--border);border-radius:4px;overflow:hidden;transition:border-color .2s;animation:fadeUp .6s .15s ease both}
.search-wrap:focus-within{border-color:var(--accent);box-shadow:0 0 0 3px rgba(230,57,70,.08),0 0 24px rgba(230,57,70,.06)}
.search-prefix{display:flex;align-items:center;padding:0 16px;color:var(--muted);font-family:var(--mono);font-size:12px;border-right:1px solid var(--border);white-space:nowrap;user-select:none}
input[type="text"]{flex:1;background:transparent;border:none;outline:none;color:var(--text);font-family:var(--mono);font-size:14px;padding:16px 18px}
input::placeholder{color:var(--muted)}
button[type="submit"]{background:var(--accent);border:none;outline:none;color:#fff;font-family:var(--sans);font-size:13px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;padding:0 28px;cursor:pointer;transition:background .15s,transform .1s}
button[type="submit"]:hover{background:#c0303b}
button[type="submit"]:active{transform:scale(.97)}
.hints{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px;animation:fadeUp .6s .25s ease both}
.hint{font-family:var(--mono);font-size:11px;color:var(--muted);background:var(--surface);border:1px solid var(--border);padding:3px 10px;border-radius:2px;cursor:pointer;transition:color .15s,border-color .15s}
.hint:hover{color:var(--text);border-color:var(--muted)}
#results{margin-top:48px}
.status-bar{display:flex;align-items:center;gap:12px;font-family:var(--mono);font-size:12px;color:var(--muted);border-bottom:1px solid var(--border);padding-bottom:16px;margin-bottom:24px}
.status-bar .count{color:var(--accent2);font-weight:500}
.status-bar .sep{opacity:.3}
.breach-card{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:24px;margin-bottom:12px;position:relative;overflow:hidden;animation:slideIn .4s ease both}
.breach-card::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px}
.breach-card.critical::before{background:var(--accent)}
.breach-card.high::before{background:#e67e22}
.breach-card.medium::before{background:var(--warn)}
.breach-card.low::before{background:#3498db}
.card-header{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:10px}
.breach-name{font-size:1rem;font-weight:700;letter-spacing:-.01em}
.severity-badge{font-family:var(--mono);font-size:10px;letter-spacing:.08em;text-transform:uppercase;padding:3px 8px;border-radius:2px;white-space:nowrap}
.severity-badge.critical{background:rgba(230,57,70,.15);color:var(--accent2);border:1px solid rgba(230,57,70,.3)}
.severity-badge.high{background:rgba(230,126,34,.15);color:#e67e22;border:1px solid rgba(230,126,34,.3)}
.severity-badge.medium{background:rgba(243,156,18,.12);color:var(--warn);border:1px solid rgba(243,156,18,.3)}
.severity-badge.low{background:rgba(52,152,219,.12);color:#3498db;border:1px solid rgba(52,152,219,.3)}
.breach-desc{font-family:var(--mono);font-size:12px;line-height:1.6;color:var(--muted);margin-bottom:16px}
.card-meta{display:flex;flex-wrap:wrap;gap:20px;font-family:var(--mono);font-size:11px}
.meta-item{display:flex;flex-direction:column;gap:3px}
.meta-label{color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
.meta-value{color:var(--text)}
.fields-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:14px}
.field-tag{font-family:var(--mono);font-size:11px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:3px 9px;border-radius:2px}
.field-tag.sensitive{border-color:rgba(230,57,70,.3);color:var(--accent2)}
.safe-msg{text-align:center;padding:48px 24px;border:1px solid rgba(46,204,113,.2);background:rgba(46,204,113,.04);border-radius:4px}
.safe-icon{font-size:2.5rem;margin-bottom:12px}
.safe-msg h3{color:var(--safe);margin-bottom:6px}
.safe-msg p{font-family:var(--mono);font-size:12px;color:var(--muted)}
.error-msg{text-align:center;padding:32px;border:1px solid rgba(230,57,70,.2);background:rgba(230,57,70,.04);border-radius:4px;font-family:var(--mono);font-size:13px;color:var(--accent2)}
.loading{display:flex;align-items:center;justify-content:center;gap:10px;padding:40px;font-family:var(--mono);font-size:13px;color:var(--muted)}
.spinner{width:18px;height:18px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
footer{text-align:center;margin-top:72px;font-family:var(--mono);font-size:11px;color:var(--muted);letter-spacing:.04em;animation:fadeUp .6s .4s ease both}
footer a{color:var(--muted);text-decoration:none}
footer a:hover{color:var(--text)}
@keyframes fadeDown{from{opacity:0;transform:translateY(-16px)}to{opacity:1;transform:none}}
@keyframes fadeUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
@keyframes slideIn{from{opacity:0;transform:translateX(-8px)}to{opacity:1;transform:none}}
@media(max-width:600px){.search-prefix{display:none}button[type="submit"]{padding:0 18px;font-size:12px}.card-header{flex-direction:column}}
</style>
</head>
<body>
<div class="noise"></div>
<div class="grid-bg"></div>
<div class="glow"></div>
<div class="container">
  <header>
    <div class="badge">Data Breach Intelligence</div>
    <h1>LEAK<span>-API</span></h1>
    <p class="subtitle">Vérifiez si vos données ont été compromises</p>
  </header>
  <form class="search-wrap" id="searchForm">
    <div class="search-prefix">/search?q=</div>
    <input type="text" id="queryInput" placeholder="email, username ou domaine…" autocomplete="off" spellcheck="false"/>
    <button type="submit">Scan</button>
  </form>
  <div class="hints">
    <span class="hint" onclick="fill('john.doe@example.com')">john.doe@example.com</span>
    <span class="hint" onclick="fill('admin')">admin</span>
    <span class="hint" onclick="fill('example.com')">example.com</span>
  </div>
  <div id="results"></div>
  <footer><p>LEAK-API v2.0 &nbsp;·&nbsp; Mots de passe jamais exposés &nbsp;·&nbsp; <a href="/docs">API Docs</a></p></footer>
</div>
<script>
const SEVERITY_ORDER={critical:0,high:1,medium:2,low:3};
const SENSITIVE=['password','hash','encrypted_password','hashed_password','credit_card','ssn','bank_account'];
function fill(v){document.getElementById('queryInput').value=v;document.getElementById('queryInput').focus()}
function fmt(n){if(!n)return '?';if(n>=1e9)return(n/1e9).toFixed(1)+'B';if(n>=1e6)return(n/1e6).toFixed(1)+'M';if(n>=1e3)return(n/1e3).toFixed(1)+'K';return n.toString()}
function renderResults(data){
  const el=document.getElementById('results');
  const sorted=[...data.breaches].sort((a,b)=>(SEVERITY_ORDER[a.severity]||9)-(SEVERITY_ORDER[b.severity]||9));
  let html=`<div class="status-bar"><span>Requête : <span class="count">${data.query}</span></span><span class="sep">|</span><span><span class="count">${data.breach_count}</span> breach${data.breach_count>1?'es':''} trouvé${data.breach_count>1?'s':''}</span><span class="sep">|</span><span>${data.meta?.execution_time_ms??'—'} ms</span></div>`;
  for(const b of sorted){
    const fields=b.compromised_fields.map(f=>`<span class="field-tag${SENSITIVE.includes(f)?' sensitive':''}">${f}</span>`).join('');
    html+=`<div class="breach-card ${b.severity}"><div class="card-header"><span class="breach-name">${b.breach_name}</span><span class="severity-badge ${b.severity}">${b.severity}</span></div><p class="breach-desc">${b.description}</p><div class="card-meta"><div class="meta-item"><span class="meta-label">Date</span><span class="meta-value">${b.breach_date}</span></div><div class="meta-item"><span class="meta-label">Comptes affectés</span><span class="meta-value">${fmt(b.affected_accounts)}</span></div><div class="meta-item"><span class="meta-label">Vérifié</span><span class="meta-value">${b.verified?'✓ Oui':'✗ Non'}</span></div></div><div class="fields-list">${fields}</div></div>`;
  }
  el.innerHTML=html;
}
function renderSafe(q){document.getElementById('results').innerHTML=`<div class="safe-msg"><div class="safe-icon">✓</div><h3>Aucun breach détecté</h3><p>« ${q} » n'apparaît dans aucune base connue.</p></div>`}
function renderError(msg){document.getElementById('results').innerHTML=`<div class="error-msg">⚠ ${msg}</div>`}
function renderLoading(){document.getElementById('results').innerHTML=`<div class="loading"><div class="spinner"></div>Analyse en cours…</div>`}
document.getElementById('searchForm').addEventListener('submit',async(e)=>{
  e.preventDefault();
  const q=document.getElementById('queryInput').value.trim();
  if(!q)return;
  renderLoading();
  try{
    const res=await fetch(`/search?q=${encodeURIComponent(q)}`);
    const data=await res.json();
    if(res.status===404)return renderSafe(q);
    if(!res.ok)return renderError(data.detail?.detail||'Erreur serveur');
    renderResults(data);
  }catch{renderError("Impossible de contacter l'API.")}
});
const p=new URLSearchParams(window.location.search);
if(p.get('q')){document.getElementById('queryInput').value=p.get('q');document.getElementById('searchForm').dispatchEvent(new Event('submit'))}
</script>
</body>
</html>"""
