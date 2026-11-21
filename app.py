import csv
import hashlib
import html as html_lib
import io
import json
import math
import re
import socket
import ssl
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote_plus, urlparse

import cv2
from fpdf import FPDF
import numpy as np
from PIL import Image, ImageChops, ImageEnhance, ImageOps
from PIL.ExifTags import GPSTAGS, TAGS
import requests
import streamlit as st

try:
  import pytesseract  # type: ignore

  HAS_PYTESSERACT = True
except ImportError:
  pytesseract = None
  HAS_PYTESSERACT = False

st.set_page_config(
    page_title="OSINT Shield Ultimate",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ==========================================
# CUSTOM CSS: TEMA CYBER-SLATE & SIDEBAR MODERN
# ==========================================
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }
    code, pre {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Latar belakang utama */
    .stApp {
        background-color: #090d16;
        color: #e2e8f0;
    }

    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 3rem;
        max-width: 1240px;
    }

    /* Styling Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #0d1320;
        border-right: 1px solid rgba(16, 185, 129, 0.18);
    }
    section[data-testid="stSidebar"] .block-container {
        padding-top: 1.2rem;
    }

    .sidebar-brand {
        background: linear-gradient(135deg, rgba(16, 185, 129, 0.14), rgba(6, 182, 212, 0.08));
        border: 1px solid rgba(16, 185, 129, 0.3);
        border-radius: 12px;
        padding: 0.95rem 1rem;
        margin-bottom: 1rem;
    }
    .sidebar-brand-title {
        font-size: 1.2rem;
        font-weight: 700;
        color: #f8fafc;
        margin: 0;
        letter-spacing: -0.01em;
    }
    .sidebar-brand-sub {
        font-size: 0.78rem;
        color: #6ee7b7;
        margin: 0.15rem 0 0 0;
    }

    .nav-section-label {
        font-size: 0.72rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #64748b;
        margin: 0.9rem 0 0.35rem 0.2rem;
    }

    /* Styling tombol navigasi sidebar */
    section[data-testid="stSidebar"] button[kind="secondary"] {
        background-color: transparent;
        border: 1px solid transparent;
        color: #cbd5e1;
        text-align: left;
        justify-content: flex-start;
        padding: 0.5rem 0.75rem;
        border-radius: 9px;
        font-weight: 500;
        font-size: 0.88rem;
        transition: all 0.18s ease;
    }
    section[data-testid="stSidebar"] button[kind="secondary"]:hover {
        background-color: rgba(16, 185, 129, 0.1);
        border-color: rgba(16, 185, 129, 0.25);
        color: #ffffff;
    }
    section[data-testid="stSidebar"] button[kind="primary"] {
        background: linear-gradient(90deg, rgba(16, 185, 129, 0.22), rgba(6, 182, 212, 0.18));
        border: 1px solid rgba(16, 185, 129, 0.55);
        color: #6ee7b7;
        text-align: left;
        justify-content: flex-start;
        padding: 0.5rem 0.75rem;
        border-radius: 9px;
        font-weight: 600;
        font-size: 0.88rem;
        box-shadow: 0 2px 10px rgba(16, 185, 129, 0.12);
    }

    /* Hero Banner di Area Utama */
    .hero-banner {
        background: linear-gradient(135deg, #0f172a 0%, #111c33 55%, #0b292e 100%);
        border: 1px solid rgba(16, 185, 129, 0.28);
        border-left: 4px solid #10b981;
        border-radius: 14px;
        padding: 1.45rem 1.8rem;
        margin-bottom: 1.5rem;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.28);
    }
    .hero-badge {
        display: inline-block;
        background: rgba(16, 185, 129, 0.15);
        color: #34d399;
        border: 1px solid rgba(16, 185, 129, 0.35);
        font-size: 0.74rem;
        font-weight: 600;
        padding: 0.2rem 0.7rem;
        border-radius: 999px;
        margin-bottom: 0.55rem;
        letter-spacing: 0.05em;
    }
    .hero-title {
        font-size: 1.7rem;
        font-weight: 700;
        margin: 0 0 0.35rem 0;
        color: #f8fafc;
    }
    .hero-subtitle {
        font-size: 0.94rem;
        color: #94a3b8;
        margin: 0;
        line-height: 1.5;
    }

    /* Kartu Informasi & Metrik */
    .info-card {
        background: rgba(15, 23, 42, 0.75);
        border: 1px solid rgba(148, 163, 184, 0.18);
        border-radius: 12px;
        padding: 1.1rem 1.25rem;
        margin-bottom: 0.9rem;
        line-height: 1.65;
    }
    div[data-testid="stMetric"] {
        background: rgba(15, 23, 42, 0.8);
        border: 1px solid rgba(16, 185, 129, 0.2);
        border-radius: 12px;
        padding: 0.85rem 1.1rem;
    }
    div[data-testid="stMetricLabel"] {
        color: #94a3b8 !important;
        font-size: 0.82rem !important;
    }
    div[data-testid="stMetricValue"] {
        color: #f8fafc !important;
        font-size: 1.35rem !important;
    }

    /* Tombol Aksi Utama */
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        color: #ffffff;
        border: none;
        border-radius: 9px;
        font-weight: 600;
        padding: 0.55rem 1.2rem;
        transition: all 0.2s ease;
    }
    .stButton > button[kind="primary"]:hover {
        background: linear-gradient(135deg, #34d399 0%, #10b981 100%);
        box-shadow: 0 4px 14px rgba(16, 185, 129, 0.35);
    }

    /* Tab Styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 6px;
        background-color: rgba(15, 23, 42, 0.6);
        padding: 0.35rem;
        border-radius: 11px;
        border: 1px solid rgba(148, 163, 184, 0.15);
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        padding: 0.45rem 0.9rem;
        color: #94a3b8;
        font-weight: 500;
    }
    .stTabs [aria-selected="true"] {
        background-color: rgba(16, 185, 129, 0.18) !important;
        color: #6ee7b7 !important;
        font-weight: 600 !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def render_hero(badge: str, title: str, subtitle: str) -> None:
  st.markdown(
      f"""
      <div class="hero-banner">
          <div class="hero-badge">{badge}</div>
          <h1 class="hero-title">{title}</h1>
          <p class="hero-subtitle">{subtitle}</p>
      </div>
      """,
      unsafe_allow_html=True,
  )


# ==========================================
# FUNGSI BANTU UMUM & HASHING
# ==========================================
def compute_hashes(file_bytes: bytes) -> Dict[str, str]:
  return {
      "md5": hashlib.md5(file_bytes).hexdigest(),
      "sha1": hashlib.sha1(file_bytes).hexdigest(),
      "sha256": hashlib.sha256(file_bytes).hexdigest(),
  }


def rational_to_float(value: Any) -> Optional[float]:
  try:
    if hasattr(value, "numerator") and hasattr(value, "denominator"):
      if value.denominator == 0:
        return None
      return float(value.numerator) / float(value.denominator)
    if isinstance(value, tuple) and len(value) == 2:
      num, den = value
      if den == 0:
        return None
      return float(num) / float(den)
    return float(value)
  except (TypeError, ValueError, ZeroDivisionError):
    return None


def convert_gps_to_decimal(
    gps_info: Dict[str, Any],
) -> Optional[Tuple[float, float]]:
  lat = gps_info.get("GPSLatitude")
  lat_ref = gps_info.get("GPSLatitudeRef")
  lon = gps_info.get("GPSLongitude")
  lon_ref = gps_info.get("GPSLongitudeRef")

  if not (lat and lat_ref and lon and lon_ref):
    return None

  try:
    lat_deg = rational_to_float(lat[0])
    lat_min = rational_to_float(lat[1])
    lat_sec = rational_to_float(lat[2])
    lon_deg = rational_to_float(lon[0])
    lon_min = rational_to_float(lon[1])
    lon_sec = rational_to_float(lon[2])

    if None in (lat_deg, lat_min, lat_sec, lon_deg, lon_min, lon_sec):
      return None

    decimal_lat = lat_deg + (lat_min / 60.0) + (lat_sec / 3600.0)
    if str(lat_ref).strip().upper() in ("S", "SOUTH"):
      decimal_lat = -decimal_lat

    decimal_lon = lon_deg + (lon_min / 60.0) + (lon_sec / 3600.0)
    if str(lon_ref).strip().upper() in ("W", "WEST"):
      decimal_lon = -decimal_lon

    return round(decimal_lat, 6), round(decimal_lon, 6)
  except (IndexError, TypeError):
    return None


def serialize_value(val: Any) -> Any:
  if isinstance(val, bytes):
    try:
      decoded = val.decode("utf-8", errors="replace").strip("\x00").strip()
      return decoded if decoded else f"<{len(val)} bytes>"
    except Exception:
      return f"<{len(val)} bytes>"
  if hasattr(val, "numerator") and hasattr(val, "denominator"):
    num = int(val.numerator)
    den = int(val.denominator)
    return str(num) if den == 1 else f"{num}/{den} ({round(num / den, 4)})"
  if isinstance(val, (tuple, list)):
    return [serialize_value(item) for item in val]
  if isinstance(val, dict):
    return {str(k): serialize_value(v) for k, v in val.items()}
  return str(val)


def extract_exif_data(
    img: Image.Image,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
  general_exif: Dict[str, Any] = {}
  gps_parsed: Dict[str, Any] = {}

  exif_obj = img.getexif()
  if not exif_obj:
    return general_exif, gps_parsed

  for tag_id, raw_val in exif_obj.items():
    tag_name = TAGS.get(tag_id, f"UnknownTag_{tag_id}")
    if tag_name != "GPSInfo":
      general_exif[tag_name] = serialize_value(raw_val)

  try:
    gps_ifd = exif_obj.get_ifd(0x8825)
  except Exception:
    gps_ifd = None

  if gps_ifd:
    for gps_tag_id, gps_val in gps_ifd.items():
      gps_tag_name = GPSTAGS.get(gps_tag_id, f"GPSTag_{gps_tag_id}")
      gps_parsed[gps_tag_name] = gps_val

  return general_exif, gps_parsed


def extract_deep_metadata(
    img: Image.Image, file_bytes: bytes, min_len: int = 5, limit: int = 120
) -> Dict[str, Any]:
  pil_info: Dict[str, Any] = {}
  if img.info:
    for k, v in img.info.items():
      if k != "exif":
        pil_info[str(k)] = serialize_value(v)

  text_blob = file_bytes.decode("latin-1", errors="ignore")
  xmp_matches = re.findall(
      r"<(?:x:xmpmeta|rdf:RDF)[\s\S]*?</(?:x:xmpmeta|rdf:RDF)>", text_blob
  )
  xmp_snippets = [m.strip()[:2000] for m in xmp_matches[:5]]

  pattern = re.compile(rf"[ -~]{{{min_len},}}")
  raw_strings = pattern.findall(text_blob)
  unique_strings: List[str] = []
  seen = set()
  for s in raw_strings:
    cleaned = s.strip()
    if len(cleaned) >= min_len and cleaned not in seen:
      seen.add(cleaned)
      unique_strings.append(cleaned)
      if len(unique_strings) >= limit:
        break

  return {
      "pil_info": pil_info,
      "xmp_snippets": xmp_snippets,
      "strings": unique_strings,
  }


def perform_ela(
    img: Image.Image, quality: int = 90, scale: int = 15
) -> Image.Image:
  rgb_img = img.convert("RGB")
  buffer = io.BytesIO()
  rgb_img.save(buffer, format="JPEG", quality=quality)
  buffer.seek(0)
  recompressed = Image.open(buffer).convert("RGB")

  diff = ImageChops.difference(rgb_img, recompressed)
  extrema = diff.getextrema()
  max_diff = max(channel[1] for channel in extrema) if extrema else 1
  if max_diff == 0:
    max_diff = 1

  enhancement_factor = min(max((255.0 / max_diff) * (scale / 15.0), 1.0), 50.0)
  return ImageEnhance.Brightness(diff).enhance(enhancement_factor)


def calculate_solar_position(
    lat_deg: float, lon_deg: float, dt_utc: datetime
) -> Dict[str, float]:
  day_of_year = dt_utc.timetuple().tm_yday
  utc_hours = dt_utc.hour + dt_utc.minute / 60.0 + dt_utc.second / 3600.0
  declination_rad = math.radians(23.44) * math.sin(
      math.radians((360.0 / 365.0) * (day_of_year - 81))
  )
  b_rad = math.radians((360.0 / 365.0) * (day_of_year - 81))
  eot_min = (
      9.87 * math.sin(2 * b_rad)
      - 7.53 * math.cos(b_rad)
      - 1.5 * math.sin(b_rad)
  )
  solar_time_hr = (utc_hours + (lon_deg / 15.0) + (eot_min / 60.0)) % 24.0
  hour_angle_rad = math.radians(15.0 * (solar_time_hr - 12.0))
  lat_rad = math.radians(lat_deg)

  sin_alt = math.sin(lat_rad) * math.sin(declination_rad) + math.cos(
      lat_rad
  ) * math.cos(declination_rad) * math.cos(hour_angle_rad)
  sin_alt = max(-1.0, min(1.0, sin_alt))
  elevation_deg = math.degrees(math.asin(sin_alt))

  cos_alt = math.cos(math.asin(sin_alt))
  if abs(cos_alt) < 1e-6:
    azimuth_deg = 180.0
  else:
    cos_az = (math.sin(declination_rad) - math.sin(lat_rad) * sin_alt) / (
        math.cos(lat_rad) * cos_alt
    )
    cos_az = max(-1.0, min(1.0, cos_az))
    az_deg = math.degrees(math.acos(cos_az))
    azimuth_deg = (360.0 - az_deg) if hour_angle_rad > 0 else az_deg

  shadow_direction_deg = (azimuth_deg + 180.0) % 360.0
  return {
      "azimuth_deg": round(azimuth_deg, 2),
      "elevation_deg": round(elevation_deg, 2),
      "shadow_direction_deg": round(shadow_direction_deg, 2),
  }


def strip_metadata_to_jpeg(img: Image.Image, quality: int = 92) -> bytes:
  clean_img = ImageOps.exif_transpose(img).convert("RGB")
  out = io.BytesIO()
  clean_img.save(out, format="JPEG", quality=quality, optimize=True)
  return out.getvalue()


def build_csv_report(rows: List[Dict[str, str]]) -> str:
  buf = io.StringIO()
  writer = csv.DictWriter(buf, fieldnames=["Tag EXIF", "Nilai"])
  writer.writeheader()
  for r in rows:
    writer.writerow(r)
  return buf.getvalue()


# ==========================================
# FUNGSI BANTU MODUL INSTAGRAM OSINT
# ==========================================
def clean_instagram_username(raw_input: str) -> str:
  val = raw_input.strip()
  if "instagram.com/" in val:
    parsed = urlparse(val if val.startswith("http") else "https://" + val)
    parts = [p for p in parsed.path.split("/") if p]
    if parts:
      val = parts[0]
  return val.lstrip("@").strip()


def inspect_instagram_public(username: str) -> Dict[str, Any]:
  clean_u = clean_instagram_username(username)
  profile_url = f"https://www.instagram.com/{clean_u}/"
  result: Dict[str, Any] = {
      "username": clean_u,
      "profile_url": profile_url,
      "status": "Tidak Diketahui",
      "title": "",
      "description": "",
      "og_image": "",
      "risk_flags": [],
  }

  if re.search(r"[._]{3,}", clean_u):
    result["risk_flags"].append(
        "Username memakai banyak titik/garis bawah berulang (pola umum akun"
        " tiruan/impersonator)."
    )
  if re.search(r"\d{4,}$", clean_u):
    result["risk_flags"].append(
        "Username diakhiri banyak angka acak (sering dipakai akun bot atau"
        " akun sekali pakai)."
    )
  scam_keywords = (
      "giveaway",
      "official_id",
      "promo_",
      "lelang",
      "tebusmurah",
      "dana_kaget",
      "cs_resmi",
  )
  if any(kw in clean_u.lower() for kw in scam_keywords):
    result["risk_flags"].append(
        "Username mengandung kata kunci yang sering disalahgunakan untuk modus"
        " penipuan/giveaway palsu."
    )

  headers = {
      "User-Agent": (
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
          " (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
      ),
      "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
  }

  try:
    resp = requests.get(
        profile_url, headers=headers, timeout=8, allow_redirects=True
    )
    if resp.status_code == 404:
      result["status"] = "Akun Tidak Ditemukan (404)"
      return result

    page_html = resp.text
    og_title_m = re.search(
        r'<meta\s+property="og:title"\s+content="([^"]*)"', page_html
    )
    og_desc_m = re.search(
        r'<meta\s+property="og:description"\s+content="([^"]*)"', page_html
    )
    og_img_m = re.search(
        r'<meta\s+property="og:image"\s+content="([^"]*)"', page_html
    )

    if og_title_m:
      result["title"] = html_lib.unescape(og_title_m.group(1))
    if og_desc_m:
      result["description"] = html_lib.unescape(og_desc_m.group(1))
    if og_img_m:
      result["og_image"] = html_lib.unescape(og_img_m.group(1))

    if result["title"] or result["description"]:
      result["status"] = "Metadata Publik Terbaca"
      desc_lower = result["description"].lower()
      if "0 posts" in desc_lower or "0 kiriman" in desc_lower:
        result["risk_flags"].append(
            "Akun memiliki 0 kiriman (hati-hati jika mengaku sebagai toko"
            " terpercaya atau akun lama)."
        )
      if any(
          w in desc_lower
          for w in ("wa.me", "whatsapp", "telegram", "t.me", "bit.ly")
      ):
        result["risk_flags"].append(
            "Deskripsi mengarahkan kontak keluar Instagram (WhatsApp/Telegram/"
            "shortlink) — selalu verifikasi nomor tujuan sebelum transaksi."
        )
    else:
      result["status"] = (
          f"Dibatasi Login Wall Instagram (HTTP {resp.status_code})"
      )
  except Exception as exc:
    result["status"] = f"Gagal mengakses halaman publik ({exc})"

  return result


def extract_usernames_from_ig_export(raw_bytes: bytes) -> Set[str]:
  usernames: Set[str] = set()
  text = raw_bytes.decode("utf-8", errors="ignore")

  try:
    data = json.loads(text)

    def walk_json(node: Any) -> None:
      if isinstance(node, dict):
        if "string_list_data" in node and isinstance(
            node["string_list_data"], list
        ):
          for entry in node["string_list_data"]:
            if isinstance(entry, dict) and entry.get("value"):
              usernames.add(str(entry["value"]).strip().lower())
        for v in node.values():
          walk_json(v)
      elif isinstance(node, list):
        for item in node:
          walk_json(item)

    walk_json(data)
  except Exception:
    pass

  if not usernames:
    matches = re.findall(
        r'href="https?://(?:www\.)?instagram\.com/([a-zA-Z0-9._]+)/?"', text
    )
    for m in matches:
      if m.lower() not in ("explore", "accounts", "about", "legal", "privacy"):
        usernames.add(m.lower())

  return usernames


# ==========================================
# FUNGSI BANTU QR CODE DECODER
# ==========================================
def decode_qr_codes(pil_img: Image.Image) -> List[str]:
  rgb = np.array(pil_img.convert("RGB"))
  bgr = cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)
  detector = cv2.QRCodeDetector()
  decoded_items: List[str] = []

  try:
    retval, decoded_info, _, _ = detector.detectAndDecodeMulti(bgr)
    if retval and decoded_info:
      for item in decoded_info:
        if item and item.strip():
          decoded_items.append(item.strip())
  except Exception:
    pass

  if not decoded_items:
    data, _, _ = detector.detectAndDecode(bgr)
    if data and data.strip():
      decoded_items.append(data.strip())

  return list(dict.fromkeys(decoded_items))


# ==========================================
# FUNGSI BANTU APK & FILE INSPECTOR
# ==========================================
DANGEROUS_APK_PERMS = {
    "READ_SMS": "Membaca SMS masuk (berisiko mencuri kode OTP perbankan).",
    "RECEIVE_SMS": "Mencegat SMS masuk secara diam-diam.",
    "SEND_SMS": "Mengirim SMS berbayar atau menyebarkan link penipuan ke kontak.",
    "READ_CONTACTS": "Mencuri seluruh daftar nomor telepon keluarga/kerabat di HP.",
    "BIND_ACCESSIBILITY_SERVICE": "Mengambil alih kontrol layar & membaca ketikan PIN/password.",
    "SYSTEM_ALERT_WINDOW": "Menampilkan layar palsu (overlay) di atas aplikasi mobile banking.",
    "REQUEST_INSTALL_PACKAGES": "Menginstal aplikasi berbahaya tambahan tanpa sepengetahuan korban.",
    "READ_CALL_LOG": "Membaca riwayat panggilan telepon.",
    "RECORD_AUDIO": "Merekam suara melalui mikrofon HP.",
    "ACCESS_FINE_LOCATION": "Melacak lokasi GPS secara presisi.",
}


def inspect_suspicious_file(file_name: str, file_bytes: bytes) -> Dict[str, Any]:
  hashes = compute_hashes(file_bytes)
  info: Dict[str, Any] = {
      "file_name": file_name,
      "size_kb": round(len(file_bytes) / 1024, 2),
      "hashes": hashes,
      "is_zip_or_apk": zipfile.is_zipfile(io.BytesIO(file_bytes)),
      "archive_entries": [],
      "detected_permissions": [],
      "embedded_urls": [],
  }

  text_blob = file_bytes.decode("latin-1", errors="ignore")
  urls = re.findall(r"https?://[^\s\"'<>\\\x00-\x1f]{6,120}", text_blob)
  info["embedded_urls"] = list(dict.fromkeys(urls))[:30]

  if info["is_zip_or_apk"]:
    try:
      with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zf:
        entries = zf.namelist()
        info["archive_entries"] = entries[:40]
        if "AndroidManifest.xml" in entries:
          manifest_bytes = zf.read("AndroidManifest.xml")
          m_ascii = manifest_bytes.decode("latin-1", errors="ignore")
          m_utf16 = manifest_bytes.decode("utf-16le", errors="ignore")
          combined_manifest = m_ascii + "\n" + m_utf16

          for perm_key, desc in DANGEROUS_APK_PERMS.items():
            if perm_key in combined_manifest:
              info["detected_permissions"].append({
                  "permission": f"android.permission.{perm_key}",
                  "risk_description": desc,
              })
    except Exception as exc:
      info["zip_error"] = str(exc)

  return info


# ==========================================
# FUNGSI BANTU LINK & PHISHING INSPECTOR
# ==========================================
def inspect_url_safety(raw_url: str) -> Dict[str, Any]:
  url = raw_url.strip()
  if not url.startswith(("http://", "https://")):
    url = "https://" + url

  parsed = urlparse(url)
  domain = parsed.hostname or ""
  result: Dict[str, Any] = {
      "input_url": url,
      "domain": domain,
      "redirect_chain": [],
      "final_url": url,
      "ip_addresses": [],
      "dns_records": {},
      "ssl_info": {},
      "risk_flags": [],
  }

  suspicious_tlds = (
      ".xyz",
      ".top",
      ".buzz",
      ".click",
      ".apk",
      ".vip",
      ".icu",
      ".loan",
  )
  if any(domain.endswith(tld) for tld in suspicious_tlds):
    result["risk_flags"].append(
        f"Domain menggunakan ekstensi TLD berisiko tinggi ({domain})."
    )
  if "@" in url:
    result["risk_flags"].append(
        "URL mengandung karakter '@' yang sering dipakai untuk menyamarkan tujuan asli."
    )
  if domain.count("-") >= 3:
    result["risk_flags"].append(
        "Domain memiliki banyak tanda hubung (-), pola umum situs tiruan/phishing."
    )
  if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
    result["risk_flags"].append(
        "Tautan mengarah langsung ke alamat IP mentah, bukan nama domain resmi."
    )

  try:
    resp = requests.head(
        url,
        allow_redirects=True,
        timeout=8,
        headers={"User-Agent": "OSINT-Shield-Inspector/2.0"},
    )
    chain = [h.url for h in resp.history] + [resp.url]
    result["redirect_chain"] = chain
    result["final_url"] = resp.url
    final_domain = urlparse(resp.url).hostname or domain
    if final_domain != domain:
      result["risk_flags"].append(
          f"Tautan dialihkan (redirect) ke domain berbeda: `{final_domain}`"
      )
      domain = final_domain
      result["domain"] = domain
  except Exception as exc:
    result["redirect_error"] = str(exc)

  if domain:
    try:
      ips = list({info[4][0] for info in socket.getaddrinfo(domain, None)})
      result["ip_addresses"] = ips
    except Exception:
      pass

    for rtype in ("A", "MX", "NS", "TXT"):
      try:
        dns_resp = requests.get(
            f"https://dns.google/resolve?name={domain}&type={rtype}",
            timeout=5,
        ).json()
        answers = [ans.get("data") for ans in dns_resp.get("Answer", [])]
        if answers:
          result["dns_records"][rtype] = answers
      except Exception:
        pass

    try:
      ctx = ssl.create_default_context()
      with socket.create_connection((domain, 443), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
          cert = ssock.getpeercert()
          issuer = dict(x[0] for x in cert.get("issuer", []))
          result["ssl_info"] = {
              "issuer": issuer.get("organizationName", "Tidak diketahui"),
              "valid_from": cert.get("notBefore", "-"),
              "valid_until": cert.get("notAfter", "-"),
          }
    except Exception as exc:
      result["ssl_info"] = {
          "error": f"Tidak ada SSL valid / gagal koneksi HTTPS ({exc})"
      }
      result["risk_flags"].append(
          "Situs tidak memiliki sertifikat SSL/HTTPS yang valid."
      )

  return result


# ==========================================
# FUNGSI BANTU EMAIL HEADER ANALYZER
# ==========================================
def analyze_email_header(raw_header: str) -> Dict[str, Any]:
  lines = raw_header.splitlines()
  headers_map: Dict[str, List[str]] = {}
  current_key = ""
  for line in lines:
    if line.startswith((" ", "\t")) and current_key:
      headers_map[current_key][-1] += " " + line.strip()
    elif ":" in line:
      k, v = line.split(":", 1)
      current_key = k.strip().lower()
      headers_map.setdefault(current_key, []).append(v.strip())

  from_val = headers_map.get("from", ["-"])[0]
  reply_to_val = headers_map.get("reply-to", ["-"])[0]
  return_path = headers_map.get("return-path", ["-"])[0]
  subject_val = headers_map.get("subject", ["-"])[0]
  auth_results = " | ".join(headers_map.get("authentication-results", []))

  warnings = []
  from_domain_match = re.search(r"@([a-zA-Z0-9.-]+)", from_val)
  reply_domain_match = re.search(r"@([a-zA-Z0-9.-]+)", reply_to_val)
  if from_domain_match and reply_domain_match:
    if from_domain_match.group(1).lower() != reply_domain_match.group(1).lower():
      warnings.append(
          f"Alamat 'From' ({from_domain_match.group(1)}) berbeda dengan 'Reply-To' ({reply_domain_match.group(1)}) — indikasi kuat email spoofing/penipuan!"
      )

  auth_lower = auth_results.lower()
  spf_status = (
      "PASS"
      if "spf=pass" in auth_lower
      else ("FAIL" if "spf=fail" in auth_lower else "Tidak Terdeteksi")
  )
  dkim_status = (
      "PASS"
      if "dkim=pass" in auth_lower
      else ("FAIL" if "dkim=fail" in auth_lower else "Tidak Terdeteksi")
  )
  dmarc_status = (
      "PASS"
      if "dmarc=pass" in auth_lower
      else ("FAIL" if "dmarc=fail" in auth_lower else "Tidak Terdeteksi")
  )

  if "FAIL" in (spf_status, dkim_status, dmarc_status):
    warnings.append(
        "Salah satu verifikasi keamanan email (SPF/DKIM/DMARC) GAGAL. Email ini kemungkinan besar dipalsukan."
    )

  received_hops = headers_map.get("received", [])
  ips_found = list(
      dict.fromkeys(
          re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "\n".join(received_hops))
      )
  )

  return {
      "subject": subject_val,
      "from": from_val,
      "reply_to": reply_to_val,
      "return_path": return_path,
      "spf": spf_status,
      "dkim": dkim_status,
      "dmarc": dmarc_status,
      "warnings": warnings,
      "server_ips": ips_found,
      "received_hops": received_hops,
  }


# ==========================================
# FUNGSI BANTU PASSWORD LEAK (K-ANONYMITY)
# ==========================================
def check_password_pwned(password: str) -> int:
  sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
  prefix, suffix = sha1_hash[:5], sha1_hash[5:]
  resp = requests.get(
      f"https://api.pwnedpasswords.com/range/{prefix}",
      timeout=8,
      headers={"User-Agent": "OSINT-Shield-Checker"},
  )
  resp.raise_for_status()
  for line in resp.text.splitlines():
    if ":" in line:
      h_suffix, count = line.split(":", 1)
      if h_suffix.strip() == suffix:
        return int(count.strip())
  return 0


# ==========================================
# FUNGSI BANTU USERNAME RECON
# ==========================================
PLATFORMS = {
    "GitHub": "https://github.com/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "TikTok": "https://www.tiktok.com/@{}",
    "X (Twitter)": "https://x.com/{}",
    "YouTube": "https://www.youtube.com/@{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "Pinterest": "https://www.pinterest.com/{}/",
    "Medium": "https://medium.com/@{}",
    "Telegram (t.me)": "https://t.me/{}",
    "Linktree": "https://linktr.ee/{}",
}


def check_username_public(username: str) -> List[Dict[str, str]]:
  clean_u = username.strip().lstrip("@")
  results = []
  headers = {
      "User-Agent": (
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
          " (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
      )
  }
  for name, template in PLATFORMS.items():
    target_url = template.format(clean_u)
    status_label = "Perlu Cek Manual"
    try:
      r = requests.get(
          target_url, headers=headers, timeout=5, allow_redirects=True
      )
      if r.status_code == 200:
        lower_text = r.text.lower()
        if "page not found" in lower_text or "user not found" in lower_text:
          status_label = "Tidak Ditemukan (404)"
        else:
          status_label = "Kemungkinan Ada (HTTP 200)"
      elif r.status_code == 404:
        status_label = "Tidak Ditemukan (404)"
      else:
        status_label = f"Terbatas / Anti-Bot (HTTP {r.status_code})"
    except Exception:
      status_label = "Timeout / Cek Manual"

    results.append({
        "Platform": name,
        "Status": status_label,
        "Tautan Profil": target_url,
    })
  return results


# ==========================================
# FUNGSI BANTU GENERATOR LAPORAN PDF
# ==========================================
def generate_case_pdf(
    case_title: str,
    investigator: str,
    victim_or_target: str,
    incident_date: str,
    chronology: str,
    digital_evidence: str,
) -> bytes:
  pdf = FPDF()
  pdf.add_page()
  pdf.set_auto_page_break(auto=True, margin=15)

  pdf.set_font("Helvetica", "B", 16)
  pdf.cell(
      0, 10, "LAPORAN DOKUMENTASI BUKTI DIGITAL (OSINT)", ln=True, align="C"
  )
  pdf.set_font("Helvetica", "", 10)
  pdf.cell(
      0,
      6,
      f"Dibuat via OSINT Shield pada {datetime.now().strftime('%Y-%m-%d %H:%M')}",
      ln=True,
      align="C",
  )
  pdf.ln(8)

  def add_field(label: str, value: str) -> None:
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, label, ln=True)
    pdf.set_font("Helvetica", "", 10)
    safe_val = value.encode("latin-1", errors="replace").decode("latin-1")
    pdf.multi_cell(0, 6, safe_val if safe_val.strip() else "-")
    pdf.ln(3)

  add_field("Judul Kasus / Laporan:", case_title)
  add_field("Pelapor / Peneliti:", investigator)
  add_field(
      "Entitas Terlapor (Nomor / Akun / Rekening / Link):", victim_or_target
  )
  add_field("Waktu Kejadian:", incident_date)
  add_field("Kronologi Singkat:", chronology)
  add_field(
      "Rincian Bukti Digital (Hash SHA-256 / IP / Metadata / URL):",
      digital_evidence,
  )

  return bytes(pdf.output())


# ==========================================
# NAVIGASI SIDEBAR MODERN
# ==========================================
MENU_GROUPS = {
    "Media Sosial & Identitas": [
        ("ig_osint", "📸  Investigasi Instagram"),
        ("username_osint", "👤  Pelacak Username"),
    ],
    "Forensik Visual & QR": [
        ("image_forensics", "🕵️  Forensik Gambar & EXIF"),
        ("qr_decoder", "📷  Bongkar QR / QRIS"),
    ],
    "Keamanan Link, File & Email": [
        ("link_checker", "🔗  Cek Link Phishing"),
        ("apk_inspector", "📦  Cek File .APK / Malware"),
        ("email_header", "📧  Analisis Header Email"),
    ],
    "Transaksi, Kebocoran & Laporan": [
        ("bank_dork", "💳  Cek Rekening & Dorking"),
        ("leak_checker", "🔐  Cek Kebocoran Sandi"),
        ("pdf_report", "📄  Buat Laporan Bukti PDF"),
    ],
}


def render_sidebar_nav() -> str:
  if "active_module" not in st.session_state:
    st.session_state["active_module"] = "ig_osint"

  with st.sidebar:
    st.markdown(
        """
        <div class="sidebar-brand">
            <div class="sidebar-brand-title">🛡️ OSINT Shield</div>
            <div class="sidebar-brand-sub">● Sistem Aktif · 10 Modul Siap</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    for group_name, items in MENU_GROUPS.items():
      st.markdown(
          f'<div class="nav-section-label">{group_name}</div>',
          unsafe_allow_html=True,
      )
      for mod_key, mod_label in items:
        is_active = st.session_state["active_module"] == mod_key
        if st.button(
            mod_label,
            key=f"nav_{mod_key}",
            type="primary" if is_active else "secondary",
            width="stretch",
        ):
          st.session_state["active_module"] = mod_key
          st.rerun()

    st.divider()
    st.caption(
        "Gunakan seluruh modul secara etis untuk verifikasi fakta dan"
        " perlindungan kerabat dari penipuan digital."
    )

  return st.session_state["active_module"]


# ==========================================
# ANTARMUKA UTAMA APLIKASI
# ==========================================
def main() -> None:
  active_mod = render_sidebar_nav()

  # ==========================================
  # MODUL INSTAGRAM OSINT
  # ==========================================
  if active_mod == "ig_osint":
    render_hero(
        "MODUL OSINT MEDIA SOSIAL",
        "📸 Investigasi & Verifikasi Profil Instagram",
        "Periksa metadata publik profil Instagram, deteksi pola akun toko palsu/penipu, lacak riwayat username, serta audit file ekspor resmi Instagram tanpa perlu login.",
    )

    ig_tab1, ig_tab2 = st.tabs([
        "🔍 Analisis Profil & Jejak Publik",
        "📂 Audit File Ekspor Instagram (Non-Followers)",
    ])

    with ig_tab1:
      ig_input = st.text_input(
          "Masukkan Username atau URL Profil Instagram:",
          placeholder="Contoh: toko_sepatu_murah123 atau https://www.instagram.com/username/",
      )
      if (
          st.button("🔎 Analisis Profil Instagram", type="primary")
          and ig_input.strip()
      ):
        with st.spinner("Memeriksa metadata publik & indikator risiko..."):
          ig_res = inspect_instagram_public(ig_input)

        uname = ig_res["username"]
        if ig_res["risk_flags"]:
          st.error("⚠️ **Ditemukan Indikator Kewaspadaan (Red Flags):**")
          for fl in ig_res["risk_flags"]:
            st.write(f"- {fl}")
        else:
          st.success(
              "✅ Tidak terdeteksi pola red-flag otomatis pada format username"
              " maupun bio publik yang terbaca."
          )

        col_ig1, col_ig2 = st.columns([1.3, 1], gap="large")
        with col_ig1:
          st.subheader("Ringkasan Metadata Publik")
          st.markdown(
              f"""
              <div class="info-card">
                  <b>Username:</b> <code>@{uname}</code><br>
                  <b>Status Akses:</b> {ig_res['status']}<br>
                  <b>Judul Profil:</b> {ig_res['title'] or '-'}<br>
                  <b>Deskripsi / Bio Publik:</b> {ig_res['description'] or 'Tidak tersedia (tertutup login wall)'}
              </div>
              """,
              unsafe_allow_html=True,
          )
          if ig_res["og_image"]:
            st.markdown(
                f"🖼️ **[Buka Tautan Foto Profil Publik]({ig_res['og_image']})** "
                "(Simpan gambarnya lalu cek keasliannya di modul **Forensik Gambar** atau **Google Lens**)."
            )

        with col_ig2:
          st.subheader("Tautan Riset & Jejak Digital")
          u_enc = quote_plus(f'"{uname}"')
          scam_ig_enc = quote_plus(
              f'"{uname}" (penipu OR penipuan OR scam OR hati-hati OR waspada)'
          )
          cache_enc = quote_plus(f"site:instagram.com/{uname}")
          st.markdown(
              f"* [Buka Profil Asli di Instagram]({ig_res['profile_url']})\n"
              f"* [Cek Laporan Penipuan Terkait @{uname}](https://www.google.com/search?q={scam_ig_enc})\n"
              f"* [Arsip Indeks Postingan di Google](https://www.google.com/search?q={cache_enc})\n"
              f"* [Jejak @{uname} di Platform Lain](https://www.google.com/search?q={u_enc})"
          )

    with ig_tab2:
      st.subheader("Audit Pengikut & Mengikuti (100% Aman Tanpa Password)")
      st.caption(
          "Unggah file `followers_1.json` (atau `.html`) dan `following.json`"
          " dari menu **Pusat Akun Meta > Informasi dan izin Anda > Unduh"
          " informasi Anda** untuk melihat akun yang tidak mengikuti balik."
      )
      f_col1, f_col2 = st.columns(2)
      with f_col1:
        followers_file = st.file_uploader(
            "Unggah file Followers (JSON/HTML)",
            type=["json", "html"],
            key="ig_flw",
        )
      with f_col2:
        following_file = st.file_uploader(
            "Unggah file Following (JSON/HTML)",
            type=["json", "html"],
            key="ig_flg",
        )

      if followers_file and following_file:
        flw_set = extract_usernames_from_ig_export(followers_file.getvalue())
        flg_set = extract_usernames_from_ig_export(following_file.getvalue())
        not_following_back = sorted(flg_set - flw_set)

        m1, m2, m3 = st.columns(3)
        m1.metric("Total Followers", len(flw_set))
        m2.metric("Total Following", len(flg_set))
        m3.metric("Tidak Follback", len(not_following_back))

        if not_following_back:
          rows_nfb = [
              {
                  "Username": u,
                  "Tautan Profil": f"https://www.instagram.com/{u}/",
              }
              for u in not_following_back
          ]
          st.dataframe(
              rows_nfb,
              width="stretch",
              hide_index=True,
              column_config={
                  "Tautan Profil": st.column_config.LinkColumn("Tautan Profil")
              },
          )
        else:
          st.info(
              "Semua akun yang diikuti sudah mengikuti balik (atau pastikan"
              " file ekspor yang diunggah sudah sesuai)."
          )

  # ==========================================
  # MODUL PELACAK USERNAME LINTAS PLATFORM
  # ==========================================
  elif active_mod == "username_osint":
    render_hero(
        "REKON IDENTITAS PUBLIK",
        "👤 Pelacak Jejak Username Lintas Platform",
        "Cek penggunaan username di berbagai platform media sosial untuk memverifikasi keaslian akun atau melacak akun tiruan.",
    )

    uname_input = st.text_input(
        "Masukkan Username (tanpa @):", placeholder="Contoh: budi_santoso99"
    )
    if st.button("🔎 Lacak Username", type="primary") and uname_input.strip():
      with st.spinner("Mengecek profil publik..."):
        rows = check_username_public(uname_input)
      st.dataframe(
          rows,
          width="stretch",
          hide_index=True,
          column_config={
              "Tautan Profil": st.column_config.LinkColumn("Tautan Profil")
          },
      )

  # ==========================================
  # MODUL FORENSIK GAMBAR & METADATA
  # ==========================================
  elif active_mod == "image_forensics":
    render_hero(
        "MODUL FORENSIK VISUAL",
        "🕵️ Forensik Gambar & Deep Metadata",
        "Periksa keaslian foto, bukti transfer editan (ELA), koordinat GPS, arah bayangan matahari, OCR, dan bersihkan metadata sebelum berbagi foto.",
    )

    uploaded_file = st.file_uploader(
        "Unggah file gambar untuk dianalisis",
        type=["jpg", "jpeg", "png", "webp", "tiff", "tif"],
    )

    if not uploaded_file:
      st.info("Unggah gambar terlebih dahulu untuk memulai analisis forensik.")
      return

    file_bytes = uploaded_file.getvalue()
    hashes = compute_hashes(file_bytes)
    file_size_kb = round(len(file_bytes) / 1024, 2)

    try:
      uploaded_file.seek(0)
      with Image.open(uploaded_file) as img:
        oriented_img = ImageOps.exif_transpose(img).copy()
        raw_img = img.copy()
        img_format = img.format or "Tidak diketahui"
        width, height = img.size
        general_exif, gps_raw = extract_exif_data(img)
        deep_meta = extract_deep_metadata(img, file_bytes)
    except Exception as exc:
      st.error(f"Gagal membaca gambar: {exc}")
      return

    coords = convert_gps_to_decimal(gps_raw) if gps_raw else None
    exif_rows_all = [
        {
            "Tag EXIF": k,
            "Nilai": (
                ", ".join(str(x) for x in v) if isinstance(v, list) else str(v)
            ),
        }
        for k, v in sorted(general_exif.items())
    ]

    report_payload = {
        "file_name": uploaded_file.name,
        "file_size_bytes": len(file_bytes),
        "format": img_format,
        "dimensions": {"width": width, "height": height},
        "hashes": hashes,
        "gps_decimal": {"lat": coords[0], "lon": coords[1]} if coords else None,
        "exif": general_exif,
        "deep_metadata": deep_meta,
    }

    t1, t2, t3, t4, t5 = st.tabs([
        "📋 Overview & EXIF",
        "🧬 Deep Metadata & Strings",
        "🔬 Cek Editan (ELA)",
        "🗺️ Peta, Matahari & Reverse Search",
        "🧹 OCR & Hapus Metadata",
    ])

    with t1:
      c1, c2 = st.columns([1, 1.35], gap="large")
      with c1:
        st.image(oriented_img, caption=uploaded_file.name, width="stretch")
      with c2:
        st.subheader("Ringkasan & Sidik Jari File")
        m_a, m_b, m_c = st.columns(3)
        m_a.metric("Format", img_format)
        m_b.metric("Resolusi", f"{width}×{height}")
        m_c.metric("Ukuran", f"{file_size_kb} KB")

        st.markdown(
            f"""
            <div class="info-card">
                <b>Nama File:</b> <code>{uploaded_file.name}</code><br>
                <b>MD5:</b> <code>{hashes['md5']}</code><br>
                <b>SHA-256:</b> <code>{hashes['sha256']}</code>
            </div>
            """,
            unsafe_allow_html=True,
        )

        b1, b2 = st.columns(2)
        with b1:
          st.download_button(
              "⬇️ Unduh Laporan JSON",
              data=json.dumps(report_payload, indent=2, ensure_ascii=False),
              file_name=f"{uploaded_file.name}_report.json",
              mime="application/json",
              width="stretch",
          )
        with b2:
          st.download_button(
              "⬇️ Unduh EXIF CSV",
              data=build_csv_report(exif_rows_all),
              file_name=f"{uploaded_file.name}_exif.csv",
              mime="text/csv",
              width="stretch",
          )

      st.divider()
      q_exif = (
          st.text_input(
              "Filter Tag EXIF",
              placeholder="Cari Make, Model, Software, DateTime...",
          )
          .strip()
          .lower()
      )
      filtered = [
          r
          for r in exif_rows_all
          if not q_exif
          or q_exif in r["Tag EXIF"].lower()
          or q_exif in r["Nilai"].lower()
      ]
      if filtered:
        st.dataframe(filtered, width="stretch", hide_index=True)
      else:
        st.info(
            "Tidak ada metadata EXIF standar yang ditemukan pada gambar ini."
        )

    with t2:
      st.subheader("Jejak Software & Strings Tersembunyi")
      if deep_meta["pil_info"]:
        st.json(deep_meta["pil_info"])
      if deep_meta["xmp_snippets"]:
        for idx, snip in enumerate(deep_meta["xmp_snippets"], 1):
          with st.expander(f"Data XMP #{idx}"):
            st.code(snip, language="xml")
      str_q = (
          st.text_input(
              "Filter strings biner",
              placeholder="Contoh: Photoshop, Canva, PixelLab",
          )
          .strip()
          .lower()
      )
      matched_s = [
          s
          for s in deep_meta["strings"]
          if not str_q or str_q in s.lower()
      ]
      if matched_s:
        st.code("\n".join(matched_s), language="text")
      else:
        st.info("Tidak ada string tersembunyi yang cocok.")

    with t3:
      st.subheader("Error Level Analysis (Deteksi Editan)")
      st.caption(
          "Area dengan kecerahan kontras mencolok dibanding sekitarnya patut"
          " dicurigai sebagai hasil tempelan/editan (misalnya nominal pada"
          " bukti transfer palsu)."
      )
      ec1, ec2 = st.columns(2)
      with ec1:
        q_ela = st.slider("Kualitas Rekompresi", 50, 98, 90)
      with ec2:
        s_ela = st.slider("Intensitas Kontras", 5, 40, 15)
      ela_img = perform_ela(oriented_img, quality=q_ela, scale=s_ela)
      vc1, vc2 = st.columns(2, gap="large")
      with vc1:
        st.markdown("**Gambar Asli**")
        st.image(oriented_img, width="stretch")
      with vc2:
        st.markdown("**Hasil Analisis ELA**")
        st.image(ela_img, width="stretch")

    with t4:
      st.subheader("Geolokasi & Verifikasi Waktu Bayangan")
      lat_def = coords[0] if coords else -6.8898
      lon_def = coords[1] if coords else 109.6746
      if coords:
        st.success(
            f"Koordinat GPS ditemukan di EXIF: **{coords[0]}, {coords[1]}**"
        )
      cc1, cc2 = st.columns(2)
      with cc1:
        lat_in = st.number_input("Latitude", value=float(lat_def), format="%.6f")
      with cc2:
        lon_in = st.number_input(
            "Longitude", value=float(lon_def), format="%.6f"
        )
      st.map({"lat": [lat_in], "lon": [lon_in]})
      st.markdown(
          f"[Buka Google Maps](https://www.google.com/maps?q={lat_in},{lon_in}) | "
          f"[Google Street View](https://www.google.com/maps/@?api=1&map_action=pano&viewpoint={lat_in},{lon_in}) | "
          f"[SunCalc.org](https://www.suncalc.org/#/{lat_in},{lon_in},16/2026.11.21/08:19/1/3)"
      )

      st.divider()
      sc1, sc2 = st.columns(2)
      with sc1:
        d_val = st.date_input(
            "Tanggal (UTC)", value=datetime.now(timezone.utc).date()
        )
      with sc2:
        t_val = st.time_input(
            "Jam (UTC)",
            value=datetime.now(timezone.utc).time().replace(microsecond=0),
        )
      solar = calculate_solar_position(
          lat_in, lon_in, datetime.combine(d_val, t_val, tzinfo=timezone.utc)
      )
      m1, m2, m3 = st.columns(3)
      m1.metric("Azimuth Matahari", f"{solar['azimuth_deg']}°")
      m2.metric("Elevasi Matahari", f"{solar['elevation_deg']}°")
      m3.metric("Arah Bayangan Benda", f"{solar['shadow_direction_deg']}°")

      st.divider()
      st.subheader("Reverse Image Search")
      st.markdown(
          "* [Cari di Google Lens](https://lens.google.com/)\n"
          "* [Cari di Yandex Images](https://yandex.com/images/)\n"
