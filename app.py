import csv
import hashlib
import io
import json
import math
import re
import socket
import ssl
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
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
# CUSTOM CSS UNTUK TAMPILAN MODERN & BERSIH
# ==========================================
st.markdown(
    """
    <style>
    .block-container {
        padding-top: 1.8rem;
        padding-bottom: 2.5rem;
        max-width: 1200px;
    }
    .hero-banner {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 60%, #0f2942 100%);
        border: 1px solid rgba(56, 189, 248, 0.25);
        border-radius: 14px;
        padding: 1.4rem 1.8rem;
        margin-bottom: 1.4rem;
        color: #f8fafc;
    }
    .hero-badge {
        display: inline-block;
        background: rgba(56, 189, 248, 0.15);
        color: #38bdf8;
        border: 1px solid rgba(56, 189, 248, 0.35);
        font-size: 0.78rem;
        font-weight: 600;
        padding: 0.2rem 0.65rem;
        border-radius: 999px;
        margin-bottom: 0.5rem;
        letter-spacing: 0.03em;
    }
    .hero-title {
        font-size: 1.75rem;
        font-weight: 700;
        margin: 0 0 0.35rem 0;
        color: #ffffff;
    }
    .hero-subtitle {
        font-size: 0.95rem;
        color: #cbd5e1;
        margin: 0;
    }
    .info-card {
        background-color: rgba(30, 41, 59, 0.45);
        border: 1px solid rgba(148, 163, 184, 0.2);
        border-radius: 12px;
        padding: 1rem 1.2rem;
        margin-bottom: 0.8rem;
    }
    div[data-testid="stMetric"] {
        background-color: rgba(30, 41, 59, 0.45);
        border: 1px solid rgba(148, 163, 184, 0.2);
        border-radius: 10px;
        padding: 0.75rem 1rem;
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
# ANTARMUKA UTAMA APLIKASI
# ==========================================
def main() -> None:
  with st.sidebar:
    st.markdown("## 🛡️ OSINT Shield")
    st.caption("Pusat Verifikasi Fakta & Perlindungan Digital")
    st.divider()

    category = st.selectbox(
        "Kategori Alat:",
        [
            "🖼️ Forensik Gambar & QR",
            "🔗 Cek Link, APK & Email",
            "👤 Identitas, Akun & Kebocoran",
            "📄 Dokumentasi Bukti",
        ],
    )

    if category == "🖼️ Forensik Gambar & QR":
      module_choice = st.radio(
          "Pilih Modul:",
          [
              "Forensik Gambar & Metadata",
              "Bongkar QR Code / QRIS Palsu",
          ],
      )
    elif category == "🔗 Cek Link, APK & Email":
      module_choice = st.radio(
          "Pilih Modul:",
          [
              "Cek Link Phishing & Domain",
              "Cek File .APK / Dokumen Berbahaya",
              "Analisis Header Email Phishing",
          ],
      )
    elif category == "👤 Identitas, Akun & Kebocoran":
      module_choice = st.radio(
          "Pilih Modul:",
          [
              "Cek Rekening, E-Wallet & Dorking",
              "Pelacak Username Publik",
              "Cek Kebocoran Password & Email",
          ],
      )
    else:
      module_choice = "Buat Laporan Bukti PDF"

    st.divider()
    st.caption(
        "🟢 **Status Sistem:** Aktif\n\n"
        "Dirancang untuk membantu memverifikasi bukti digital dan melindungi"
        " kerabat dari penipuan online."
    )

  # ==========================================
  # MODUL 1: FORENSIK GAMBAR & METADATA
  # ==========================================
  if module_choice == "Forensik Gambar & Metadata":
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
        st.image(
            oriented_img, caption=uploaded_file.name, width="stretch"
        )
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
          "* [Cari di TinEye](https://tineye.com/)"
      )

    with t5:
      st.subheader("Pembersih Metadata (Lindungi Privasi Keluarga)")
      clean_bytes = strip_metadata_to_jpeg(raw_img, quality=92)
      st.download_button(
          "🧹 Unduh Foto Bersih Tanpa Metadata (JPEG)",
          data=clean_bytes,
          file_name=f"aman_{uploaded_file.name.rsplit('.', 1)[0]}.jpg",
          mime="image/jpeg",
      )
      st.divider()
      st.subheader("Ekstraksi Teks (OCR)")
      if HAS_PYTESSERACT and pytesseract is not None:
        try:
          txt = pytesseract.image_to_string(oriented_img)
          st.text_area("Teks Terbaca", value=txt.strip(), height=180)
        except Exception as e:
          st.warning(f"OCR tidak tersedia di server ini: {e}")
      else:
        st.info(
            "OCR memerlukan pustaka `pytesseract` & engine `tesseract-ocr` di"
            " server."
        )

  # ==========================================
  # MODUL 2: DETEKTOR QR CODE / QRIS PALSU
  # ==========================================
  elif module_choice == "Bongkar QR Code / QRIS Palsu":
    render_hero(
        "KEAMANAN PEMBAYARAN & TAUTAN",
        "📷 Bongkar Isi QR Code / QRIS Sebelum Dipindai",
        "Unggah tangkapan layar QR Code untuk melihat tautan atau nama merchant asli di dalamnya tanpa memindainya langsung lewat kamera HP.",
    )

    qr_file = st.file_uploader(
        "Unggah gambar berisi QR Code", type=["jpg", "jpeg", "png", "webp"]
    )
    if qr_file:
      pil_qr = Image.open(qr_file)
      c1, c2 = st.columns([1, 1.4], gap="large")
      with c1:
        st.image(pil_qr, caption="Gambar QR", width="stretch")
      with c2:
        decoded_list = decode_qr_codes(pil_qr)
        if decoded_list:
          st.success(f"Ditemukan {len(decoded_list)} data QR Code:")
          for idx, item in enumerate(decoded_list, 1):
            st.markdown(f"**Isi QR #{idx}:**")
            st.code(item, language="text")
            if item.startswith(("http://", "https://")):
              st.warning(
                  "QR ini mengarah ke tautan web! Pastikan domainnya resmi"
                  " sebelum dikunjungi."
              )
            elif "ID.CO.QRIS" in item.upper() or "000201" in item:
              st.info(
                  "Terdeteksi format standar **QRIS Pembayaran**. Periksa"
                  " nama merchant yang muncul di teks mentah di atas."
              )
        else:
          st.warning(
              "Tidak ada QR Code yang terbaca. Pastikan gambar QR cukup jelas"
              " dan tidak terpotong."
          )

  # ==========================================
  # MODUL 3: CEK FILE .APK / DOKUMEN MENCURIGAKAN
  # ==========================================
  elif module_choice == "Cek File .APK / Dokumen Berbahaya":
    render_hero(
        "ANTI-MALWARE SNIFFING",
        "📦 Pemeriksa File .APK & Dokumen Mencurigakan",
        "Periksa file kiriman WhatsApp (seperti 'Undangan_Nikah.apk' atau 'Resi Paket.apk') secara aman tanpa menginstalnya di ponsel.",
    )

    susp_file = st.file_uploader(
        "Unggah file yang dicurigai (APK, ZIP, PDF, dll.)"
    )
    if susp_file:
      f_bytes = susp_file.getvalue()
      report = inspect_suspicious_file(susp_file.name, f_bytes)

      if susp_file.name.lower().endswith(".apk") or report["detected_permissions"]:
        st.error(
            "🚨 **PERINGATAN KERAS:** File ini adalah paket aplikasi Android"
            " (.APK)! Undangan pernikahan, resi kurir, atau surat tilang"
            " asli TIDAK PERNAH berbentuk file `.apk`."
        )

      st.markdown(
          f"""
          <div class="info-card">
              <b>Nama File:</b> <code>{report['file_name']}</code> ({report['size_kb']} KB)<br>
              <b>SHA-256:</b> <code>{report['hashes']['sha256']}</code><br>
              <b>MD5:</b> <code>{report['hashes']['md5']}</code>
          </div>
          """,
          unsafe_allow_html=True,
      )
      st.markdown(
          f"🔍 **[Cek Hash File Ini di VirusTotal](https://www.virustotal.com/gui/file/{report['hashes']['sha256']})**"
      )

      if report["detected_permissions"]:
        st.divider()
        st.subheader("⚠️ Izin Berbahaya Terdeteksi di Dalam APK:")
        for p in report["detected_permissions"]:
          st.error(f"**{p['permission']}** — {p['risk_description']}")

      if report["embedded_urls"]:
        st.divider()
        st.subheader("🌐 Tautan / Server Tujuan yang Tertanam di Dalam File:")
        st.code("\n".join(report["embedded_urls"]), language="text")

      if report["archive_entries"]:
        with st.expander("Lihat Struktur Isi Paket File"):
          st.code("\n".join(report["archive_entries"]), language="text")

  # ==========================================
  # MODUL 4: CEK LINK PHISHING & DOMAIN
  # ==========================================
  elif module_choice == "Cek Link Phishing & Domain":
    render_hero(
        "ANTI-PHISHING & DOMAIN RECON",
        "🔗 Pemeriksa Keamanan Link & Domain",
        "Lacak ke mana shortlink diarahkan, periksa sertifikat SSL, dan deteksi situs tiruan tanpa harus membukanya di browser HP kerabat.",
    )

    url_input = st.text_input(
        "Tempelkan link yang ingin diperiksa:",
        placeholder="Contoh: https://bit.ly/xxx atau https://promo-bank.xyz",
    )
    if (
        st.button("🔍 Periksa Keamanan Link", type="primary")
        and url_input.strip()
    ):
      with st.spinner("Menganalisis tujuan redirect, DNS, dan sertifikat SSL..."):
        res = inspect_url_safety(url_input)

      if res["risk_flags"]:
        st.error("⚠️ **Ditemukan Indikasi Risiko:**")
        for flag in res["risk_flags"]:
          st.write(f"- {flag}")
      else:
        st.success(
            "✅ Struktur domain dan SSL terlihat normal (tetap waspada"
            " terhadap halaman login/form input data)."
        )

      c1, c2 = st.columns(2, gap="large")
      with c1:
        st.subheader("Tujuan & Alur Redirect")
        st.write(f"**Domain Akhir:** `{res['domain']}`")
        st.write(f"**URL Akhir:** `{res['final_url']}`")
        if len(res["redirect_chain"]) > 1:
          st.write("**Rantai Pengalihan:**")
          for idx, step_url in enumerate(res["redirect_chain"], 1):
            st.code(f"{idx}. {step_url}", language="text")
        if res["ip_addresses"]:
          st.write(
              f"**Alamat IP Server:** `{', '.join(res['ip_addresses'])}`"
          )

      with c2:
        st.subheader("Sertifikat SSL & Catatan DNS")
        st.json(res["ssl_info"])
        if res["dns_records"]:
          st.json(res["dns_records"])

      st.divider()
      encoded_u = quote_plus(res["final_url"])
      st.markdown(
          f"**Cek Reputasi Eksternal:** "
          f"[VirusTotal](https://www.virustotal.com/gui/search/{encoded_u}) | "
          f"[urlscan.io](https://urlscan.io/search/#{quote_plus(res['domain'])})"
      )

  # ==========================================
  # MODUL 5: ANALISIS HEADER EMAIL PHISHING
  # ==========================================
  elif module_choice == "Analisis Header Email Phishing":
    render_hero(
        "ANTI-SPOOFING EMAIL",
        "📧 Analisis Header Email (Deteksi Email Palsu)",
        "Tempelkan 'Show Original' / 'View Message Source' dari email mencurigakan untuk mengecek keaslian pengirim (SPF, DKIM, DMARC).",
    )

    raw_hdr = st.text_area(
        "Tempelkan Raw Email Header di sini:",
        height=210,
        placeholder="Received: from ...\nAuthentication-Results: ...\nFrom: ...\nReply-To: ...",
    )
    if (
        st.button("🔎 Analisis Header Email", type="primary")
        and raw_hdr.strip()
    ):
      h_res = analyze_email_header(raw_hdr)

      if h_res["warnings"]:
        for w in h_res["warnings"]:
          st.error(f"🚨 {w}")
      else:
        st.success(
            "✅ Tidak ditemukan ketidaksesuaian mencolok antara pengirim dan"
            " autentikasi dasar."
        )

      m1, m2, m3 = st.columns(3)
      m1.metric("Status SPF", h_res["spf"])
      m2.metric("Status DKIM", h_res["dkim"])
      m3.metric("Status DMARC", h_res["dmarc"])

      st.markdown(
          f"""
          <div class="info-card">
              <b>Subjek:</b> {h_res['subject']}<br>
              <b>From:</b> <code>{h_res['from']}</code><br>
              <b>Reply-To:</b> <code>{h_res['reply_to']}</code><br>
              <b>Return-Path:</b> <code>{h_res['return_path']}</code>
          </div>
          """,
          unsafe_allow_html=True,
      )
      if h_res["server_ips"]:
        st.write(
            f"**IP Server Pengirim Terdeteksi:** `{', '.join(h_res['server_ips'])}`"
        )

  # ==========================================
  # MODUL 6: CEK KEBOCORAN PASSWORD & EMAIL
  # ==========================================
  elif module_choice == "Cek Kebocoran Password & Email":
    render_hero(
        "PERLINDUNGAN AKUN & KREDENSIAL",
        "🔐 Pemeriksa Keamanan Password & Kebocoran Data",
        "Cek apakah kata sandi kerabat pernah bocor dalam insiden peretasan global menggunakan metode k-Anonymity yang aman.",
    )

    pw_input = st.text_input(
        "Masukkan password yang ingin dicek keamanannya:",
        type="password",
    )
    if st.button("🛡️ Cek Kebocoran Password", type="primary") and pw_input:
      try:
        leak_count = check_password_pwned(pw_input)
        if leak_count > 0:
          st.error(
              f"⚠️ **BAHAYA!** Password ini ditemukan sebanyak **{leak_count:,}**"
              " kali dalam database kebocoran data publik! Segera ganti"
              " password ini di semua akun."
          )
        else:
          st.success(
              "✅ Password ini belum pernah ditemukan dalam database"
              " kebocoran data publik Have I Been Pwned."
          )
      except Exception as exc:
        st.warning(f"Gagal menghubungi layanan pengecekan: {exc}")

    st.divider()
    st.subheader("Cek Kebocoran Email")
    email_check = st.text_input(
        "Masukkan alamat email kerabat:", placeholder="nama@gmail.com"
    ).strip()
    if email_check:
      st.markdown(
          f"Klik untuk mengecek riwayat kebocoran email `{email_check}` secara"
          " langsung:\n"
          f"* [Cek di Have I Been Pwned](https://haveibeenpwned.com/account/{quote_plus(email_check)})\n"
          f"* [Cek Kemunculan Publik di Google](https://www.google.com/search?q=%22{quote_plus(email_check)}%22)"
      )

  # ==========================================
  # MODUL 7: PELACAK USERNAME PUBLIK
  # ==========================================
  elif module_choice == "Pelacak Username Publik":
    render_hero(
        "REKON IDENTITAS PUBLIK",
        "👤 Pelacak Jejak Username Publik",
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
  # MODUL 8: CEK REKENING, E-WALLET & DORKING
  # ==========================================
  elif module_choice == "Cek Rekening, E-Wallet & Dorking":
    render_hero(
        "VERIFIKASI TRANSAKSI & REPUTASI",
        "💳 Cek Reputasi Rekening, E-Wallet & Pencarian Publik",
        "Verifikasi nomor rekening bank, e-wallet, nomor telepon, atau nama penjual sebelum kerabat melakukan transfer dana.",
    )

    target_query = st.text_input(
        "Masukkan Nomor Rekening / No. HP / E-Wallet / Nama Toko:",
        placeholder="Contoh: 081234567890 atau 1234567890",
    ).strip()

    if target_query:
      q_enc = quote_plus(f'"{target_query}"')
      scam_enc = quote_plus(
          f'"{target_query}" (penipu OR penipuan OR scam OR hati-hati OR waspada OR blokir)'
      )
      socmed_enc = quote_plus(
          f'"{target_query}" (site:instagram.com OR site:facebook.com OR site:tiktok.com OR site:x.com)'
      )

      col_a, col_b = st.columns(2, gap="large")
      with col_a:
        st.subheader("1. Portal Cek Rekening Indonesia")
        st.markdown(
            "* [Buka CekRekening.id (Komdigi RI)](https://cekrekening.id/home)\n"
            "* [Buka Kredibel.com (Cek Reputasi Rekening & Telepon)](https://www.kredibel.com/)\n"
            "* [Indonesia Anti-Scam Centre (IASC OJK)](https://iasc.ojk.go.id/)"
        )
      with col_b:
        st.subheader("2. Pencarian Keluhan & Jejak Digital")
        st.markdown(
            f"* [Cek Laporan Penipuan di Google](https://www.google.com/search?q={scam_enc})\n"
            f"* [Pencarian Eksak di Seluruh Web](https://www.google.com/search?q={q_enc})\n"
            f"* [Jejak di Media Sosial](https://www.google.com/search?q={socmed_enc})"
        )
    else:
      st.info(
          "Masukkan nomor rekening, nomor HP, atau nama penjual di atas untuk"
          " memunculkan tautan verifikasi."
      )

  # ==========================================
  # MODUL 9: BUAT LAPORAN BUKTI DIGITAL (PDF)
  # ==========================================
  elif module_choice == "Buat Laporan Bukti PDF":
    render_hero(
        "DOKUMENTASI & PELAPORAN RESMI",
        "📄 Generator Laporan Bukti Digital (PDF)",
        "Susun temuan investigasi (hash bukti gambar, tautan phishing, nomor rekening terlapor, dan kronologi) menjadi berkas PDF siap cetak.",
    )

    with st.form("pdf_report_form"):
      c_title = st.text_input(
          "Judul Laporan", value="Dokumentasi Dugaan Penipuan Online"
      )
      c_inv = st.text_input("Nama Pelapor / Peneliti")
      c_target = st.text_input(
          "Identitas Terlapor (No. Rekening / No. HP / Username / Link)"
      )
      c_date = st.text_input(
          "Tanggal & Waktu Kejadian",
          value=datetime.now().strftime("%d %B %Y, %H:%M WIB"),
      )
      c_chron = st.text_area("Kronologi Kejadian", height=120)
      c_evid = st.text_area(
          "Rincian Bukti Digital (Tempelkan Hash SHA-256, IP Server, URL Akhir, dll.)",
          height=140,
      )
      submitted = st.form_submit_button(
          "📥 Buat & Siapkan File PDF", type="primary"
      )

    if submitted:
      pdf_bytes = generate_case_pdf(
          c_title, c_inv, c_target, c_date, c_chron, c_evid
      )
      st.success("Berkas laporan PDF berhasil dibuat!")
      st.download_button(
          "⬇️ Unduh Laporan Bukti (.PDF)",
          data=pdf_bytes,
          file_name="Laporan_Bukti_OSINT.pdf",
          mime="application/pdf",
      )


if __name__ == "__main__":
  main()
