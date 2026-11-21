import csv
import hashlib
import io
import json
import math
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote_plus, urlparse

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
    page_title="OSINT Shield — Command Center",
    page_icon="🛡️",
    layout="wide",
)


# ==========================================
# FUNGSI BANTU MODUL 1: IMAGE FORENSICS
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
  utc_hours = (
      dt_utc.hour
      + dt_utc.minute / 60.0
      + dt_utc.second / 3600.0
  )
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
# FUNGSI BANTU MODUL 2: ANTI-PHISHING & LINK
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

  # 1. Cek pola mencurigakan pada URL
  suspicious_tlds = (".xyz", ".top", ".buzz", ".click", ".apk", ".vip", ".icu", ".loan")
  if any(domain.endswith(tld) for tld in suspicious_tlds):
    result["risk_flags"].append(f"Domain menggunakan ekstensi TLD berisiko tinggi ({domain}).")
  if "@" in url:
    result["risk_flags"].append("URL mengandung karakter '@' yang sering dipakai untuk menyamarkan tujuan asli.")
  if domain.count("-") >= 3:
    result["risk_flags"].append("Domain memiliki banyak tanda hubung (-), pola umum situs tiruan/phishing.")
  if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
    result["risk_flags"].append("Tautan mengarah langsung ke alamat IP mentah, bukan nama domain resmi.")

  # 2. Lacak redirect tanpa mengeksekusi konten halaman
  try:
    resp = requests.head(
        url,
        allow_redirects=True,
        timeout=8,
        headers={"User-Agent": "OSINT-Shield-Inspector/1.0"},
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

  # 3. Resolusi IP & Google Public DNS
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

    # 4. Cek Sertifikat SSL
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
      result["ssl_info"] = {"error": f"Tidak ada SSL valid / gagal koneksi HTTPS ({exc})"}
      result["risk_flags"].append("Situs tidak memiliki sertifikat SSL/HTTPS yang valid.")

  return result


# ==========================================
# FUNGSI BANTU MODUL 3: USERNAME RECON
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
      r = requests.get(target_url, headers=headers, timeout=5, allow_redirects=True)
      if r.status_code == 200:
        # Beberapa platform tetap return 200 untuk halaman tidak ditemukan
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
# ANTARMUKA UTAMA APLIKASI
# ==========================================
def main() -> None:
  st.sidebar.title("🛡️ OSINT Shield")
  st.sidebar.caption("Alat Verifikasi Fakta & Perlindungan Digital")
  module_choice = st.sidebar.radio(
      "Pilih Modul Investigasi:",
      [
          "1. Forensik Gambar & Metadata",
          "2. Cek Link Phishing & Domain",
          "3. Pelacak Username Publik",
          "4. Pencarian Cerdas (Dorking & Kontak)",
      ],
  )
  st.sidebar.divider()
  st.sidebar.info(
      "Gunakan alat ini untuk melindungi kerabat dari penipuan online, hoaks,"
      " dan pencurian data menggunakan sumber informasi terbuka yang legal."
  )

  # ==========================================
  # MODUL 1: IMAGE FORENSICS
  # ==========================================
  if module_choice == "1. Forensik Gambar & Metadata":
    st.title("🕵️ Forensik Gambar & Deep Metadata")
    st.caption(
        "Periksa keaslian foto, bukti transfer, koordinat GPS, jejak editan"
        " (ELA), arah bayangan, hingga hapus metadata sebelum berbagi foto."
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
        img_mode = img.mode
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
        st.image(oriented_img, caption=uploaded_file.name, use_container_width=True)
      with c2:
        st.subheader("Ringkasan & Sidik Jari File")
        st.write(f"**Nama File:** `{uploaded_file.name}`")
        st.write(f"**Format / Dimensi:** `{img_format}` | `{width} x {height}` px ({file_size_kb} KB)")
        st.write(f"**MD5:** `{hashes['md5']}`")
        st.write(f"**SHA-256:** `{hashes['sha256']}`")

        b1, b2 = st.columns(2)
        with b1:
          st.download_button(
              "⬇️ Unduh Laporan JSON",
              data=json.dumps(report_payload, indent=2, ensure_ascii=False),
              file_name=f"{uploaded_file.name}_report.json",
              mime="application/json",
              use_container_width=True,
          )
        with b2:
          st.download_button(
              "⬇️ Unduh EXIF CSV",
              data=build_csv_report(exif_rows_all),
              file_name=f"{uploaded_file.name}_exif.csv",
              mime="text/csv",
              use_container_width=True,
          )

      st.divider()
      q_exif = st.text_input("Filter Tag EXIF", placeholder="Cari Make, Model, Software, DateTime...").strip().lower()
      filtered = [
          r for r in exif_rows_all
          if not q_exif or q_exif in r["Tag EXIF"].lower() or q_exif in r["Nilai"].lower()
      ]
      if filtered:
        st.dataframe(filtered, use_container_width=True, hide_index=True)
      else:
        st.info("Tidak ada metadata EXIF standar yang ditemukan (umum jika foto dikirim lewat WhatsApp/medsos).")

    with t2:
      st.subheader("Jejak Software & Strings Tersembunyi")
      if deep_meta["pil_info"]:
        st.json(deep_meta["pil_info"])
      if deep_meta["xmp_snippets"]:
        for idx, snip in enumerate(deep_meta["xmp_snippets"], 1):
          with st.expander(f"Data XMP #{idx}"):
            st.code(snip, language="xml")
      str_q = st.text_input("Filter strings biner", placeholder="Contoh: Photoshop, Canva, PixelLab").strip().lower()
      matched_s = [s for s in deep_meta["strings"] if not str_q or str_q in s.lower()]
      if matched_s:
        st.code("\n".join(matched_s), language="text")
      else:
        st.info("Tidak ada string tersembunyi yang cocok.")

    with t3:
      st.subheader("Error Level Analysis (Deteksi Manipulasi / Editan)")
      st.caption("Berguna untuk mengecek bukti transfer atau dokumen foto. Bagian yang memiliki tingkat kecerahan kontras mencolok dibanding area sekitarnya patut dicurigai telah ditempel/diedit.")
      ec1, ec2 = st.columns(2)
      with ec1:
        q_ela = st.slider("Kualitas Rekompresi", 50, 98, 90)
      with ec2:
        s_ela = st.slider("Intensitas Kontras", 5, 40, 15)
      ela_img = perform_ela(oriented_img, quality=q_ela, scale=s_ela)
      vc1, vc2 = st.columns(2)
      with vc1:
        st.markdown("**Asli**")
        st.image(oriented_img, use_container_width=True)
      with vc2:
        st.markdown("**Analisis ELA**")
        st.image(ela_img, use_container_width=True)

    with t4:
      st.subheader("Geolokasi & Verifikasi Waktu Bayangan")
      lat_def = coords[0] if coords else -6.8898
      lon_def = coords[1] if coords else 109.6746
      if coords:
        st.success(f"Koordinat GPS ditemukan di EXIF: **{coords[0]}, {coords[1]}**")
      cc1, cc2 = st.columns(2)
      with cc1:
        lat_in = st.number_input("Latitude", value=float(lat_def), format="%.6f")
      with cc2:
        lon_in = st.number_input("Longitude", value=float(lon_def), format="%.6f")
      st.map({"lat": [lat_in], "lon": [lon_in]})
      st.markdown(
          f"[Buka Google Maps](https://www.google.com/maps?q={lat_in},{lon_in}) | "
          f"[Google Street View](https://www.google.com/maps/@?api=1&map_action=pano&viewpoint={lat_in},{lon_in}) | "
          f"[SunCalc.org](https://www.suncalc.org/#/{lat_in},{lon_in},16/2026.11.21/08:19/1/3)"
      )

      st.divider()
      sc1, sc2 = st.columns(2)
      with sc1:
        d_val = st.date_input("Tanggal (UTC)", value=datetime.now(timezone.utc).date())
      with sc2:
        t_val = st.time_input("Jam (UTC)", value=datetime.now(timezone.utc).time().replace(microsecond=0))
      solar = calculate_solar_position(lat_in, lon_in, datetime.combine(d_val, t_val, tzinfo=timezone.utc))
      m1, m2, m3 = st.columns(3)
      m1.metric("Azimuth Matahari", f"{solar['azimuth_deg']}°")
      m2.metric("Elevasi Matahari", f"{solar['elevation_deg']}°")
      m3.metric("Arah Bayangan Benda", f"{solar['shadow_direction_deg']}°")

      st.divider()
      st.subheader("Reverse Image Search (Cek Foto Curian / Hoaks)")
      st.markdown(
          "* [Cari di Google Lens](https://lens.google.com/)\n"
          "* [Cari di Yandex Images](https://yandex.com/images/)\n"
          "* [Cari di TinEye](https://tineye.com/)"
      )

    with t5:
      st.subheader("Pembersih Metadata (Lindungi Privasi Keluarga)")
      st.caption("Hapus lokasi GPS dan tipe HP dari foto sebelum diunggah ke media sosial atau grup publik.")
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
        st.info("Fitur OCR memerlukan pustaka `pytesseract` & engine `tesseract-ocr` di server.")

  # ==========================================
  # MODUL 2: ANTI-PHISHING & LINK INSPECTOR
  # ==========================================
  elif module_choice == "2. Cek Link Phishing & Domain":
    st.title("🔗 Pemeriksa Keamanan Link & Domain (Anti-Scam)")
    st.caption(
        "Periksa tautan mencurigakan (undangan palsu, promo bank, shortlink)"
        " tanpa harus membukanya di browser HP kerabat."
    )

    url_input = st.text_input(
        "Tempelkan link yang ingin diperiksa:",
        placeholder="Contoh: https://bit.ly/xxx atau https://cek-paket-kurir.xyz",
    )
    if st.button("🔍 Periksa Keamanan Link", type="primary") and url_input.strip():
      with st.spinner("Menganalisis tujuan redirect, DNS, dan sertifikat SSL..."):
        res = inspect_url_safety(url_input)

      if res["risk_flags"]:
        st.error("⚠️ **Peringatan! Ditemukan Indikasi Risiko:**")
        for flag in res["risk_flags"]:
          st.write(f"- {flag}")
      else:
        st.success("✅ Tidak ditemukan pola mencurigakan dasar pada struktur tautan & SSL (tetap waspada terhadap isi halaman).")

      c1, c2 = st.columns(2)
      with c1:
        st.subheader("Tujuan & Alur Redirect")
        st.write(f"**Domain Akhir:** `{res['domain']}`")
        st.write(f"**URL Akhir:** `{res['final_url']}`")
        if len(res["redirect_chain"]) > 1:
          st.write("**Rantai Pengalihan:**")
          for idx, step_url in enumerate(res["redirect_chain"], 1):
            st.code(f"{idx}. {step_url}", language="text")
        if res["ip_addresses"]:
          st.write(f"**Alamat IP Server:** `{', '.join(res['ip_addresses'])}`")

      with c2:
        st.subheader("Sertifikat SSL & Catatan DNS")
        st.json(res["ssl_info"])
        if res["dns_records"]:
          st.json(res["dns_records"])

      st.divider()
      encoded_u = quote_plus(res["final_url"])
      st.markdown(
          f"**Cek Reputasi Eksternal:** "
          f"[Cek di VirusTotal](https://www.virustotal.com/gui/search/{encoded_u}) | "
          f"[Cek di urlscan.io](https://urlscan.io/search/#{quote_plus(res['domain'])})"
      )

  # ==========================================
  # MODUL 3: PELACAK USERNAME PUBLIK
  # ==========================================
  elif module_choice == "3. Pelacak Username Publik":
    st.title("👤 Pelacak Jejak Username Publik")
    st.caption(
        "Cek apakah sebuah username digunakan di berbagai platform sosial media"
        " untuk memverifikasi keaslian akun atau melacak akun penipu."
    )

    uname_input = st.text_input(
        "Masukkan Username (tanpa @):",
        placeholder="Contoh: budi_santoso99",
    )
    if st.button("🔎 Lacak Username", type="primary") and uname_input.strip():
      with st.spinner("Mengecek ketersediaan profil publik di berbagai platform..."):
        rows = check_username_public(uname_input)
      st.dataframe(
          rows,
          use_container_width=True,
          hide_index=True,
          column_config={
              "Tautan Profil": st.column_config.LinkColumn("Tautan Profil")
          },
      )

  # ==========================================
  # MODUL 4: SMART GOOGLE DORKING & KONTAK
  # ==========================================
  elif module_choice == "4. Pencarian Cerdas (Dorking & Kontak)":
    st.title("🎯 Pencarian Investigasi Cerdas (OSINT Dorking)")
    st.caption(
        "Buat kueri pencarian presisi untuk mengecek riwayat nomor telepon,"
        " email, rekening, atau nama pelaku penipuan di catatan publik."
    )

    target_query = st.text_input(
        "Masukkan Nomor HP / Email / Nama / Kata Kunci:",
        placeholder="Contoh: 081234567890 atau nama toko online mencurigakan",
    ).strip()

    if target_query:
      q_enc = quote_plus(f'"{target_query}"')
      scam_enc = quote_plus(
          f'"{target_query}" (penipu OR penipuan OR scam OR hati-hati OR waspada)'
      )
      socmed_enc = quote_plus(
          f'"{target_query}" (site:instagram.com OR site:facebook.com OR site:tiktok.com OR site:x.com)'
      )
      doc_enc = quote_plus(
          f'"{target_query}" (filetype:pdf OR filetype:xls OR filetype:xlsx OR filetype:doc)'
      )

      st.subheader("Klik Tautan Riset Otomatis:")
      st.markdown(
          f"1. **Cek Laporan Penipuan / Keluhan Publik:** [Cari di Google](https://www.google.com/search?q={scam_enc})\n"
          f"2. **Pencarian Eksak di Seluruh Web:** [Cari di Google](https://www.google.com/search?q={q_enc})\n"
          f"3. **Jejak di Media Sosial Utama:** [Cari di Google](https://www.google.com/search?q={socmed_enc})\n"
          f"4. **Kemunculan di Dokumen Publik (PDF/Excel):** [Cari di Google](https://www.google.com/search?q={doc_enc})"
      )
    else:
      st.info("Ketik nomor telepon, email, atau nama di atas untuk membuat tautan investigasi otomatis.")


if __name__ == "__main__":
  main()
