import hashlib
from typing import Any, Dict, Optional, Tuple
from PIL import Image, ImageOps
from PIL.ExifTags import GPSTAGS, TAGS
import streamlit as st

st.set_page_config(
    page_title="EXIF & Image Metadata Inspector",
    page_icon="🔍",
    layout="wide",
)


def compute_sha256(file_bytes: bytes) -> str:
  """Menghitung hash SHA-256 dari byte file asli."""
  return hashlib.sha256(file_bytes).hexdigest()


def rational_to_float(value: Any) -> Optional[float]:
  """Mengonversi nilai rational PIL (tuple/IFDRational) menjadi float."""
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
  """Mengonversi data GPS EXIF (DMS) menjadi koordinat (latitude, longitude) desimal."""
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
  """Merapikan tipe data EXIF agar aman ditampilkan dan di-export."""
  if isinstance(val, bytes):
    try:
      decoded = val.decode("utf-8", errors="replace").strip("\x00").strip()
      return decoded if decoded else f"<{len(val)} bytes>"
    except Exception:
      return f"<{len(val)} bytes>"
  if hasattr(val, "numerator") and hasattr(val, "denominator"):
    num = int(val.numerator)
    den = int(val.denominator)
    if den == 1:
      return str(num)
    return f"{num}/{den} ({round(num / den, 4)})"
  if isinstance(val, tuple):
    return [serialize_value(item) for item in val]
  if isinstance(val, list):
    return [serialize_value(item) for item in val]
  if isinstance(val, dict):
    return {str(k): serialize_value(v) for k, v in val.items()}
  return str(val)


def extract_exif_data(
    img: Image.Image,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
  """Mengekstrak metadata EXIF umum dan sub-tag GPS."""
  general_exif: Dict[str, Any] = {}
  gps_parsed: Dict[str, Any] = {}

  exif_obj = img.getexif()
  if not exif_obj:
    return general_exif, gps_parsed

  for tag_id, raw_val in exif_obj.items():
    tag_name = TAGS.get(tag_id, f"UnknownTag_{tag_id}")
    if tag_name == "GPSInfo":
      continue
    general_exif[tag_name] = serialize_value(raw_val)

  # Ambil blok GPS IFD jika tersedia
  gps_ifd = None
  try:
    gps_ifd = exif_obj.get_ifd(0x8825)
  except Exception:
    gps_ifd = None

  if gps_ifd:
    for gps_tag_id, gps_val in gps_ifd.items():
      gps_tag_name = GPSTAGS.get(gps_tag_id, f"GPSTag_{gps_tag_id}")
      gps_parsed[gps_tag_name] = gps_val

  return general_exif, gps_parsed


def main() -> None:
  st.title("🔍 EXIF & Image Metadata Inspector")
  st.caption(
      "Ekstrak metadata EXIF, koordinat GPS, dimensi gambar, dan hash SHA-256"
      " untuk analisis OSINT."
  )

  st.warning(
      "Catatan: Banyak platform media sosial dan aplikasi pesan menghapus"
      " metadata EXIF atau koordinat GPS saat gambar diunggah atau dikirim"
      " ulang. File asli (original/uncompressed) jauh lebih mungkin menyimpan"
      " metadata lengkap."
  )

  uploaded_file = st.file_uploader(
      "Unggah file gambar",
      type=["jpg", "jpeg", "png", "webp", "tiff", "tif"],
      help="Format yang didukung: JPG, JPEG, PNG, WEBP, TIFF",
  )

  if not uploaded_file:
    st.info(
        "Silakan unggah file gambar terlebih dahulu untuk melihat metadata"
        " EXIF."
    )
    return

  file_bytes = uploaded_file.getvalue()
  sha256_hash = compute_sha256(file_bytes)
  file_size_kb = round(len(file_bytes) / 1024, 2)

  try:
    uploaded_file.seek(0)
    with Image.open(uploaded_file) as img:
      display_img = ImageOps.exif_transpose(img).copy()
      img_format = img.format or "Tidak diketahui"
      img_mode = img.mode
      width, height = img.size
      general_exif, gps_raw = extract_exif_data(img)
  except Exception as exc:
    st.error(f"Gagal membaca file gambar: {exc}")
    return

  col_preview, col_summary = st.columns([1, 1.3], gap="large")

  with col_preview:
    st.subheader("Pratinjau Gambar")
    st.image(
        display_img, caption=uploaded_file.name, use_container_width=True
    )

  with col_summary:
    st.subheader("Ringkasan File & Teknis")
    st.write(f"**Nama File:** `{uploaded_file.name}`")
    st.write(f"**Format:** `{img_format}` | **Mode Warna:** `{img_mode}`")
    st.write(f"**Resolusi:** `{width} x {height}` px")
    st.write(f"**Ukuran File:** `{file_size_kb} KB` ({len(file_bytes):,} byte)")
    st.write(f"**SHA-256:** `{sha256_hash}`")

  st.divider()

  # Bagian Koordinat GPS
  st.subheader("📍 Lokasi / Koordinat GPS")
  coords = convert_gps_to_decimal(gps_raw) if gps_raw else None

  if coords:
    lat_val, lon_val = coords
    maps_url = f"https://www.google.com/maps?q={lat_val},{lon_val}"
    st.success(f"Koordinat GPS ditemukan: **{lat_val}, {lon_val}**")
    st.markdown(f"[Buka di Google Maps]({maps_url})")
    st.map({"lat": [lat_val], "lon": [lon_val]})
  else:
    st.info(
        "Tidak ada koordinat GPS yang terdeteksi pada metadata gambar ini."
    )

  st.divider()

  # Bagian Tabel Metadata EXIF
  st.subheader("📋 Metadata EXIF")
  search_query = st.text_input(
      "Filter tag metadata",
      placeholder="Contoh: Make, Model, DateTime, Software, Exposure",
  ).strip().lower()

  if not general_exif:
    st.info(
        "Tidak ditemukan tag metadata EXIF pada gambar ini (umum terjadi pada"
        " gambar hasil kompresi atau screenshot)."
    )
  else:
    filtered_rows = []
    for tag_key, tag_val in sorted(general_exif.items()):
      val_str = (
          ", ".join(str(x) for x in tag_val)
          if isinstance(tag_val, list)
          else str(tag_val)
      )
      if (
          search_query
          and search_query not in tag_key.lower()
          and search_query not in val_str.lower()
      ):
        continue
      filtered_rows.append({"Tag EXIF": tag_key, "Nilai": val_str})

    st.caption(f"Menampilkan {len(filtered_rows)} tag metadata.")
    if filtered_rows:
      st.dataframe(
          filtered_rows, use_container_width=True, hide_index=True
      )
    else:
      st.warning("Tidak ada tag yang cocok dengan kata kunci filter.")

  # Bagian Mentah (Raw) untuk keperluan lanjutan
  with st.expander("Lihat Data Mentah (JSON)"):
    payload = {
        "file_name": uploaded_file.name,
        "sha256": sha256_hash,
        "format": img_format,
        "width": width,
        "height": height,
        "gps_decimal": (
            {"lat": coords[0], "lon": coords[1]} if coords else None
        ),
        "exif": general_exif,
        "gps_raw": {k: serialize_value(v) for k, v in gps_raw.items()},
    }
    st.json(payload)


if __name__ == "__main__":
  main()
