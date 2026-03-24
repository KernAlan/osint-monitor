"""Image/Video Intelligence (IMINT) processor.

Provides EXIF extraction, OCR, error-level analysis for manipulation
detection, and CLIP-based zero-shot object classification.  All heavy
dependencies are lazily imported so the module degrades gracefully when
optional packages are missing.

Required packages:
    Pillow          - EXIF extraction, ELA, image I/O

Optional packages:
    easyocr         - multi-language OCR  (fallback: pytesseract)
    pytesseract     - Tesseract OCR wrapper (fallback for easyocr)
    transformers    - HuggingFace CLIP zero-shot classification
    torch           - backend for transformers
    numpy           - ELA pixel-level comparison
    requests        - downloading remote images (usually already present)
"""

from __future__ import annotations

import io
import json
import logging
import re
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

# Cached model singletons (loaded on first use)
_clip_model = None
_clip_processor = None

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Image file extensions recognised when scanning item URLs / content.
_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".tiff", ".bmp", ".gif"}

# Default labels for CLIP zero-shot classification (OSINT-relevant).
DEFAULT_CLIP_LABELS: list[str] = [
    "military vehicle",
    "tank",
    "aircraft",
    "warship",
    "missile launcher",
    "troops",
    "explosion",
    "building damage",
    "protest",
    "civilian",
]

# ELA threshold: mean pixel-error above which we flag "suspicious".
_ELA_MEAN_THRESHOLD = 8.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fetch_image_bytes(url: str) -> bytes:
    """Download an image from *url* and return raw bytes.

    Uses a 15-second timeout.  Raises on HTTP errors.
    """
    import requests  # noqa: lazy

    resp = requests.get(url, timeout=15, stream=True)
    resp.raise_for_status()
    return resp.content


def _load_image(path_or_url: str):
    """Return a PIL Image from a local path or remote URL.

    Returns ``(image, temp_path | None)``.  The caller should delete
    *temp_path* when finished if it is not ``None``.
    """
    from PIL import Image  # noqa: lazy

    if path_or_url.startswith(("http://", "https://")):
        data = _fetch_image_bytes(path_or_url)
        tmp = tempfile.NamedTemporaryFile(suffix=".img", delete=False)
        tmp.write(data)
        tmp.flush()
        tmp.close()
        img = Image.open(tmp.name)
        return img, tmp.name
    else:
        img = Image.open(path_or_url)
        return img, None


def _cleanup_temp(temp_path: str | None) -> None:
    """Delete a temporary file if it exists."""
    if temp_path is not None:
        try:
            Path(temp_path).unlink(missing_ok=True)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# GPS helpers
# ---------------------------------------------------------------------------

def _dms_to_decimal(dms_tuple, ref: str) -> float:
    """Convert EXIF GPS DMS (degrees, minutes, seconds) to decimal degrees."""
    degrees = float(dms_tuple[0])
    minutes = float(dms_tuple[1])
    seconds = float(dms_tuple[2])
    decimal = degrees + minutes / 60.0 + seconds / 3600.0
    if ref in ("S", "W"):
        decimal = -decimal
    return decimal


def _extract_gps(exif_data: dict) -> dict | None:
    """Extract GPS lat/lon from EXIF GPSInfo dict, returning decimal degrees."""
    try:
        from PIL.ExifTags import GPSTAGS  # noqa: lazy

        gps_info = exif_data.get("GPSInfo")
        if gps_info is None:
            return None

        # Resolve numeric tag keys to human-readable names.
        decoded: dict = {}
        for tag_id, value in gps_info.items():
            tag_name = GPSTAGS.get(tag_id, tag_id)
            decoded[tag_name] = value

        lat_dms = decoded.get("GPSLatitude")
        lat_ref = decoded.get("GPSLatitudeRef")
        lon_dms = decoded.get("GPSLongitude")
        lon_ref = decoded.get("GPSLongitudeRef")

        if lat_dms is None or lon_dms is None:
            return None

        lat = _dms_to_decimal(lat_dms, lat_ref or "N")
        lon = _dms_to_decimal(lon_dms, lon_ref or "E")
        return {"lat": round(lat, 7), "lon": round(lon, 7)}
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 1. EXIF extraction
# ---------------------------------------------------------------------------

def extract_exif(image_path_or_url: str) -> dict | None:
    """Extract EXIF metadata from an image file or URL.

    Returns a dict with keys ``gps``, ``camera``, ``software``,
    ``datetime``, ``dimensions``, and ``all_tags``.  Returns ``None``
    if the image cannot be opened or has no EXIF data at all.
    """
    temp_path: str | None = None
    try:
        from PIL import Image  # noqa: lazy
        from PIL.ExifTags import TAGS  # noqa: lazy

        img, temp_path = _load_image(image_path_or_url)

        raw_exif = img.getexif()
        if not raw_exif:
            # Still return basic info even without EXIF.
            return {
                "gps": None,
                "camera": "",
                "software": "",
                "datetime": "",
                "dimensions": [img.width, img.height],
                "all_tags": {},
            }

        # Decode all tags to human-readable names.
        decoded_tags: dict = {}
        for tag_id, value in raw_exif.items():
            tag_name = TAGS.get(tag_id, str(tag_id))
            # Some values are bytes; try to make them JSON-friendly.
            if isinstance(value, bytes):
                try:
                    value = value.decode("utf-8", errors="replace")
                except Exception:
                    value = repr(value)
            decoded_tags[tag_name] = value

        # Also decode nested IFDs (GPSInfo, ExifOffset, etc.)
        for ifd_id in raw_exif.get_ifd(0x8825) if hasattr(raw_exif, "get_ifd") else {}:
            pass  # GPS is handled separately below.

        # Build a full dict including GPSInfo sub-dict for _extract_gps.
        full_exif = dict(decoded_tags)
        try:
            gps_ifd = raw_exif.get_ifd(0x8825)
            if gps_ifd:
                full_exif["GPSInfo"] = gps_ifd
        except Exception:
            pass

        gps = _extract_gps(full_exif)

        return {
            "gps": gps,
            "camera": decoded_tags.get("Model", decoded_tags.get("Make", "")),
            "software": decoded_tags.get("Software", ""),
            "datetime": decoded_tags.get("DateTime", decoded_tags.get("DateTimeOriginal", "")),
            "dimensions": [img.width, img.height],
            "all_tags": decoded_tags,
        }

    except ImportError:
        logger.warning("Pillow is not installed; EXIF extraction unavailable.")
        return None
    except Exception as exc:
        logger.error("EXIF extraction failed for %s: %s", image_path_or_url, exc)
        return None
    finally:
        _cleanup_temp(temp_path)


# ---------------------------------------------------------------------------
# 2. OCR text extraction
# ---------------------------------------------------------------------------

def extract_text_ocr(image_path_or_url: str) -> str:
    """Extract text from an image using OCR.

    Tries EasyOCR first (supports ``en``, ``ru``, ``ar``, ``zh``),
    then falls back to pytesseract, and finally returns an empty string
    if neither is available.
    """
    temp_path: str | None = None
    try:
        _, temp_path_maybe = _load_image(image_path_or_url)
        # We need a file path for both backends.
        file_path = temp_path_maybe or image_path_or_url
        temp_path = temp_path_maybe

        # --- Try EasyOCR ---
        try:
            import easyocr  # noqa: lazy

            reader = easyocr.Reader(["en", "ru", "ar", "ch_sim"], gpu=False, verbose=False)
            results = reader.readtext(file_path, detail=0)
            text = "\n".join(results).strip()
            if text:
                return text
        except ImportError:
            logger.debug("easyocr not available, trying pytesseract.")
        except Exception as exc:
            logger.warning("easyocr failed: %s; trying pytesseract.", exc)

        # --- Try pytesseract ---
        try:
            from PIL import Image  # noqa: lazy
            import pytesseract  # noqa: lazy

            img = Image.open(file_path)
            text = pytesseract.image_to_string(img).strip()
            return text
        except ImportError:
            logger.debug("pytesseract not available; OCR unavailable.")
        except Exception as exc:
            logger.warning("pytesseract failed: %s", exc)

        return ""

    except ImportError:
        logger.warning("Pillow is not installed; OCR helper cannot load image.")
        return ""
    except Exception as exc:
        logger.error("OCR extraction failed for %s: %s", image_path_or_url, exc)
        return ""
    finally:
        _cleanup_temp(temp_path)


# ---------------------------------------------------------------------------
# 3. Error-Level Analysis (ELA)
# ---------------------------------------------------------------------------

def error_level_analysis(image_path_or_url: str) -> dict:
    """Perform basic JPEG error-level analysis for manipulation detection.

    Re-saves the image as JPEG at quality 95, computes the pixel-wise
    absolute difference with the original, and returns summary statistics.
    High mean/max error can indicate spliced or retouched regions.
    """
    temp_path: str | None = None
    try:
        from PIL import Image  # noqa: lazy
        import numpy as np  # noqa: lazy

        img, temp_path = _load_image(image_path_or_url)
        original = img.convert("RGB")

        # Re-save at quality 95 into an in-memory buffer.
        buf = io.BytesIO()
        original.save(buf, format="JPEG", quality=95)
        buf.seek(0)
        resaved = Image.open(buf).convert("RGB")

        orig_arr = np.array(original, dtype=np.float64)
        resaved_arr = np.array(resaved, dtype=np.float64)

        diff = np.abs(orig_arr - resaved_arr)

        mean_error = float(np.mean(diff))
        max_error = float(np.max(diff))
        suspicious = mean_error > _ELA_MEAN_THRESHOLD

        if suspicious:
            summary = (
                f"Mean pixel error {mean_error:.2f} exceeds threshold "
                f"({_ELA_MEAN_THRESHOLD}); possible manipulation detected."
            )
        else:
            summary = (
                f"Mean pixel error {mean_error:.2f} is within normal range; "
                "no obvious signs of manipulation."
            )

        return {
            "mean_error": round(mean_error, 4),
            "max_error": round(max_error, 4),
            "suspicious": suspicious,
            "ela_summary": summary,
        }

    except ImportError as exc:
        logger.warning("ELA unavailable (missing dependency): %s", exc)
        return {
            "mean_error": 0.0,
            "max_error": 0.0,
            "suspicious": False,
            "ela_summary": "ELA unavailable: missing Pillow or numpy.",
        }
    except Exception as exc:
        logger.error("ELA failed for %s: %s", image_path_or_url, exc)
        return {
            "mean_error": 0.0,
            "max_error": 0.0,
            "suspicious": False,
            "ela_summary": f"ELA error: {exc}",
        }
    finally:
        _cleanup_temp(temp_path)


# ---------------------------------------------------------------------------
# 4. CLIP zero-shot object classification
# ---------------------------------------------------------------------------

def detect_objects_clip(
    image_path_or_url: str,
    labels: list[str] | None = None,
) -> list[dict]:
    """Run CLIP zero-shot image classification against a set of labels.

    Returns a list of ``{"label": str, "confidence": float}`` dicts
    sorted by confidence descending.  If the ``transformers`` library is
    not installed, returns an empty list with a warning.
    """
    if labels is None:
        labels = DEFAULT_CLIP_LABELS

    temp_path: str | None = None
    try:
        from PIL import Image  # noqa: lazy

        img, temp_path = _load_image(image_path_or_url)
        img = img.convert("RGB")

        try:
            from transformers import CLIPModel, CLIPProcessor  # noqa: lazy
            import torch  # noqa: lazy
        except ImportError:
            logger.warning(
                "transformers/torch not installed; CLIP classification unavailable."
            )
            return []

        model_name = "openai/clip-vit-base-patch32"
        # Cache model as module-level singleton to avoid reloading per call
        global _clip_model, _clip_processor
        if "_clip_model" not in globals() or _clip_model is None:
            _clip_processor = CLIPProcessor.from_pretrained(model_name)
            _clip_model = CLIPModel.from_pretrained(model_name)
        processor = _clip_processor
        model = _clip_model

        inputs = processor(text=labels, images=img, return_tensors="pt", padding=True)

        with torch.no_grad():
            outputs = model(**inputs)

        # Normalised cosine similarities -> softmax probabilities.
        logits_per_image = outputs.logits_per_image  # shape (1, num_labels)
        probs = logits_per_image.softmax(dim=1).squeeze(0).tolist()

        results = [
            {"label": lbl, "confidence": round(conf, 4)}
            for lbl, conf in zip(labels, probs)
        ]
        results.sort(key=lambda r: r["confidence"], reverse=True)
        return results

    except ImportError:
        logger.warning("Pillow not installed; CLIP classification unavailable.")
        return []
    except Exception as exc:
        logger.error("CLIP detection failed for %s: %s", image_path_or_url, exc)
        return []
    finally:
        _cleanup_temp(temp_path)


# ---------------------------------------------------------------------------
# 5. Combined analysis
# ---------------------------------------------------------------------------

def analyze_image(image_path_or_url: str) -> dict:
    """Run all IMINT analyses on a single image and return combined results.

    Individual analysis failures are caught and logged; the corresponding
    key in the result dict will contain the fallback/empty value.
    """
    result: dict = {
        "source": image_path_or_url,
        "exif": None,
        "ocr_text": "",
        "ela": {},
        "clip_labels": [],
    }

    try:
        result["exif"] = extract_exif(image_path_or_url)
    except Exception as exc:
        logger.error("analyze_image: EXIF failed: %s", exc)

    try:
        result["ocr_text"] = extract_text_ocr(image_path_or_url)
    except Exception as exc:
        logger.error("analyze_image: OCR failed: %s", exc)

    try:
        result["ela"] = error_level_analysis(image_path_or_url)
    except Exception as exc:
        logger.error("analyze_image: ELA failed: %s", exc)

    try:
        result["clip_labels"] = detect_objects_clip(image_path_or_url)
    except Exception as exc:
        logger.error("analyze_image: CLIP failed: %s", exc)

    return result


# ---------------------------------------------------------------------------
# 6. Pipeline integration: process media from a raw item
# ---------------------------------------------------------------------------

_IMAGE_URL_PATTERN = re.compile(
    r'https?://[^\s"\'<>]+\.(?:' + "|".join(ext.lstrip(".") for ext in _IMAGE_EXTENSIONS) + r")(?:\?[^\s\"'<>]*)?",
    re.IGNORECASE,
)


def _find_image_urls(item) -> list[str]:
    """Return image URLs found in a RawItem's url and content fields."""
    urls: list[str] = []

    # Check if the item URL itself is an image.
    if item.url:
        suffix = Path(item.url.split("?")[0]).suffix.lower()
        if suffix in _IMAGE_EXTENSIONS:
            urls.append(item.url)

    # Scan content for embedded image URLs.
    if item.content:
        for match in _IMAGE_URL_PATTERN.finditer(item.content):
            url = match.group(0)
            if url not in urls:
                urls.append(url)

    return urls


def process_media_item(session: Session, item_id: int) -> dict | None:
    """Process media (images) attached to or referenced by a raw item.

    Looks up the :class:`~osint_monitor.core.database.RawItem` by *item_id*,
    discovers image URLs in its ``url`` and ``content`` fields, runs
    :func:`analyze_image` on each, and logs the results.  Returns a dict
    mapping each image URL to its analysis result, or ``None`` if no
    images were found.
    """
    from osint_monitor.core.database import RawItem  # noqa: lazy / avoid circular

    item = session.get(RawItem, item_id)
    if item is None:
        logger.warning("process_media_item: RawItem %d not found.", item_id)
        return None

    image_urls = _find_image_urls(item)
    if not image_urls:
        logger.debug("process_media_item: no images found in item %d.", item_id)
        return None

    results: dict = {}
    for url in image_urls:
        logger.info("IMINT: analysing image %s (item %d)", url, item_id)
        try:
            analysis = analyze_image(url)
            results[url] = analysis
        except Exception as exc:
            logger.error("IMINT: failed to analyse %s: %s", url, exc)
            results[url] = {"error": str(exc)}

    # Log a summary for the item.
    logger.info(
        "IMINT: processed %d image(s) for item %d: %s",
        len(results),
        item_id,
        json.dumps(
            {u: {"exif_gps": r.get("exif", {}).get("gps") if isinstance(r.get("exif"), dict) else None}
             for u, r in results.items()},
            default=str,
        ),
    )

    return results
