"""
Desktop icon generator for NetGuard (one-off tool, safe to re-run).

Converts the brand mark (netguard-winning-mark-512.png) into a multi-size
Windows .ico for the splash window and the PyInstaller bundle.

Output: backend/assets/app.ico (16..256px, Windows multi-size)
Requires: backend venv with Pillow (pip install pillow)
"""
import os

from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root
SRC = os.path.join(ROOT, "netguard-winning-mark-512.png")
OUT_DIR = os.path.join(ROOT, "backend", "assets")
os.makedirs(OUT_DIR, exist_ok=True)

TILE = (10, 10, 11, 255)  # #0A0A0B

img = Image.open(SRC).convert("RGBA")
size = 512
tile = Image.new("RGBA", (size, size), TILE)
w, h = img.size
tile.paste(img, ((size - w) // 2, (size - h) // 2), img)

out_path = os.path.join(OUT_DIR, "app.ico")
tile.save(out_path, format="ICO", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("WROTE", out_path)
