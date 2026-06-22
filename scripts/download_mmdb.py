import urllib.request
import os

url = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
out_path = os.path.join(os.path.dirname(__file__), "..", "data", "GeoLite2-Country.mmdb")

print(f"Downloading GeoLite2-Country.mmdb to {out_path} ...")
urllib.request.urlretrieve(url, out_path)
print("Download complete.")
