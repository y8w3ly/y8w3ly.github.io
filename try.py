from PIL import Image
import os

# Path to source image
source_image = "avatar.png"

# Output directory
output_dir = "./_site/assets/img/favicons"
os.makedirs(output_dir, exist_ok=True)

# Desired output sizes and filenames
icons = {
    "android-chrome-192x192.png": (192, 192),
    "android-chrome-512x512.png": (512, 512),
    "apple-touch-icon.png": (180, 180),
    "favicon-16x16.png": (16, 16),
    "favicon-32x32.png": (32, 32),
    "mstile-150x150.png": (150, 150),
    "favicon.ico": [(16, 16), (32, 32), (48, 48)]  # .ico can hold multiple sizes
}

# Load the source image
img = Image.open(source_image)

# Create PNG files
for filename, size in icons.items():
    out_path = os.path.join(output_dir, filename)
    if filename.endswith(".ico"):
        # For favicon.ico with multiple sizes
        img.save(out_path, format="ICO", sizes=size)
    else:
        resized = img.resize(size, Image.LANCZOS)
        resized.save(out_path, format="PNG")

print("All favicon files generated in:", output_dir)
