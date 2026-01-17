from PIL import Image
import os

source_path = r"c:\Users\bruno_i1sa\OneDrive\Bureau\extension\lucid-origin_A_modern_cybersecurity_browser_extension_logo._Dark_theme_minimalist_style._A_st-0.jpg"
output_dir = r"c:\Users\bruno_i1sa\OneDrive\Bureau\extension\public\icons"

if not os.path.exists(output_dir):
    os.makedirs(output_dir)

sizes = [16, 48, 128]

try:
    with Image.open(source_path) as img:
        for size in sizes:
            resized_img = img.resize((size, size), Image.Resampling.LANCZOS)
            output_path = os.path.join(output_dir, f"icon{size}.png")
            resized_img.save(output_path, "PNG")
            print(f"Saved {output_path}")
except Exception as e:
    print(f"Error: {e}")
