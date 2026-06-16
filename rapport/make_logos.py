from PIL import Image, ImageDraw, ImageFont

logos = [
    "terraform.png",
    "docker.png",
    "kubernetes.png",
    "checkov.png",
    "tfsec.png",
    "trivy.png",
    "opa.png",
]
for logo in logos:
    img = Image.new("RGB", (100, 100), color=(200, 200, 200))
    d = ImageDraw.Draw(img)
    d.text((10, 40), logo.split(".")[0], fill=(0, 0, 0))
    img.save(
        f"a:/USER/Downloads/devsecops-policy-service-main/devsecops-policy-service-main/rapport/images/{logo}"
    )
    print(f"Created {logo}")
