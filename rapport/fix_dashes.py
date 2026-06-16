import os
import glob
import re

tex_files = glob.glob(
    "a:/USER/Downloads/devsecops-policy-service-main/devsecops-policy-service-main/rapport/**/*.tex",
    recursive=True,
)

for file in tex_files:
    with open(file, "r", encoding="utf-8") as f:
        content = f.read()

    original = content

    content = content.replace(" --- ", ", ")
    content = content.replace("--- ", ", ")
    content = content.replace(" — ", ", ")
    content = content.replace("— ", ", ")
    content = content.replace("—", ",")

    content = content.replace("& , &", "& --- &")

    if content != original:
        with open(file, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Updated {file}")
