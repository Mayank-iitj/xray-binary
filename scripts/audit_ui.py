import re
import os
import subprocess
import tempfile

def audit_html(filepath):
    print(f"\n==========================================")
    print(f"AUDITING: {filepath}")
    print(f"==========================================")
    if not os.path.exists(filepath):
        print(f"ERROR: {filepath} not found!")
        return

    with open(filepath, "r", encoding="utf-8") as f:
        html = f.read()

    # 1. Check all inline <script> tags for syntax errors
    pattern = r"<script([^>]*)>(.*?)</script>"
    scripts = re.findall(pattern, html, re.DOTALL)
    print(f"Found {len(scripts)} inline script tag(s).")
    for i, (attrs, code) in enumerate(scripts):
        if not code.strip():
            continue
        is_module = 'type="module"' in attrs or "type='module'" in attrs
        suffix = ".mjs" if is_module else ".js"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False, mode="w", encoding="utf-8") as tmp:
            tmp.write(code)
            tmp_name = tmp.name

        proc = subprocess.run(["node", "--check", tmp_name], capture_output=True, text=True)
        if proc.returncode != 0:
            print(f"[!] SCRIPT {i} ({'module' if is_module else 'standard'}) SYNTAX ERROR:")
            print(proc.stderr)
        else:
            print(f"[✓] Script {i} ({'module' if is_module else 'standard'}): Syntax VALID ({len(code)} bytes)")
        try:
            os.remove(tmp_name)
        except:
            pass

    # 2. Check for missing element IDs referenced in JS
    id_refs = re.findall(r"getElementById\(['\"]([^'\"]+)['\"]\)", html)
    id_refs += re.findall(r"querySelector\(['\"]#([a-zA-Z0-9_-]+)['\"]\)", html)
    unique_refs = sorted(list(set(id_refs)))
    print(f"\nChecking {len(unique_refs)} referenced DOM IDs...")
    missing_ids = []
    for elem_id in unique_refs:
        # Check if id="elem_id" exists in html
        if not re.search(rf'id=[\'\"]{re.escape(elem_id)}[\'\"]', html):
            missing_ids.append(elem_id)
    if missing_ids:
        print(f"[!] WARNING: The following {len(missing_ids)} ID(s) are referenced in JS but NOT found in HTML:")
        for m in missing_ids:
            print(f"    - {m}")
    else:
        print(f"[✓] All {len(unique_refs)} referenced DOM IDs exist in HTML!")

    # 3. Check for onclick/onchange/onmouseover handlers calling undefined functions
    handlers = re.findall(r'on[a-z]+="([^"]+)"', html)
    print(f"\nFound {len(handlers)} inline event handlers.")
    # Extract function names like foo()
    fn_calls = set()
    for h in handlers:
        calls = re.findall(r'([a-zA-Z0-9_]+)\(', h)
        for c in calls:
            if c not in ('this', 'event', 'console', 'Math', 'alert', 'confirm', 'parseInt', 'parseFloat', 'String', 'Number'):
                fn_calls.add(c)
    print(f"Functions called in event handlers: {sorted(list(fn_calls))}")
    for fn in sorted(list(fn_calls)):
        if not re.search(rf'function\s+{re.escape(fn)}\b|window\.{re.escape(fn)}\s*=|const\s+{re.escape(fn)}\s*=\s*(?:function|\()|let\s+{re.escape(fn)}\s*=\s*(?:function|\()|var\s+{re.escape(fn)}\s*=\s*(?:function|\()', html):
            print(f"[!] POTENTIALLY UNDEFINED FUNCTION CALLED: {fn}")
        else:
            print(f"[✓] Function defined: {fn}")

    # 4. Check broken images
    imgs = re.findall(r'<img[^>]+src=[\'\"]([^\'\"]+)[\'\"]', html)
    print(f"\nFound {len(imgs)} <img> tags.")
    for src in imgs:
        if src.startswith("http") or src.startswith("data:"):
            continue
        # Local file
        local_path = os.path.join(os.path.dirname(filepath), src.lstrip("/"))
        if not os.path.exists(local_path):
            print(f"[!] MISSING LOCAL IMAGE: {src} (checked {local_path})")
        else:
            print(f"[✓] Local image exists: {src}")

if __name__ == "__main__":
    audit_html("apps/web/landing.html")
    audit_html("apps/web/index.html")
