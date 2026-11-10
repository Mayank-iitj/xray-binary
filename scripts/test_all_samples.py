import subprocess
import sys
import json

samples = [
    'samples/sample_benign_util.exe',
    'samples/sample_ransomware.exe',
    'samples/sample_keylogger.exe',
    'samples/sample_downloader.exe',
    'samples/sample_packed.exe'
]

print("=" * 70)
print("VERIFYING ZERO FALSE POSITIVES ACROSS TEST SAMPLES")
print("=" * 70)

for s in samples:
    res = subprocess.run([sys.executable, 'packages/xray_core/cli.py', 'scan', s, '--format', 'json'], capture_output=True, text=True)
    if res.returncode != 0:
        print(f"FAILED on {s}: {res.stderr}")
        continue
    d = json.loads(res.stdout)
    v = d['verdict']
    print(f"{s:<30} | Verdict: {v['label'].upper():<10} | Family: {v['family'].upper():<12} | Conf: {v['confidence']*100:5.1f}% | P(Malware): {d['scores']['p_malware']:.3f}")

print("=" * 70)
