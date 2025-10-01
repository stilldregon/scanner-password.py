# scanner_segreti.py
# Uso: python3 scanner_segreti.py <github-token> [username_or_org]
import sys
import re
import base64
from math import log2
from github import Github

# Calcola entropia di Shannon di una stringa
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c)/len(s) for c in set(s)]
    return -sum(p * log2(p) for p in probs)

# Pattern semplici per possibili segreti (esempi)
KEYWORDS = [
    r'password', r'pass', r'passwd', r'api[_-]?key', r'token', r'secret',
    r'aws_access_key_id', r'aws_secret_access_key', r'client_secret'
]
COMPILED_KEYWORDS = re.compile('|'.join(KEYWORDS), re.IGNORECASE)

# Pattern per stringhe sospette (base64/hex/alphanum lunghe)
SUSPICIOUS_STRING = re.compile(r'([A-Za-z0-9+/]{20,}|[A-Fa-f0-9]{20,})')

MAX_FILE_SIZE = 100 * 1024  # ignora file > 100 KB

def scan_repo(repo):
    findings = []
    try:
        contents = repo.get_contents("")
    except Exception as e:
        print(f"Errore ottenendo contents di {repo.full_name}: {e}")
        return findings

    stack = contents[:]
    while stack:
        file = stack.pop()
        if file.type == "dir":
            stack.extend(repo.get_contents(file.path))
        elif file.type == "file":
            if file.size > MAX_FILE_SIZE:
                continue
            try:
                blob = repo.get_contents(file.path)
                raw = base64.b64decode(blob.content).decode('utf-8', errors='ignore')
            except Exception:
                continue

            for i, line in enumerate(raw.splitlines(), start=1):
                if COMPILED_KEYWORDS.search(line) or SUSPICIOUS_STRING.search(line):
                    # Estrai possibili token candidates
                    candidates = SUSPICIOUS_STRING.findall(line)
                    for cand in candidates:
                        ent = shannon_entropy(cand)
                        if ent >= 4.0 or COMPILED_KEYWORDS.search(line):
                            findings.append({
                                "repo": repo.full_name,
                                "file": file.path,
                                "line_no": i,
                                "line_preview": line.strip()[:300],
                                "candidate": cand,
                                "entropy": round(ent, 2)
                            })
    return findings

def main():
    if len(sys.argv) < 3:
        print("Uso: python3 scanner_segreti.py <github-token> <username_or_org>")
        sys.exit(1)
    token = sys.argv[1]
    target = sys.argv[2]

    g = Github(token)
    try:
        user = g.get_user(target)
    except Exception:
        user = g.get_organization(target)

    print(f"Scanning repositories di {target}...")
    all_findings = []
    for repo in user.get_repos():
        print(" >", repo.full_name)
        f = scan_repo(repo)
        all_findings.extend(f)

    print("\n--- Risultati ---")
    for item in all_findings:
        print(f"{item['repo']}:{item['file']} (line {item['line_no']}) entropy={item['entropy']}")
        print("  preview:", item['line_preview'])
        print("  candidate:", item['candidate'])
        print()

    print(f"Totale segnalazioni: {len(all_findings)}")

if __name__ == "__main__":
    main()
