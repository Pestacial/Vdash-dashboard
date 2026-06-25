python3 << 'EOF'
import json

with open('/home/pasta/trivy-opensilex-only.json') as f:
    data = json.load(f)

rows = ''
for result in data.get('Results', []):
    target = result.get('Target', '')                                                                                         vulns = result.get('Vulnerabilities') or []
    for v in vulns:
        sev = v.get('Severity', 'UNKNOWN')
        rows += f"<tr><td class='{sev}'>{sev}</td><td>{v.get('VulnerabilityID','')}</td><td>{v.get('PkgName','')} ({v.get('InstalledVersion','')})</td><td>{v.get('Title','')}</td></tr>\n"

html = """<html><head><style>
table { border-collapse: collapse; width: 100%; font-family: sans-serif; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; }
.CRITICAL { color: red; font-weight: bold; }
.HIGH { color: orange; font-weight: bold; }
.MEDIUM { color: blue; }
.LOW { color: gray; }
</style></head><body>
<h1>Trivy Vulnerability Report: OpenSILEX</h1>
<table><tr><th>Severity</th><th>ID</th><th>Package</th><th>Title</th></tr>
""" + rows + "</table></body></html>"

with open('/home/pasta/trivy-opensilex-report.html', 'w') as f:                                                     <....
Traceback (most recent call last):
  File "<stdin>", line 27, in <module>
PermissionError: [Errno 13] Permission denied: '/home/pasta/trivy-opensilex-report.html'

┌──(pasta㉿kali)-[~]
└─$ sudo rm -f /home/pasta/trivy-opensilex-report.html

┌──(pasta㉿kali)-[~]
└─$ >....

rows = ''
for result in data.get('Results', []):
    target = result.get('Target', '')
    vulns = result.get('Vulnerabilities') or []
    for v in vulns:
        sev = v.get('Severity', 'UNKNOWN')
        rows += f"<tr><td class='{sev}'>{sev}</td><td>{v.get('VulnerabilityID','')}</td><td>{v.get('PkgName','')} ({v.get('InstalledVersion','')})</td><td>{v.get('Title','')}</td></tr>\n"

html = """<html><head><style>
table { border-collapse: collapse; width: 100%; font-family: sans-serif; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; }
.CRITICAL { color: red; font-weight: bold; }
.HIGH { color: orange; font-weight: bold; }
.MEDIUM { color: blue; }
.LOW { color: gray; }
</style></head><body>
<h1>Trivy Vulnerability Report: OpenSILEX</h1>
<table><tr><th>Severity</th><th>ID</th><th>Package</th><th>Title</th></tr>
""" + rows + "</table></body></html>"

with open('/home/pasta/trivy-opensilex-report.html', 'w') as f:
    f.write(html)

print("Done!")
EOF
Done!