import zipfile
import re

jar = 'tools/CICFlowMeter-4.0/lib/CICFlowMeter-4.0.jar'
with zipfile.ZipFile(jar) as z:
    names = z.namelist()
    for n in names:
        if n.endswith('.class') and ('Cmd' in n or 'App' in n):
            data = z.read(n)
            text = data.decode('latin1', 'ignore')
            if 'pcap' in text.lower() or 'args' in text.lower() or 'output' in text.lower() or 'help' in text.lower():
                print('CLASS', n)
                for line in text.splitlines():
                    if any(k in line.lower() for k in ['pcap', 'args', 'output', 'help', 'usage', 'option', 'file']):
                        print(line[:400])
                print('---')
