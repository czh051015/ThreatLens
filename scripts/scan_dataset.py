import json
from collections import Counter

files = {
    'Execution':          'edr/data/telemetry/empire_launcher_vbs_2020-09-04160940.json',
    'CredentialAccess':   'edr/data/telemetry/empire_mimikatz_logonpasswords_2020-08-07103224.json',
    'Discovery':          'edr/data/telemetry/cmd_seatbelt_group_user_2020-11-0216391814.json',
    'LateralMovement':    'edr/data/telemetry/covenant_copy_smb_CreateRequest_2020-09-22145302.json',
}
kws = ['mimikatz', 'procdump', 'lsass', 'powershell', 'seatbelt',
       'copy', 'smb', 'wscript', 'cscript', 'net.exe', 'net1']

for label, rel in files.items():
    n = 0
    hits = Counter()
    with open(rel, encoding='utf-8') as f:
        for line in f:
            try:
                o = json.loads(line)
            except Exception:
                continue
            n += 1
            cmd = (o.get('CommandLine') or o.get('command_line') or '')
            img = (o.get('Image') or o.get('process_name') or '')
            blob = (cmd + ' ' + img).lower()
            for k in kws:
                if k in blob:
                    hits[k] += 1
    top = hits.most_common(4)
    print(f'[{label}] 事件数={n}  命中关键词 Top: {top}')
