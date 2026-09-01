# 攻击链分析报告（自动生成，mock）

## 摘要
共识别 13 个技术，覆盖 4 个战术阶段

## 攻击链详情
### T1059.005 — Visual Basic
- 战术: execution
- 首次出现: 2020-09-04T20:09:55.953000Z
- 证据:
  - `empire_launcher_vbs_2020-09-04160940.json:73`
  - `empire_launcher_vbs_2020-09-04160940.json:77`
  - `empire_launcher_vbs_2020-09-04160940.json:78`
  - `empire_launcher_vbs_2020-09-04160940.json:79`
  - `empire_launcher_vbs_2020-09-04160940.json:81`

### T1059.001 — PowerShell
- 战术: execution
- 首次出现: 2020-09-04T20:09:57.060000Z
- 证据:
  - `empire_launcher_vbs_2020-09-04160940.json:259`
  - `empire_launcher_vbs_2020-09-04160940.json:328`
  - `empire_launcher_vbs_2020-09-04160940.json:918`

### T1003.001 — LSASS Memory
- 战术: credential-access
- 首次出现: 2020-08-07T14:32:57.589000Z
- 证据:
  - `empire_mimikatz_logonpasswords_2020-08-07103224.json:2451`
  - `empire_mimikatz_logonpasswords_2020-08-07103224.json:2460`
  - `empire_mimikatz_logonpasswords_2020-08-07103224.json:2461`

### T1033 — System Owner/User Discovery
- 战术: discovery
- 首次出现: 2020-08-07T14:32:47.591000Z
- 证据:
  - `empire_launcher_vbs_2020-09-04160940.json:1820`
  - `empire_mimikatz_logonpasswords_2020-08-07103224.json:282`

### T1087.001 — Local Account
- 战术: discovery
- 首次出现: 2020-08-07T14:32:47.591000Z
- 证据:
  - `empire_launcher_vbs_2020-09-04160940.json:1820`
  - `empire_mimikatz_logonpasswords_2020-08-07103224.json:282`

### T1526 — Cloud Service Discovery
- 战术: discovery
- 首次出现: 2020-11-02T04:39:11.681000Z
- 证据:
  - `cmd_seatbelt_group_user_2020-11-0216391814.json:148`

### T1087 — Account Discovery
- 战术: discovery
- 首次出现: 2020-11-02T04:39:11.681000Z
- 证据:
  - `cmd_seatbelt_group_user_2020-11-0216391814.json:148`

### T1083 — File and Directory Discovery
- 战术: discovery
- 首次出现: 2020-11-02T04:39:11.681000Z
- 证据:
  - `cmd_seatbelt_group_user_2020-11-0216391814.json:148`

### T1021.002 — SMB/Windows Admin Shares
- 战术: lateral-movement
- 首次出现: 2020-09-22T18:53:32.342000Z
- 证据:
  - `covenant_copy_smb_CreateRequest_2020-09-22145302.json:62`

### T1531 — Account Access Removal
- 战术: impact
- 首次出现: 2020-08-07T14:32:29.370000Z
- 证据:
  - `empire_launcher_vbs_2020-09-04160940.json:18`
  - `empire_launcher_vbs_2020-09-04160940.json:2001`
  - `empire_mimikatz_logonpasswords_2020-08-07103224.json:31`
  - `empire_mimikatz_logonpasswords_2020-08-07103224.json:648`
  - `empire_mimikatz_logonpasswords_2020-08-07103224.json:651`

### T1055 — Process Injection
- 战术: defense-evasion
- 首次出现: 2020-08-07T14:32:47.604000Z
- 证据:
  - `empire_launcher_vbs_2020-09-04160940.json:328`
  - `empire_launcher_vbs_2020-09-04160940.json:343`
  - `empire_launcher_vbs_2020-09-04160940.json:1817`
  - `empire_mimikatz_logonpasswords_2020-08-07103224.json:303`
  - `empire_launcher_vbs_2020-09-04160940.json:247`

### T1112 — Modify Registry
- 战术: defense-evasion
- 首次出现: 2020-09-04T20:09:55.953000Z
- 证据:
  - `empire_launcher_vbs_2020-09-04160940.json:73`
  - `empire_launcher_vbs_2020-09-04160940.json:77`
  - `empire_launcher_vbs_2020-09-04160940.json:78`
  - `empire_launcher_vbs_2020-09-04160940.json:79`
  - `empire_launcher_vbs_2020-09-04160940.json:81`

### T1685 — Disable or Modify Tools
- 战术: defense-evasion
- 首次出现: 2020-09-04T20:10:00.327000Z
- 证据:
  - `empire_launcher_vbs_2020-09-04160940.json:918`

## 证据附录（原始事件 UID 列表）
cmd_seatbelt_group_user_2020-11-0216391814.json:148
covenant_copy_smb_CreateRequest_2020-09-22145302.json:62
empire_launcher_vbs_2020-09-04160940.json:18
empire_launcher_vbs_2020-09-04160940.json:1817
empire_launcher_vbs_2020-09-04160940.json:1820
empire_launcher_vbs_2020-09-04160940.json:2001
empire_launcher_vbs_2020-09-04160940.json:247
empire_launcher_vbs_2020-09-04160940.json:259
empire_launcher_vbs_2020-09-04160940.json:328
empire_launcher_vbs_2020-09-04160940.json:343
empire_launcher_vbs_2020-09-04160940.json:73
empire_launcher_vbs_2020-09-04160940.json:77
empire_launcher_vbs_2020-09-04160940.json:78
empire_launcher_vbs_2020-09-04160940.json:79
empire_launcher_vbs_2020-09-04160940.json:81
empire_launcher_vbs_2020-09-04160940.json:918
empire_mimikatz_logonpasswords_2020-08-07103224.json:2451
empire_mimikatz_logonpasswords_2020-08-07103224.json:2460
empire_mimikatz_logonpasswords_2020-08-07103224.json:2461
empire_mimikatz_logonpasswords_2020-08-07103224.json:282
empire_mimikatz_logonpasswords_2020-08-07103224.json:303
empire_mimikatz_logonpasswords_2020-08-07103224.json:31
empire_mimikatz_logonpasswords_2020-08-07103224.json:648
empire_mimikatz_logonpasswords_2020-08-07103224.json:651