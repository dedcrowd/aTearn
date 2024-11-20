
> [!WARNING]
> aTearn.py is intended for educational and ethical hacking purposes only. Use it responsibly and only on systems you own or have explicit permission to test. Unauthorized use is illegal and unethical.

<div align="center">
   <a href="https://github.com/hunthack3r/aTearn"><img src="https://media.giphy.com/media/3og0ILLVvPp8d64Jd6/giphy.gif?cid=790b7611udpkaea137z4qwwjsr2xwp2rr6o53qubl7djkbo1&ep=v1_gifs_search&rid=giphy.gif&ct=g" height="225" width="450" align="center"/></a>
</div>

<br>
<br>
<br>

<div align="center">
   
|**aTearn.py**|Automated Recon and Exploitation Framework|
|-------------|------------------------------------------|
| Built for Bug Bounty Hunters | Streamlined for Speed | Designed for Professionals |

> **aTearn.py** automates the essential stages of bug bounty and pentesting, integrating powerful tools like **Subfinder**, **Katana**, and **Gau** into a cohesive framework. <br><br> *`Made by`* - [`hunthack3r`](https://github.com/hunthack3r)!

</div>

<hr>

<br>
<br>
<br>

## 🚀 **Features**

| Functionality                | Description                                                                      |
|------------------------------|----------------------------------------------------------------------------------|
| **Subdomain Discovery**      | Finds subdomains using tools like Subfinder and Assetfinder.                     |
| **HTTP Probing**             | Filters live subdomains with Httpx Toolkit.                                      |
| **URL Scraping**             | Collects URLs with tools like Gau, Katana, and Waymore.                          |
| **Vulnerability Patterns**   | Identifies XSS, SQLi, SSRF, LFI, and more using custom patterns.                 |
| **JS Analysis**              | Detects secrets and misconfigurations in JavaScript files.                       |
| **Multi-threaded Scanning**  | Uses threading for faster execution and better performance.                      |
| **Customizable Payloads**    | Supports custom payload files for specific targets.                              |
| **Automated Output Handling**| Dynamically stores outputs in user-specified directories.                        |

---

## 🛠️ **Installation**

### Clone the repository
```bash
git clone https://github.com/hunthack3r/aTearn.git
cd aTearn


# A-TEARN

## Installation

```bash
git clone https://github.com/hunthack3r/aTearn.git
cd aTearn
```

### Install dependencies

```bash
pip install -r requirements.txt
```

## 💻 Usage

### Input Options

#### Provide a single domain using `echo`:

```bash
echo "apple.com" | python3 aTearn.py -o output_dir/
```

#### Provide multiple domains using `cat`:

```bash
cat domains.txt | python3 aTearn.py -o output_dir/
```

#### Specify a file directly:

```bash
python3 aTearn.py -d domains.txt -o output_dir/
```

### Customizing Output

#### Specify an output directory with the `-o` flag:

```bash
python3 aTearn.py -d domains.txt -o /Desktop/my_results/
```

## 📂 Outputs

All results are dynamically saved to your specified output directory:

- `Subs.txt`: Discovered subdomains.
- `subdomains_alive.txt`: Live subdomains.
- `allurls.txt`: Collected URLs.
- `secrets.txt`: Detected secrets in JavaScript files.
- `params.txt`: Parameters identified via Paramspider.
- Vulnerabilities like SQLi, XSS, and SSRF saved in separate files.

## 📖 Workflow

| Step                     | Command                                                                 |
|--------------------------|-------------------------------------------------------------------------|
| Subdomain Enumeration    | Runs Subfinder and Assetfinder to find subdomains.                     |
| Live Subdomain Filtering | Probes subdomains with Httpx Toolkit.                                  |
| URL Scraping             | Scrapes URLs using Gau and Katana.                                     |
| Vulnerability Scanning   | Detects issues like XSS, SQLi, SSRF, and more with GF patterns.        |
| JS File Analysis         | Analyzes JavaScript files for secrets and misconfigurations using Nuclei. |

## ✨ Tags

#bugbounty #pentesting #automation #xss #sqli #lfi #ssrf #cybersecurity #infosec #recon #hacking #osint #ethicalhacking #gfpatterns #nuclei #dalfox #automationtools #hacker

## 📥 Download

Get aTearn.py [here](https://github.com/hunthack3r/aTearn)

## 📷 Screenshots

### Sample Workflow

```
[✓] Subdomain: subdomain.example.com
[✓] Alive URL: https://subdomain.example.com
[✓] Vulnerable URL Found: https://example.com/test?param=payload
```
