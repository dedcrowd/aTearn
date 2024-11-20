## ⚠️ Disclaimer

> [!WARNING]
> aTearn.py is intended for educational and ethical hacking purposes only. Use it responsibly and only on systems you own or have explicit permission to test. Unauthorized use is illegal and unethical.

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
