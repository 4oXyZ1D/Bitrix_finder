import asyncio
import aiohttp
from aiohttp import ClientSession, TCPConnector
from urllib.parse import urljoin
import csv
import argparse
import sys

async def is_bitrix(url: str, session: ClientSession, timeout=5):
    try:
        async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
            final_url = str(resp.url)
            content = await resp.text()
            cookies = resp.cookies
            headers = resp.headers

            if final_url.rstrip('/') != url.rstrip('/'):
                print(f"[!] {url} -> Redirected to {final_url}")
                return False, f"Redirected to {final_url}, skipping CMS check"

            if "x-powered-cms" in headers and "bitrix" in headers["x-powered-cms"].lower():
                return True, "Bitrix found in X-Powered-CMS header"
            if "x-powered-by" in headers and "bitrix" in headers["x-powered-by"].lower():
                return True, "Bitrix found in X-Powered-By header"

            for cookie_name in cookies.keys():
                if cookie_name.upper().startswith("BITRIX_SM"):
                    return True, "BITRIX_SM cookie detected"

            if "/bitrix/" in content.lower() or "bitrix" in content.lower():
                return True, "Mention of '/bitrix/' in HTML"

            async with session.get(urljoin(url, "/bitrix/"), timeout=timeout) as bitrix_resp:
                text = await bitrix_resp.text()
                if bitrix_resp.status == 200 and "index of /bitrix" in text.lower():
                    return True, "Accessible /bitrix/ directory"

            async with session.get(urljoin(url, "/bitrix/admin/"), timeout=timeout) as admin_resp:
                text = await admin_resp.text()
                if "bitrix" in text.lower():
                    return True, "Admin panel detected"

    except Exception as e:
        return False, f"Request failed: {e}"

    return False, "No Bitrix indicators found"

async def main(domains):
    connector = TCPConnector(limit_per_host=5)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for domain in domains:
            if not domain.startswith("http"):
                domain = "https://" + domain
            task = asyncio.create_task(is_bitrix(domain, session))
            tasks.append((domain, task))

        results = []
        for domain, task in tasks:
            found, reason = await task
            if found:
                print(f"[+] {domain} -> Bitrix detected ({reason})")
                status = "Bitrix"
            else:
                print(f"[-] {domain} -> Not Bitrix ({reason})")
                status = "Not Bitrix"

            results.append({
                "domain": domain,
                "status": status,
                "details": reason
            })

        with open("bitrix_scan_results.csv", "w", newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["domain", "status", "details"])
            writer.writeheader()
            for row in results:
                writer.writerow(row)

def parse_args():
    parser = argparse.ArgumentParser(description="Bitrix CMS scanner for multiple domains.")
    parser.add_argument("--file", help="Path to file with list of domains (one per line).")
    parser.add_argument("--domains", help="Comma-separated list of domains to scan.")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()

    if not args.file and not args.domains:
        print("❗️ Please provide --file or --domains argument. Use --help for more info.")
        sys.exit(1)

    domains = []
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                domains = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Failed to read file: {e}")
            sys.exit(1)

    if args.domains:
        domains += [d.strip() for d in args.domains.split(",") if d.strip()]

    if not domains:
        print("❗️ No domains found to scan.")
        sys.exit(1)

    asyncio.run(main(domains))
