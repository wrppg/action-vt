import vt
import asyncio
import argparse
import aiohttp
import json
import re
import os.path
import sys

def get_only_arm64(tup):
    filters = ["arm64", "-v8a", "armv8", "arm-64"]
    r = []
    for url, flag in tup:
        for arm_64 in filters:
            if arm_64 in url.lower():
                r.apepnd((url, flag))
        if len(r) > 0:
            return r
    return tup

def filter_out_x86(tup):
    return [item for item in tup if not re.search(r'[^a-zA-Z](x86|x64)[^a-zA-Z]', item[0].lower())]
    
async def fetch_github_assets(github_url, gh_token):
    headers = {"Authorization": f"Bearer {gh_token}"} if gh_token else None
    async with aiohttp.ClientSession(headers=headers) as session:
        try:
            async with session.get(github_url) as response:
                if response.status != 200:
                    print(f"Error fetching GitHub assets from {github_url}: HTTP {response.status}")
                    return []
                data = await response.json()
                if not isinstance(data, list):
                    print(f"Error: Response from {github_url} is not an array.")
                    return []
                # Extract browser_download_url and size, filter for .apk/.apks 33553688 Byte
                return [
                    (item["browser_download_url"], int(item.get("size", 0)) <= 33.5 * 1000 * 1000)
                    for item in data
                    if item.get("browser_download_url", "").lower().endswith((".apk", ".apks", ".eapk"))
                ]
        except Exception as e:
            print(f"Error fetching GitHub assets from {github_url}: {e}")
            return []

async def scan_url(apikey, url, is_small_apk):
    async with vt.Client(apikey) as client:
        try:
            # Submit URL for scanning, wait_for_completion depends on is_small_apk
            analysis = await client.scan_url_async(url, wait_for_completion=not is_small_apk)
            print(f"URL scan completed for {url} Analysis ID: {analysis.id}")
            
            if not is_small_apk:
              # Get the URL object using the URL ID
              url_id = vt.url_id(url)
              url_obj = await client.get_object_async(f"/urls/{url_id}")
  
              # Check for last_http_response_content_sha256 attribute
              if hasattr(url_obj, "last_http_response_content_sha256"):
                  sha256 = url_obj.last_http_response_content_sha256
                  print(f"last_http_response_content_sha256 for {os.path.basename(url)}: {sha256}")
                  
                  print(f"File reanalysis triggered for {os.path.basename(url)} .")
                  response = await client.post_async(f"/files/{sha256}/analyse")
                  # response_obj = await response.json_async()
                  # print(f"File reanalysis triggered for {os.path.basename(url)} Response: {response_obj.data.id}")
              else:
                  print(f"last_http_response_content_sha256 not available for {url}")

        except vt.error.APIError as e:
            print(f"Error for {url}: {e}")

async def scan_multiple_urls(apikey, urls_with_flags):
    # Create tasks for scanning each URL concurrently, passing is_small_apk flag
    tasks = [scan_url(apikey, url, is_small_apk) for url, is_small_apk in urls_with_flags]
    await asyncio.gather(*tasks, return_exceptions=True)

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Scan URLs from GitHub API using VirusTotal API, retrieve last_http_response_content_sha256, and trigger file reanalysis for non-APK or large APKs.")
    parser.add_argument("--apikey", required=True, help="VirusTotal API key")
    parser.add_argument("--url", required=True, help="GitHub API URL (e.g., https://api.github.com/repos/OWNER/REPO/releases/RELEASE_ID/assets)")
    parser.add_argument("--gh_token", required=False, help="GitHub Token")
    args = parser.parse_args()

    # Determine URLs to process
    urls_with_flags = []
    if not args.url.startswith("https://api.github.com/repos/"):
        print("Error: URL must be a GitHub API releases URL (e.g., https://api.github.com/repos/OWNER/REPO/releases/RELEASE_ID/assets)")
        sys.exit(1)
    # Fetch assets from GitHub API, with size-based flags
    urls_with_flags = asyncio.run(fetch_github_assets(args.url + '/assets', args.gh_token))
    urls_with_flags = get_only_arm64(urls_with_flags)
    urls_with_flags = filter_out_x86(urls_with_flags)
    print("These URLs will be process")
    print(*urls_with_flags, sep='\n')
    print("--------------------------------------------------------------------------------------")

    if not urls_with_flags:
        print("Error: No valid .apk or .apks URLs found in the GitHub API response.")
        sys.exit(0)

    # Run the async scan for all URLs
    asyncio.run(scan_multiple_urls(args.apikey, urls_with_flags))

if __name__ == "__main__":
    main()
