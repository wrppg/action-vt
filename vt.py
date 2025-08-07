import vt
import asyncio
import argparse
import sys
import select
import logging

async def scan_url(apikey, url):
    async with vt.Client(apikey) as client:
        try:
            # Submit URL for scanning with wait_for_completion.
            # Returns a vt.Object of analysis type, per vt.Client.scan_url_async documentation.
            analysis = await client.scan_url_async(url, wait_for_completion=True)
            print(f"URL scan completed for {url}. Analysis ID: {analysis.id}")

            # Get the URL object using the URL ID.
            # Returns a vt.Object of URL type, per vt.Client.get_object_async documentation.
            url_id = vt.url_id(url)
            url_obj = await client.get_object_async(f"/urls/{url_id}")

            # Check for last_http_response_content_sha256 attribute.
            # Using hasattr as a safe way to check for attribute existence,
            # equivalent to url_obj.get("last_http_response_content_sha256", None)
            # as described in vt.Object documentation.
            if hasattr(url_obj, "last_http_response_content_sha256"):
                sha256 = url_obj.last_http_response_content_sha256
                print(f"last_http_response_content_sha256 for {url}: {sha256}")

                # Send POST request to /files/{id}/analyse to trigger file reanalysis, no headers
                response = await client.post_async(f"/files/{sha256}/analyse")
                response_obj = await response.json_async()  # Use json_async for async context
                print(f"File reanalysis triggered for {url}. Response: {response_obj}")
            else:
                print(f"last_http_response_content_sha256 not available for {url}.")

        except vt.error.APIError as e:
            print(f"Error for {url}: {e}")

async def scan_multiple_urls(apikey, urls):
    # Create tasks for scanning each URL concurrently
    tasks = [scan_url(apikey, url) for url in urls]
    # Run tasks concurrently and wait for all to complete
    await asyncio.gather(*tasks, return_exceptions=True)

def main():
    logger.info("logger")
    print("print")
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Scan URLs from stdin or --url using VirusTotal API, retrieve last_http_response_content_sha256, and trigger file reanalysis.")
    parser.add_argument("--apikey", required=True, help="VirusTotal API key")
    parser.add_argument("--url", required=False, help="Single URL to scan")
    args = parser.parse_args()

    # Determine URLs to process
    urls = []
    if args.url:
        urls = [args.url]
    else:
        # Check if stdin has data without blocking
        if select.select([sys.stdin], [], [], 0.0)[0]:
            urls = [line.strip() for line in sys.stdin if line.strip()]
        if not urls:
            print("Error: No URLs provided via --url or stdin.")
            sys.exit(1)

    # Run the async scan for all URLs
    asyncio.run(scan_multiple_urls(args.apikey, urls))

if __name__ == "__main__":
    main()
