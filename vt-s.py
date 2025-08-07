import vt
import argparse
import sys
import urllib.parse
import os

def scan_url(apikey, url):
    print(f"DEBUG: Entering scan_url for URL: {url}", flush=True)
    # Ensure URL has a scheme (default to https if none provided)
    parsed_url = urllib.parse.urlparse(url)
    if not parsed_url.scheme:
        url = f"https://{url}"
        print(f"DEBUG: Added https scheme to URL: {url}", flush=True)

    print(f"DEBUG: Using vt module from: {vt.__file__}", flush=True)
    print(f"DEBUG: Attempting to initialize VirusTotal client", flush=True)
    try:
        with vt.Client(apikey) as client:
            print(f"DEBUG: VirusTotal client initialized", flush=True)
            # Submit URL for scanning with wait_for_completion.
            print(f"DEBUG: Submitting {url} for scanning", flush=True)
            analysis = client.scan_url(url, wait_for_completion=True)
            print(f"URL scan completed. Analysis ID: {analysis.id}", flush=True)

            # Get the URL object using the URL ID.
            url_id = vt.url_id(url)
            print(f"DEBUG: Fetching URL object for ID: {url_id}", flush=True)
            url_obj = client.get_object(f"/urls/{url_id}")

            # Check for last_http_response_content_sha256 attribute.
            if hasattr(url_obj, "last_http_response_content_sha256"):
                sha256 = url_obj.last_http_response_content_sha256
                print(f"last_http_response_content_sha256: {sha256}", flush=True)

                # Send POST request to /files/{id}/analyse to trigger file reanalysis
                print(f"DEBUG: Triggering reanalysis for file: {sha256}", flush=True)
                response = client.post(f"/files/{sha256}/analyse")
                response_obj = response.json()
                print(f"File reanalysis triggered. Response: {response_obj}", flush=True)
                return True
            else:
                print(f"last_http_response_content_sha256 not available for {url}.", flush=True)
                return False

    except vt.error.APIError as e:
        print(f"Error for {url}: APIError: {e}", flush=True)
        return False
    except Exception as e:
        print(f"Error for {url}: Unexpected error: {e}", flush=True)
        return False

def main():
    os.environ["PYTHONUNBUFFERED"] = "1"
    print(f"DEBUG: Starting main function", flush=True)
    print(f"DEBUG: Python sys.path: {sys.path}", flush=True)

    parser = argparse.ArgumentParser(description="Scan a URL using VirusTotal API, retrieve last_http_response_content_sha256, and trigger file reanalysis.")
    parser.add_argument("--apikey", required=False, help="VirusTotal API key (or set VT_APIKEY env var)")
    parser.add_argument("--url", required=True, help="URL to scan")
    args = parser.parse_args()
    print(f"DEBUG: Parsed args: apikey={bool(args.apikey)}, url={args.url}", flush=True)

    apikey = args.apikey or os.getenv("VT_APIKEY")
    if not apikey:
        print("Error: API key missing (use --apikey or VT_APIKEY env var).", flush=True)
        sys.exit(1)
    print(f"DEBUG: API key found", flush=True)

    success = scan_url(apikey, args.url)
    if not success:
        print(f"Error: Failed to process {args.url} successfully.", flush=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
