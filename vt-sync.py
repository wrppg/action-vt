import vt
import argparse
import sys

def scan_url(apikey, url):
    with vt.Client(apikey) as client:
        try:
            # Submit URL for scanning with wait_for_completion.
            # Returns a vt.Object of analysis type, per vt.Client.scan_url documentation.
            analysis = client.scan_url(url, wait_for_completion=True)
            print(f"URL scan completed. Analysis ID: {analysis.id}")

            # Get the URL object using the URL ID.
            # Returns a vt.Object of URL type, per vt.Client.get_object documentation.
            url_id = vt.url_id(url)
            url_obj = client.get_object(f"/urls/{url_id}")

            # Check for last_http_response_content_sha256 attribute.
            # Using hasattr as a safe way to check for attribute existence,
            # equivalent to url_obj.get("last_http_response_content_sha256", None)
            # as described in vt.Object documentation.
            if hasattr(url_obj, "last_http_response_content_sha256"):
                sha256 = url_obj.last_http_response_content_sha256
                print(f"last_http_response_content_sha256: {sha256}")

                # Send POST request to /files/{id}/analyse to trigger file reanalysis
                response = client.post(
                    f"/files/{sha256}/analyse",
                )
                response_obj = response.json()
                print(f"File reanalysis triggered. Response: {response_obj}")
            else:
                print("last_http_response_content_sha256 not available for this URL.")

        except vt.error.APIError as e:
            print(f"Error: {e}")
            sys.exit(1)

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Scan a URL using VirusTotal API, retrieve last_http_response_content_sha256, and trigger file reanalysis.")
    parser.add_argument("--apikey", required=True, help="VirusTotal API key")
    parser.add_argument("--url", required=True, help="URL to scan")
    args = parser.parse_args()

    # Run the scan
    scan_url(args.apikey, args.url)

if __name__ == "__main__":
    main()
