import requests
import time

def zap_scan(target_url):
    zap_url = 'http://localhost:8080'  # ZAP should be running at this URL
    scan_url = f'{zap_url}/JSON/ascan/action/scan/?url={target_url}&recurse=true'

    try:
        print("[+] Starting aggressive OWASP ZAP vulnerability scan...")
        # Start a ZAP scan
        response = requests.get(scan_url)
        scan_id = response.json()['scan']

        # Monitor scan progress
        progress_url = f'{zap_url}/JSON/ascan/view/status/?scanId={scan_id}'
        progress = 0
        while progress < 100:
            time.sleep(10)  # Wait 10 seconds before checking progress again
            progress = int(requests.get(progress_url).json()['status'])
            print(f"Scan progress: {progress}%")

        # Get the scan report
        report_url = f'{zap_url}/HTML/ascan/view/scanProgress/?scanId={scan_id}'
        report = requests.get(report_url).text
        return report

    except Exception as e:
        print(f"Error during ZAP scan: {e}")
        return None
