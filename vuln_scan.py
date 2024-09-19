import requests

def zap_scan(target_url):
    zap_url = 'http://localhost:8080'  # Replace with your OWASP ZAP instance
    scan_url = f'{zap_url}/JSON/ascan/action/scan/?url={target_url}'

    try:
        # Start a scan
        response = requests.get(scan_url)
        scan_id = response.json()['scan']

        # Monitor scan progress
        progress_url = f'{zap_url}/JSON/ascan/view/status/?scanId={scan_id}'
        while True:
            progress = requests.get(progress_url).json()['status']
            print(f"Scan progress: {progress}%")
            if progress == '100':
                break

        # Get the scan report
        report_url = f'{zap_url}/HTML/ascan/view/scanProgress/?scanId={scan_id}'
        report = requests.get(report_url).text
        return report

    except Exception as e:
        print(f"Error during ZAP scan: {e}")
        return None
