import pdfkit

def generate_report(vulns, output_file):
    report_content = "<html><body><h1>Vulnerability Report</h1><ul>"
    
    for vuln in vulns:
        for key, value in vuln.items():
            report_content += f"<li><strong>{key}</strong>:<br>{format_vulnerability(value)}</li>"
    report_content += "</ul></body></html>"

    print(f"[+] Writing report content to {output_file}")

    # Write the HTML to a file for debugging purposes
    with open("report.html", "w") as report_file:
        report_file.write(report_content)

    # Generate PDF from HTML
    pdfkit.from_file("report.html", output_file)
