import pdfkit

# Specify the path to wkhtmltopdf
path_wkhtmltopdf = '/usr/local/bin/wkhtmltopdf'
config = pdfkit.configuration(wkhtmltopdf=path_wkhtmltopdf)

# Define the format_vulnerability function to handle formatting for different types of data
def format_vulnerability(vuln):
    if isinstance(vuln, dict):
        formatted_vuln = ""
        for key, value in vuln.items():
            formatted_vuln += f"<strong>{key}:</strong> {format_vulnerability(value)}<br>"
        return formatted_vuln
    elif isinstance(vuln, list):
        return "<br>".join([format_vulnerability(item) for item in vuln])
    else:
        return str(vuln)

def generate_report(vulns, output_file):
    report_content = "<html><body><h1>Vulnerability Report</h1><ul>"
    for vuln in vulns:
        for key, value in vuln.items():
            report_content += f"<li><strong>{key}</strong>:<br>{format_vulnerability(value)}</li>"
    report_content += "</ul></body></html>"

    # Write the HTML report to a file
    with open("report.html", "w") as report_file:
        report_file.write(report_content)

    # Generate PDF from HTML
    pdfkit.from_file("report.html", output_file, configuration=config)
