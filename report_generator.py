from datetime import datetime

def generate_report(analysis_result, url_scan_result=None):
    report = f"""
========= PHISHING ANALYSIS REPORT =========

Date: {datetime.now()}

AI Email Analysis:
{analysis_result}

"""

    if url_scan_result:
        report += f"""
URL Threat Intelligence:
{url_scan_result}
"""

    report += """
===========================================
"""

    with open("phishing_report.txt", "w") as f:
        f.write(report)

    print("\nReport saved as phishing_report.txt\n")
