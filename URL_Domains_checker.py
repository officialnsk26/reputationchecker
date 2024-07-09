import requests
import base64
import pandas as pd
from datetime import datetime, timezone

def get_url_reputation(api_key, url):
    headers = {
        "x-apikey": api_key
    }
    params = {
        "url": url
    }
    
    # Scan the URL
    response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data=params)
    if response.status_code != 200:
        print(f"Error scanning URL {url}: {response.status_code}")
        print(response.text)
        return None
    
    # Encode the URL in base64 format as required by VirusTotal API
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    # Get the URL report
    report_url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
    report_response = requests.get(report_url, headers=headers)
    if report_response.status_code != 200:
        print(f"Error fetching report for URL {url}: {report_response.status_code}")
        print(report_response.text)
        return None
    
    return report_response.json()

def read_urls_from_file(file_path):
    with open(file_path, 'r') as file:
        urls = [line.strip() for line in file.readlines()]
    return urls

def convert_to_utc(timestamp):
    if isinstance(timestamp, int) and timestamp > 0:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')
    return ""

def extract_fields(report):
    data = report.get('data', {}).get('attributes', {})
    filtered_data = {
        "url": report.get('data', {}).get('id', ""),
        "num_detections": sum(1 for result in data.get("last_analysis_results", {}).values() if result["category"] == "malicious"),
        "last_analysis_results": data.get("last_analysis_results", {}),
        "last_analysis_date": convert_to_utc(data.get("last_analysis_date", 0)),
        "last_submission_date": convert_to_utc(data.get("last_submission_date", 0)),
        "categories": data.get("categories", {}),
        "first_submission_date": convert_to_utc(data.get("first_submission_date", 0)),
        "title": data.get("title", ""),
        "last_final_url": data.get("last_final_url", ""),
        "belongs_to_bad_collection": data.get("popular_threat_classification", {}).get("suggested_threat_label", "")
    }
    return filtered_data

if __name__ == "__main__":
    # Replace 'your_api_key' with your actual VirusTotal API key
    api_key = 'your vt api key'
    # Replace 'urls.txt' with your text file containing URLs
    file_path = 'urls.txt'
    
    urls = read_urls_from_file(file_path)
    records = []

    for url in urls:
        report = get_url_reputation(api_key, url)
        if report:
            filtered_report = extract_fields(report)
            filtered_report["url"] = url
            # Convert last_analysis_results to a string representation
            filtered_report["last_analysis_results"] = str(filtered_report["last_analysis_results"])
            records.append(filtered_report)

    # Convert the records to a DataFrame
    df = pd.DataFrame(records)

    # Reorder columns to have 'url' and 'num_detections' first
    columns_order = ["url", "num_detections", "last_analysis_results", "last_analysis_date", "last_submission_date", 
                     "categories", "first_submission_date", "title", "last_final_url", "belongs_to_bad_collection"]
    df = df[columns_order]

    # Save the DataFrame to an Excel file
    output_file = "url_reputation_reports.xlsx"
    df.to_excel(output_file, index=False)

    print(f"Reports saved to {output_file}")
