import requests
import pandas as pd
from datetime import datetime, timezone

def get_virustotal_info(api_key, file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": api_key
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return {"error": "Hash not found in VirusTotal database."}
    else:
        return {"error": f"Error {response.status_code}: {response.reason}"}

def get_joesandbox_public_report(file_hash):
    url = f"https://www.joesandbox.com/search?q={file_hash}"
    response = requests.get(url)
    
    if response.status_code == 200:
        return {"report_url": url}
    elif response.status_code == 404:
        return {"error": "Hash not found in Joe Sandbox database."}
    else:
        return {"error": f"Error {response.status_code}: {response.reason}"}

def get_recordedfuture_public_report(file_hash):
    url = f"https://app.recordedfuture.com/live/sc/entity/{file_hash}"
    response = requests.get(url)
    
    if response.status_code == 200:
        return {"report_url": url}
    elif response.status_code == 404:
        return {"error": "Hash not found in Recorded Future database."}
    else:
        return {"error": f"Error {response.status_code}: {response.reason}"}

def format_timestamp(timestamp):
    try:
        return datetime.fromtimestamp(int(timestamp), timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if timestamp else 'N/A'
    except ValueError:
        return 'N/A'

def extract_relevant_info(info, source):
    if source == "virustotal":
        attributes = info.get('data', {}).get('attributes', {})
        relevant_info = {
            'Reputation': attributes.get('last_analysis_stats', {}).get('malicious', 'N/A'),
            'Names': ', '.join(attributes.get('names', [])),
            'File_type': attributes.get('trid', [{'file_type': 'N/A'}])[0].get('file_type', 'N/A'),
            'Last_analysis_date': format_timestamp(attributes.get('last_analysis_date', 'N/A')),
            'First_submission_date': format_timestamp(attributes.get('first_submission_date', 'N/A')),
            'Last_submission_date': format_timestamp(attributes.get('last_submission_date', 'N/A')),
            'Last_modification_date': format_timestamp(attributes.get('last_modification_date', 'N/A')),
            'Size': attributes.get('size', 'N/A'),
            'Type_description': attributes.get('type_description', 'N/A'),
            'MD5': attributes.get('md5', 'N/A'),
            'SHA1': attributes.get('sha1', 'N/A'),
            'SHA256': attributes.get('sha256', 'N/A'),
        }
        last_analysis_results = attributes.get('last_analysis_results', {})
        engine_results = []
        for engine, result in last_analysis_results.items():
            engine_results.append(f"{engine}: {result.get('result', 'N/A')}")
        relevant_info['AV_eng_results'] = '; '.join(engine_results)
    return relevant_info

def bulk_fetch_info(api_key_vt, file_hashes):
    results = []
    for file_hash in file_hashes:
        vt_info = get_virustotal_info(api_key_vt, file_hash)
        js_info = get_joesandbox_public_report(file_hash)
        rf_info = get_recordedfuture_public_report(file_hash)
        
        vt_relevant_info = extract_relevant_info(vt_info, "virustotal")
        vt_relevant_info.update({
            'hash': file_hash,
            'Joe_sandbox_report_url': js_info.get('report_url', js_info.get('error', 'N/A')),
            'Recorded_future_report_url': rf_info.get('report_url', rf_info.get('error', 'N/A'))
        })
        results.append(vt_relevant_info)
    return results

def read_hashes_from_file(file_path):
    with open(file_path, 'r') as file:
        hashes = [line.strip() for line in file if line.strip()]
    return hashes

def save_to_excel(data, output_file_path):
    df = pd.DataFrame(data)
    # Reorder columns to ensure 'hash' is the first column
    columns = ['hash'] + [col for col in df.columns if col != 'hash']
    df = df[columns]
    df.to_excel(output_file_path, index=False)

# Example usage
api_key_vt = "your vt api key"
input_file_path = "hashes.txt"  # The input file containing the hashes
output_file_path = "hash_analysis_results.xlsx"  # Output Excel file

file_hashes = read_hashes_from_file(input_file_path)
info_results = bulk_fetch_info(api_key_vt, file_hashes)
save_to_excel(info_results, output_file_path)

print(f"Results saved to {output_file_path}")