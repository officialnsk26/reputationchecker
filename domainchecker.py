import requests
import pandas as pd

def get_virustotal_domain_reputation(api_key, domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "x-apikey": api_key
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return {"error": "Domain not found in VirusTotal database."}
    else:
        return {"error": f"Error {response.status_code}: {response.reason}"}

def get_whoisxml_domain_reputation(api_key, domain):
    url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={api_key}&domainName={domain}&outputFormat=JSON"
    
    response = requests.get(url)
    
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 401:
        return {"error": "Error 401: Unauthorized"}
    elif response.status_code == 404:
        return {"error": "Domain not found in WHOISXML database."}
    else:
        return {"error": f"Error {response.status_code}: {response.reason}"}

def extract_virustotal_info(info):
    attributes = info.get('data', {}).get('attributes', {})
    reputation_info = {
        'malicious': attributes.get('last_analysis_stats', {}).get('malicious', 'N/A'),
        'suspicious': attributes.get('last_analysis_stats', {}).get('suspicious', 'N/A'),
        'categories': attributes.get('categories', 'N/A'),
        'last_dns_records': [record.get('value', 'N/A') for record in attributes.get('last_dns_records', [])],
        'crowdsourced_context': attributes.get('crowdsourced_context', [])
    }
    return reputation_info

def extract_whoisxml_info(info):
    whois_record = info.get('WhoisRecord', {})
    reputation_info = {
        'whois_domain_name': whois_record.get('domainName', 'N/A'),
        'whois_create_date': whois_record.get('createdDate', 'N/A'),
        'whois_update_date': whois_record.get('updatedDate', 'N/A'),
        'whois_expiry_date': whois_record.get('expiresDate', 'N/A'),
        'whois_registrar_name': whois_record.get('registrarName', 'N/A'),
        'whois_registrant_name': whois_record.get('registrant', {}).get('name', 'N/A'),
        'whois_registrant_email': whois_record.get('registrant', {}).get('email', 'N/A'),
        'whois_reputation_score': whois_record.get('reputationScore', 'N/A') if 'reputationScore' in whois_record else 'N/A'
    }
    return reputation_info

def bulk_domain_reputation_check(api_key_vt, api_key_whoisxml, domains):
    results = []
    for domain in domains:
        vt_info = get_virustotal_domain_reputation(api_key_vt, domain)
        whoisxml_info = get_whoisxml_domain_reputation(api_key_whoisxml, domain)
        
        vt_reputation_info = extract_virustotal_info(vt_info)
        whoisxml_reputation_info = extract_whoisxml_info(whoisxml_info)
        
        combined_info = {
            'Domain': domain,
            'Malicious': vt_reputation_info['malicious'],
            'Suspicious': vt_reputation_info['suspicious'],
            'Categories': vt_reputation_info['categories'],
            'Last_dns_records': vt_reputation_info['last_dns_records'],
            'Whois_domain_name': whoisxml_reputation_info['whois_domain_name'],
            'Whois_create_date': whoisxml_reputation_info['whois_create_date'],
            'Whois_update_date': whoisxml_reputation_info['whois_update_date'],
            'Whois_expiry_date': whoisxml_reputation_info['whois_expiry_date'],
            'Whois_registrar_name': whoisxml_reputation_info['whois_registrar_name'],
            'Whois_registrant_name': whoisxml_reputation_info['whois_registrant_name'],
            'Whois_registrant_email': whoisxml_reputation_info['whois_registrant_email']
        }
        
        results.append(combined_info)
    return results

def read_domains_from_file(file_path):
    with open(file_path, 'r') as file:
        domains = [line.strip() for line in file if line.strip()]
    return domains

def save_to_excel(data, output_file_path):
    df = pd.DataFrame(data)
    df.to_excel(output_file_path, index=False)

# Example usage
api_key_vt = "your vt api key"
api_key_whoisxml = "your whoisxml api key"
input_file_path = "domains.txt"  # The input file containing the domains
output_file_path = "domain_reputation_results.xlsx"  # Output Excel file

domains = read_domains_from_file(input_file_path)
info_results = bulk_domain_reputation_check(api_key_vt, api_key_whoisxml, domains)
save_to_excel(info_results, output_file_path)

print(f"Results saved to {output_file_path}")