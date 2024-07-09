import requests
import pandas as pd
import os

# API keys setup
VIRUSTOTAL_KEY = 'your vt api key'
ABUSEIPDB_KEY = 'your abuseipdb api key'
IPINFO_TOKEN = 'your ipinfo api key'
WHOISXML_KEY = 'your whoisxmlapi key'

def check_virustotal(ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {'x-apikey': VIRUSTOTAL_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return {}

def check_abuseipdb(ip):
    url = f'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Key': ABUSEIPDB_KEY}
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    return {}

def check_ipinfo(ip):
    url = f'https://ipinfo.io/{ip}'
    headers = {'Authorization': f'Bearer {IPINFO_TOKEN}'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        if 'privacy' not in data or not isinstance(data['privacy'], dict):
            data['privacy'] = {'vpn': False, 'proxy': False, 'tor': False, 'relay': False, 'hosting': False, 'service': ""}
        return data
    return {}

def check_whoisxml(ip):
    url = f'https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOISXML_KEY}&domainName={ip}&outputFormat=JSON'
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    return {}

def process_ip_data(ip_address):
    print("\nChecking IP:", ip_address)
    ip_data = {'IP Address': ip_address}

    vt_result = check_virustotal(ip_address)
    if 'data' in vt_result:
        vt_attributes = vt_result['data']['attributes']
        ip_data.update({
            'VT ASN': vt_attributes.get('asn', 'N/A'),
            'VT AS Owner': vt_attributes.get('as_owner', 'N/A'),
            'VT Country': vt_attributes.get('country', 'N/A'),
            'VT Continent': vt_attributes.get('continent', 'N/A'),
            'VT Malicious': vt_attributes['last_analysis_stats']['malicious']
        })

    abuse_result = check_abuseipdb(ip_address)
    if 'data' in abuse_result:
        ip_data.update({
            'AbuseIPDB ISP': abuse_result['data']['isp'],
            'AbuseIPDB Country Code': abuse_result['data']['countryCode'],
            'AbuseIPDB Confidence Score': abuse_result['data']['abuseConfidenceScore'],
            'AbuseIPDB Hostnames': ', '.join(abuse_result['data']['hostnames']),
            'AbuseIPDB Is TOR': abuse_result['data']['isTor']
        })

    ipinfo_result = check_ipinfo(ip_address)
    if ipinfo_result:
        ip_data.update({
            'IPInfo City': ipinfo_result.get('city', 'N/A'),
            'IPInfo Region': ipinfo_result.get('region', 'N/A'),
            'IPInfo Privacy VPN': ipinfo_result['privacy'].get('vpn', False),
            'IPInfo Privacy Proxy': ipinfo_result['privacy'].get('proxy', False),
            'IPInfo Privacy TOR': ipinfo_result['privacy'].get('tor', False),
            'IPInfo Privacy Hosting': ipinfo_result['privacy'].get('hosting', False)
        })

    whois_result = check_whoisxml(ip_address)
    if 'WhoisRecord' in whois_result:
        registry_data = whois_result.get('WhoisRecord', {}).get('registryData', {})
        if 'registrant' in registry_data:
            ip_data.update({
                'WhoisXML Registrant Organization': registry_data['registrant'].get('organization', 'N/A'),
                'WhoisXML Tech Email': registry_data.get('administrativeContact', {}).get('email', 'N/A'),
                'WhoisXML Net Range': registry_data.get('network', {}).get('cidr', 'N/A')
            })

    return ip_data

# Read IPs from file and process
try:
    df = pd.DataFrame()
    with open('ip.txt', 'r') as file:
        ips = file.read().splitlines()
        for ip in ips:
            ip_data = process_ip_data(ip)
            df = pd.concat([df, pd.DataFrame([ip_data])], ignore_index=True)
    
    output_path = os.path.join(os.path.dirname(__file__), 'IP_Reputation_Report.xlsx')
    df.to_excel(output_path, index=False)
    print("Excel file has been created successfully.")
except FileNotFoundError:
    print("The file 'ip.txt' was not found.")
except Exception as e:
    print("An error occurred:", str(e))