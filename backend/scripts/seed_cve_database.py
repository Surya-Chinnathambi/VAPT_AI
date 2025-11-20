#!/usr/bin/env python3
"""
CVE Database Seeding Script
Downloads and populates CVE database from NVD API
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
import psycopg2
from datetime import datetime, timedelta
from time import sleep

# Database connection
DB_CONFIG = {
    'host': 'localhost',
    'port': 5433,
    'database': 'cybersec_ai',
    'user': 'postgres',
    'password': 'password'
}

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_db_connection():
    """Create database connection"""
    return psycopg2.connect(**DB_CONFIG)

def create_cve_table():
    """Ensure CVE table exists"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            id SERIAL PRIMARY KEY,
            cve_id VARCHAR(50) UNIQUE NOT NULL,
            description TEXT,
            severity VARCHAR(20),
            cvss_score FLOAT,
            published_date TIMESTAMP,
            last_modified TIMESTAMP,
            cwe_id VARCHAR(50),
            reference_urls TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    conn.commit()
    cursor.close()
    conn.close()
    print("✓ CVE table ready")

def fetch_recent_cves(days=90):
    """Fetch CVEs from the last N days"""
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    
    params = {
        'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
        'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.999'),
        'resultsPerPage': 100
    }
    
    print(f"Fetching CVEs from {start_date.date()} to {end_date.date()}...")
    
    all_cves = []
    start_index = 0
    
    while True:
        params['startIndex'] = start_index
        
        try:
            response = requests.get(NVD_API_URL, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get('vulnerabilities', [])
            if not vulnerabilities:
                break
            
            all_cves.extend(vulnerabilities)
            print(f"  Fetched {len(all_cves)} CVEs so far...")
            
            # Check if there are more results
            total_results = data.get('totalResults', 0)
            if start_index + len(vulnerabilities) >= total_results:
                break
            
            start_index += len(vulnerabilities)
            
            # Rate limiting - NVD API allows 5 requests per 30 seconds without API key
            sleep(6)
            
        except Exception as e:
            print(f"  Error fetching CVEs: {e}")
            break
    
    print(f"✓ Fetched {len(all_cves)} total CVEs")
    return all_cves

def parse_cve(vuln):
    """Parse CVE data from NVD format"""
    cve = vuln.get('cve', {})
    cve_id = cve.get('id')
    
    # Description
    descriptions = cve.get('descriptions', [])
    description = next((d['value'] for d in descriptions if d['lang'] == 'en'), 'No description')
    
    # CVSS Score
    metrics = cve.get('metrics', {})
    cvss_score = 0.0
    severity = 'UNKNOWN'
    
    # Try CVSS v3.1 first, then v3.0, then v2.0
    if 'cvssMetricV31' in metrics:
        cvss_data = metrics['cvssMetricV31'][0]['cvssData']
        cvss_score = cvss_data.get('baseScore', 0.0)
        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
    elif 'cvssMetricV30' in metrics:
        cvss_data = metrics['cvssMetricV30'][0]['cvssData']
        cvss_score = cvss_data.get('baseScore', 0.0)
        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
    elif 'cvssMetricV2' in metrics:
        cvss_data = metrics['cvssMetricV2'][0]['cvssData']
        cvss_score = cvss_data.get('baseScore', 0.0)
        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
    
    # Dates
    published = cve.get('published', '')
    modified = cve.get('lastModified', '')
    
    # CWE
    weaknesses = cve.get('weaknesses', [])
    cwe_id = ''
    if weaknesses:
        cwe_desc = weaknesses[0].get('description', [])
        if cwe_desc:
            cwe_id = cwe_desc[0].get('value', '')
    
    # References
    references = cve.get('references', [])
    refs_text = '\n'.join([ref.get('url', '') for ref in references[:5]])  # First 5 refs
    
    return {
        'cve_id': cve_id,
        'description': description[:1000],  # Limit description length
        'severity': severity,
        'cvss_score': cvss_score,
        'published_date': published,
        'last_modified': modified,
        'cwe_id': cwe_id,
        'reference_urls': refs_text
    }

def insert_cves(cves_data):
    """Insert CVEs into database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    inserted = 0
    skipped = 0
    
    for cve in cves_data:
        try:
            cursor.execute("""
                INSERT INTO cves (cve_id, description, severity, cvss_score, 
                                published_date, last_modified, cwe_id, reference_urls)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (cve_id) DO NOTHING
            """, (
                cve['cve_id'],
                cve['description'],
                cve['severity'],
                cve['cvss_score'],
                cve['published_date'],
                cve['last_modified'],
                cve['cwe_id'],
                cve['reference_urls']
            ))
            
            if cursor.rowcount > 0:
                inserted += 1
            else:
                skipped += 1
                
        except Exception as e:
            print(f"  Error inserting {cve['cve_id']}: {e}")
            continue
    
    conn.commit()
    cursor.close()
    conn.close()
    
    print(f"✓ Inserted {inserted} new CVEs, skipped {skipped} duplicates")

def main():
    print("=" * 60)
    print("CVE Database Seeding Script")
    print("=" * 60)
    
    # Step 1: Ensure table exists
    create_cve_table()
    
    # Step 2: Fetch recent CVEs (last 90 days due to API limits)
    vulnerabilities = fetch_recent_cves(days=90)
    
    if not vulnerabilities:
        print("✗ No CVEs fetched. Exiting.")
        return
    
    # Step 3: Parse CVEs
    print("Parsing CVE data...")
    cves_data = []
    for vuln in vulnerabilities:
        try:
            cve_data = parse_cve(vuln)
            cves_data.append(cve_data)
        except Exception as e:
            print(f"  Error parsing CVE: {e}")
            continue
    
    print(f"✓ Parsed {len(cves_data)} CVEs")
    
    # Step 4: Insert into database
    print("Inserting CVEs into database...")
    insert_cves(cves_data)
    
    print("=" * 60)
    print("CVE database seeding complete!")
    print("=" * 60)

if __name__ == "__main__":
    main()
