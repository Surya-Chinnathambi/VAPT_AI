"""
PostgreSQL Database Schema for CyberSec AI Platform
Supports: Users, Scans, CVEs, Reports, Compliance Frameworks
"""

CREATE_USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role VARCHAR(20) DEFAULT 'free' CHECK (role IN ('free', 'pro', 'enterprise')),
    stripe_customer_id VARCHAR(100),
    subscription_id VARCHAR(100),
    subscription_status VARCHAR(50),
    subscription_expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
"""

CREATE_SCANS_TABLE = """
CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    target VARCHAR(500) NOT NULL,
    scan_type VARCHAR(50) NOT NULL CHECK (scan_type IN ('nmap', 'nikto', 'port_scan', 'web_scan', 'shodan', 'vapt_full', 'vapt_recon', 'vapt_scan', 'vapt_exploit')),
    tool VARCHAR(50) NOT NULL,
    raw_output JSONB,
    summary TEXT,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    risk_level VARCHAR(20) CHECK (risk_level IN ('critical', 'high', 'medium', 'low', 'info')),
    vulnerabilities_found INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_scan_type ON scans(scan_type);
"""

CREATE_CVES_TABLE = """
CREATE TABLE IF NOT EXISTS cves (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    cvss_v3_score FLOAT,
    cvss_v2_score FLOAT,
    severity VARCHAR(20),
    published_date TIMESTAMP,
    modified_date TIMESTAMP,
    reference_urls JSONB,
    cwe_ids JSONB,
    affected_products JSONB,
    exploit_available BOOLEAN DEFAULT FALSE,
    chroma_id VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cves_cve_id ON cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cves_cvss_v3_score ON cves(cvss_v3_score DESC);
CREATE INDEX IF NOT EXISTS idx_cves_published_date ON cves(published_date DESC);
"""

CREATE_REPORTS_TABLE = """
CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    report_name VARCHAR(255) NOT NULL,
    report_type VARCHAR(50) NOT NULL CHECK (report_type IN ('pentest', 'compliance', 'full_assessment', 'executive_summary')),
    format VARCHAR(10) DEFAULT 'pdf' CHECK (format IN ('pdf', 'html', 'json')),
    file_url TEXT,
    s3_key VARCHAR(500),
    compliance_frameworks JSONB,
    total_vulnerabilities INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'generating' CHECK (status IN ('generating', 'completed', 'failed')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_reports_user_id ON reports(user_id);
CREATE INDEX IF NOT EXISTS idx_reports_scan_id ON reports(scan_id);
CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at DESC);
"""

CREATE_COMPLIANCE_FRAMEWORKS_TABLE = """
CREATE TABLE IF NOT EXISTS compliance_frameworks (
    id SERIAL PRIMARY KEY,
    framework_code VARCHAR(50) UNIQUE NOT NULL,
    framework_name VARCHAR(200) NOT NULL,
    version VARCHAR(50),
    description TEXT,
    requirements JSONB,
    chroma_collection VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_compliance_framework_code ON compliance_frameworks(framework_code);
"""

CREATE_SCAN_VULNERABILITIES_TABLE = """
CREATE TABLE IF NOT EXISTS scan_vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    cve_id VARCHAR(50) REFERENCES cves(cve_id),
    vulnerability_type VARCHAR(100),
    title VARCHAR(500),
    description TEXT,
    severity VARCHAR(20),
    cvss_score FLOAT,
    affected_component VARCHAR(500),
    remediation TEXT,
    compliance_mappings JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scan_vuln_scan_id ON scan_vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_vuln_cve_id ON scan_vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_scan_vuln_severity ON scan_vulnerabilities(severity);
"""

CREATE_USAGE_LOGS_TABLE = """
CREATE TABLE IF NOT EXISTS usage_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    action_type VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50),
    resource_id INTEGER,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_usage_user_id ON usage_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_created_at ON usage_logs(created_at DESC);
"""

CREATE_API_KEYS_TABLE = """
CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    key_hash TEXT NOT NULL,
    key_prefix VARCHAR(20) NOT NULL,
    name VARCHAR(100),
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
"""

CREATE_CHAT_CONVERSATIONS_TABLE = """
CREATE TABLE IF NOT EXISTS chat_conversations (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    session_id VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(500),
    context TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_message_at TIMESTAMP,
    message_count INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_chat_conversations_user_id ON chat_conversations(user_id);
CREATE INDEX IF NOT EXISTS idx_chat_conversations_session_id ON chat_conversations(session_id);
CREATE INDEX IF NOT EXISTS idx_chat_conversations_updated_at ON chat_conversations(updated_at DESC);
"""

CREATE_CHAT_MESSAGES_TABLE = """
CREATE TABLE IF NOT EXISTS chat_messages (
    id SERIAL PRIMARY KEY,
    conversation_id INTEGER REFERENCES chat_conversations(id) ON DELETE CASCADE,
    role VARCHAR(20) NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
    content TEXT NOT NULL,
    metadata JSONB,
    token_count INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_conversation_id ON chat_messages(conversation_id);
CREATE INDEX IF NOT EXISTS idx_chat_messages_created_at ON chat_messages(created_at);
"""

# Seed Data for Compliance Frameworks
INSERT_COMPLIANCE_FRAMEWORKS = """
INSERT INTO compliance_frameworks (framework_code, framework_name, version, description) VALUES
('OWASP_TOP10', 'OWASP Top 10', '2021', 'Top 10 Web Application Security Risks'),
('PCI_DSS', 'PCI DSS', '4.0', 'Payment Card Industry Data Security Standard'),
('HIPAA', 'HIPAA Security Rule', '2023', 'Health Insurance Portability and Accountability Act'),
('ISO_27001', 'ISO/IEC 27001', '2022', 'Information Security Management'),
('NIST_CSF', 'NIST Cybersecurity Framework', '1.1', 'Framework for Improving Critical Infrastructure Cybersecurity'),
('GDPR', 'General Data Protection Regulation', '2018', 'EU Data Protection Regulation'),
('SOC2', 'SOC 2 Type II', '2023', 'Service Organization Control 2'),
('CIS_CONTROLS', 'CIS Critical Security Controls', 'v8', 'Center for Internet Security Controls')
ON CONFLICT (framework_code) DO NOTHING;
"""

ALL_TABLES = [
    CREATE_USERS_TABLE,
    CREATE_SCANS_TABLE,
    CREATE_CVES_TABLE,
    CREATE_REPORTS_TABLE,
    CREATE_COMPLIANCE_FRAMEWORKS_TABLE,
    CREATE_SCAN_VULNERABILITIES_TABLE,
    CREATE_USAGE_LOGS_TABLE,
    CREATE_API_KEYS_TABLE,
    CREATE_CHAT_CONVERSATIONS_TABLE,
    CREATE_CHAT_MESSAGES_TABLE
]
