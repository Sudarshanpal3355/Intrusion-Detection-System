-- Initialize IDS Database
-- Create tables for threat logging and analysis

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Threats Table
CREATE TABLE IF NOT EXISTS threats (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id VARCHAR(255) UNIQUE NOT NULL,
    severity VARCHAR(50) NOT NULL,
    attack_type VARCHAR(100),
    description TEXT,
    source_ip INET,
    dest_ip INET,
    src_port INTEGER,
    dst_port INTEGER,
    packet_count INTEGER,
    protocol VARCHAR(20),
    confidence DECIMAL(5,4),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for faster queries
CREATE INDEX idx_threats_timestamp ON threats(timestamp DESC);
CREATE INDEX idx_threats_severity ON threats(severity);
CREATE INDEX idx_threats_source_ip ON threats(source_ip);
CREATE INDEX idx_threats_attack_type ON threats(attack_type);

-- Alerts Table
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    threat_id UUID REFERENCES threats(id) ON DELETE CASCADE,
    channel VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'sent',
    recipient VARCHAR(255),
    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_alerts_threat_id ON alerts(threat_id);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_sent_at ON alerts(sent_at DESC);

-- Network Flows Table
CREATE TABLE IF NOT EXISTS network_flows (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    flow_id VARCHAR(255) UNIQUE NOT NULL,
    source_ip INET,
    dest_ip INET,
    src_port INTEGER,
    dst_port INTEGER,
    protocol VARCHAR(20),
    packet_count INTEGER,
    byte_count BIGINT,
    duration DECIMAL(10,2),
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    is_malicious BOOLEAN DEFAULT false,
    confidence DECIMAL(5,4),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_flows_source_ip ON network_flows(source_ip);
CREATE INDEX idx_flows_dest_ip ON network_flows(dest_ip);
CREATE INDEX idx_flows_is_malicious ON network_flows(is_malicious);

-- Traffic Statistics Table
CREATE TABLE IF NOT EXISTS traffic_stats (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hour TIMESTAMP,
    total_packets BIGINT,
    total_bytes BIGINT,
    unique_src_ips INTEGER,
    unique_dst_ips INTEGER,
    threats_detected INTEGER,
    avg_packet_size DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_stats_hour ON traffic_stats(hour DESC);

-- Audit Log Table
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    action VARCHAR(100),
    user_email VARCHAR(255),
    description TEXT,
    ip_address INET,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_user ON audit_logs(user_email);

-- Create Views for Analytics

-- View: Daily Threat Summary
CREATE OR REPLACE VIEW daily_threat_summary AS
SELECT 
    DATE(timestamp) as date,
    severity,
    attack_type,
    COUNT(*) as threat_count,
    AVG(confidence) as avg_confidence,
    COUNT(DISTINCT source_ip) as unique_sources
FROM threats
GROUP BY DATE(timestamp), severity, attack_type
ORDER BY DATE(timestamp) DESC, threat_count DESC;

-- View: Top Attacking IPs
CREATE OR REPLACE VIEW top_attacking_ips AS
SELECT 
    source_ip,
    COUNT(*) as attack_count,
    COUNT(DISTINCT attack_type) as attack_types,
    AVG(confidence) as avg_confidence,
    MAX(timestamp) as last_seen
FROM threats
WHERE timestamp > NOW() - INTERVAL '30 days'
GROUP BY source_ip
ORDER BY attack_count DESC
LIMIT 100;

-- View: Most Targeted IPs
CREATE OR REPLACE VIEW most_targeted_ips AS
SELECT 
    dest_ip,
    COUNT(*) as attack_count,
    COUNT(DISTINCT source_ip) as unique_attackers,
    COUNT(DISTINCT attack_type) as attack_types,
    MAX(timestamp) as last_attacked
FROM threats
WHERE timestamp > NOW() - INTERVAL '30 days'
GROUP BY dest_ip
ORDER BY attack_count DESC
LIMIT 100;

-- View: Alert Performance
CREATE OR REPLACE VIEW alert_performance AS
SELECT 
    severity,
    COUNT(*) as total_alerts,
    COUNT(CASE WHEN status = 'sent' THEN 1 END) as sent,
    COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed,
    ROUND(100.0 * COUNT(CASE WHEN status = 'sent' THEN 1 END) / COUNT(*), 2) as success_rate
FROM alerts
GROUP BY severity;

-- Create stored procedures

-- Procedure: Cleanup old threats
CREATE OR REPLACE FUNCTION cleanup_old_threats(retention_days INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM threats 
    WHERE timestamp < NOW() - (retention_days || ' days')::INTERVAL;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    INSERT INTO audit_logs (action, description)
    VALUES ('cleanup', 'Deleted ' || deleted_count || ' old threats');
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Procedure: Generate daily report
CREATE OR REPLACE FUNCTION generate_daily_report(report_date DATE)
RETURNS TABLE (
    date DATE,
    total_threats BIGINT,
    critical_threats BIGINT,
    warning_threats BIGINT,
    unique_sources BIGINT,
    unique_targets BIGINT,
    avg_confidence DECIMAL
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        DATE(timestamp)::DATE,
        COUNT(*)::BIGINT,
        COUNT(CASE WHEN severity = 'CRITICAL' THEN 1 END)::BIGINT,
        COUNT(CASE WHEN severity = 'WARNING' THEN 1 END)::BIGINT,
        COUNT(DISTINCT source_ip)::BIGINT,
        COUNT(DISTINCT dest_ip)::BIGINT,
        AVG(confidence)::DECIMAL
    FROM threats
    WHERE DATE(timestamp) = report_date
    GROUP BY DATE(timestamp);
END;
$$ LANGUAGE plpgsql;

-- Grant permissions
GRANT SELECT ON ALL TABLES IN SCHEMA public TO ids_user;
GRANT INSERT, UPDATE, DELETE ON threats, alerts, network_flows, traffic_stats, audit_logs TO ids_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ids_user;

-- Initialize with sample admin user
INSERT INTO audit_logs (action, user_email, description, ip_address)
VALUES ('init', 'admin@ids.local', 'Database initialized', '127.0.0.1'::inet)
ON CONFLICT DO NOTHING;
