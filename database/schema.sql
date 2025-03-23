-- Table for storing security incidents
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT CHECK( severity IN ('Low', 'Medium', 'High', 'Critical') ) NOT NULL,
    status TEXT CHECK( status IN ('Open', 'In Progress', 'Resolved', 'Closed') ) DEFAULT 'Open',
    category TEXT NOT NULL,  -- Added to categorize incidents (e.g., Network, Malware, Web, etc.)
    reported_by TEXT,  -- Stores the reporter's identity
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes to optimize queries
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_category ON incidents(category);

-- Table for threat intelligence data
CREATE TABLE IF NOT EXISTS threat_intel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    indicator TEXT NOT NULL UNIQUE,
    type TEXT CHECK( type IN ('IP', 'Domain', 'Hash', 'URL') ) NOT NULL,
    confidence INTEGER CHECK( confidence BETWEEN 0 AND 100 ) NOT NULL DEFAULT 50,
    tags TEXT,  -- Allows storing threat categorization labels
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for optimized queries
CREATE INDEX IF NOT EXISTS idx_threat_intel_indicator ON threat_intel(indicator);
CREATE INDEX IF NOT EXISTS idx_threat_intel_type ON threat_intel(type);

-- Table for storing logs and alerts
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    module TEXT NOT NULL,
    message TEXT NOT NULL,
    level TEXT CHECK( level IN ('INFO', 'WARNING', 'ERROR', 'CRITICAL') ) NOT NULL,
    user TEXT,  -- Logs the user performing the action
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for log searching
CREATE INDEX IF NOT EXISTS idx_logs_module ON logs(module);
CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(level);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp DESC);

-- Table for module-specific configurations
CREATE TABLE IF NOT EXISTS module_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    module_name TEXT NOT NULL UNIQUE,
    config_data TEXT NOT NULL, -- Stores JSON data for module-specific settings
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table for API keys and credentials
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    module_name TEXT NOT NULL UNIQUE,
    key_name TEXT NOT NULL,
    key_value TEXT NOT NULL, -- Stored securely using encryption
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table for storing scheduled tasks (cron jobs, automation)
CREATE TABLE IF NOT EXISTS scheduled_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_name TEXT NOT NULL,
    module_name TEXT NOT NULL,
    schedule TEXT NOT NULL, -- Stores cron-like schedule (e.g., 'daily', 'hourly')
    last_run TIMESTAMP DEFAULT NULL,
    status TEXT CHECK( status IN ('Pending', 'Running', 'Completed', 'Failed') ) DEFAULT 'Pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table for tracking module execution history
CREATE TABLE IF NOT EXISTS module_execution_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    module_name TEXT NOT NULL,
    execution_status TEXT CHECK( execution_status IN ('Success', 'Failure') ) NOT NULL,
    execution_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    logs TEXT -- Stores execution logs
);

-- Table for access control and role-based permissions
CREATE TABLE IF NOT EXISTS access_control (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    role TEXT CHECK( role IN ('Admin', 'User', 'Viewer', 'Analyst') ) NOT NULL,
    permissions TEXT NOT NULL, -- Stores JSON list of permissions per module
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
