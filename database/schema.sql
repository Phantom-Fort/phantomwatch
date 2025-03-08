-- Table for storing security incidents
CREATE TABLE incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT CHECK( severity IN ('Low', 'Medium', 'High', 'Critical') ) NOT NULL,
    status TEXT CHECK( status IN ('Open', 'In Progress', 'Resolved') ) DEFAULT 'Open',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index to speed up queries filtering by severity and status
CREATE INDEX idx_incidents_severity ON incidents(severity);
CREATE INDEX idx_incidents_status ON incidents(status);

-- Table for storing threat intelligence data
CREATE TABLE threat_intel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    indicator TEXT NOT NULL UNIQUE,
    type TEXT CHECK( type IN ('IP', 'Domain', 'Hash', 'URL') ) NOT NULL,
    confidence INTEGER CHECK( confidence BETWEEN 0 AND 100 ),
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index to optimize searches on indicators and types
CREATE INDEX idx_threat_intel_indicator ON threat_intel(indicator);
CREATE INDEX idx_threat_intel_type ON threat_intel(type);

-- Table for storing logs and alerts
CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    module TEXT NOT NULL,
    message TEXT NOT NULL,
    level TEXT CHECK( level IN ('INFO', 'WARNING', 'ERROR', 'CRITICAL') ) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index to speed up log searches by module and level
CREATE INDEX idx_logs_module ON logs(module);
CREATE INDEX idx_logs_level ON logs(level);
CREATE INDEX idx_logs_timestamp ON logs(timestamp DESC);  -- For quick access to the latest logs
