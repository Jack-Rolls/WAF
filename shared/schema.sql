-- WAF requests logging table
-- Captures every request (regardless of verdict) with matched rules and geolocation data
CREATE TABLE requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp INTEGER NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  query TEXT,
  body_preview TEXT,
  user_agent TEXT,
  client_ip TEXT,
  asn INTEGER,
  asn_org TEXT,
  country TEXT,
  city TEXT,
  verdict TEXT NOT NULL,        -- 'allowed' | 'blocked' | 'challenged'
  matched_rules TEXT,           -- JSON array of rule IDs
  attack_categories TEXT        -- JSON array of unique categories
);

-- Indexes for common queries on dashboard
CREATE INDEX idx_requests_ts ON requests(timestamp DESC);
CREATE INDEX idx_requests_verdict ON requests(verdict);
CREATE INDEX idx_requests_country ON requests(country);
