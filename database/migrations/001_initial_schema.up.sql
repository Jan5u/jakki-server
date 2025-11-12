-- Create channels table
CREATE TABLE IF NOT EXISTS channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL CHECK(type IN ('text', 'voice')),
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_channels_type ON channels(type);
CREATE INDEX IF NOT EXISTS idx_channels_name ON channels(name);

-- Insert default channels
INSERT OR IGNORE INTO channels (name, type, description) VALUES 
    ('#general', 'text', 'General text channel'),
    ('voice-general', 'voice', 'General voice channel');
