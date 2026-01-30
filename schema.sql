
-- Complete Database Schema - All Tables (Combined)
-- Includes: Browser Extension features, Stealth Module telemetry, and Dashboard User management.


-- Drop stealth tables first
DROP TABLE IF EXISTS session_visits CASCADE;
DROP TABLE IF EXISTS session_usage_breakdown CASCADE;
DROP TABLE IF EXISTS stealth_sessions CASCADE;
DROP TABLE IF EXISTS stealth_bindings CASCADE;
DROP TABLE IF EXISTS user_shifts CASCADE;
DROP TABLE IF EXISTS app_config CASCADE;
DROP TABLE IF EXISTS whitelisted_urls CASCADE;
DROP TABLE IF EXISTS allowed_queues CASCADE;
DROP TABLE IF EXISTS user_device_mappings CASCADE;
DROP TABLE IF EXISTS dashboard_users CASCADE;

-- Drop base tables (from user's old scheme)
DROP TABLE IF EXISTS useractivities CASCADE; 
DROP TABLE IF EXISTS inactivity CASCADE;
DROP TABLE IF EXISTS video_keys CASCADE;
DROP TABLE IF EXISTS video_speeds CASCADE;
DROP TABLE IF EXISTS videos CASCADE;
DROP TABLE IF EXISTS cards CASCADE;
DROP TABLE IF EXISTS queues CASCADE;
DROP TABLE IF EXISTS sessions CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS usertypes CASCADE;

-- ============================================
-- BASE TABLES (User's Old Scheme)
-- ============================================

-- User types table
CREATE TABLE IF NOT EXISTS usertypes (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    phone VARCHAR(255),
    active BOOLEAN DEFAULT true,
    status VARCHAR(255) NOT NULL DEFAULT 'active',
    usertype_id INTEGER NOT NULL REFERENCES usertypes(id) ON UPDATE CASCADE ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- Dashboard specific users (Admin/Management)
CREATE TABLE IF NOT EXISTS dashboard_users (
  id serial not null,
  name character varying(255) not null,
  username character varying(255) not null,
  email character varying(255) not null,
  password character varying(255) not null,
  phone character varying(255) null,
  status character varying(50) not null default 'active'::character varying,
  type character varying(50) not null,
  created_at timestamp with time zone not null default now(),
  updated_at timestamp with time zone not null default now(),
  constraint dashboard_users_pkey primary key (id),
  constraint dashboard_users_email_key unique (email),
  constraint dashboard_users_username_key unique (username),
  constraint dashboard_users_type_check check (
    (
      (type)::text = any (
        (
          array[
            'admin'::character varying,
            'manager'::character varying,
            'supervisor'::character varying,
            'employee'::character varying
          ]
        )::text[]
      )
    )
  )
);

-- Sessions table (Base sessions, distinct from stealth stealth_sessions)
CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    starttime TIMESTAMPTZ NOT NULL,
    endtime TIMESTAMPTZ,
    duration NUMERIC,
    total_videos_watched INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- User activities table
CREATE TABLE IF NOT EXISTS useractivities (
    id SERIAL PRIMARY KEY,
    userid INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    activitytype VARCHAR(255) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    metadata JSON,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- Videos table
CREATE TABLE IF NOT EXISTS videos (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    video_id VARCHAR NOT NULL,
    duration NUMERIC,
    watched INTEGER,
    loop_time INTEGER,
    status VARCHAR,
    sound_muted VARCHAR,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (session_id, video_id)
);

-- Video keys table
CREATE TABLE IF NOT EXISTS video_keys (
    id SERIAL PRIMARY KEY,
    video_id INTEGER NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
    key_value VARCHAR,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (video_id, key_value)
);

-- Video speeds table
CREATE TABLE IF NOT EXISTS video_speeds (
    id SERIAL PRIMARY KEY,
    video_id INTEGER NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
    speed_value NUMERIC,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (video_id, speed_value)
);

-- Inactivity table
CREATE TABLE IF NOT EXISTS inactivity (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    starttime TIMESTAMPTZ,
    endtime TIMESTAMPTZ,
    duration NUMERIC,
    type VARCHAR,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Queues table
CREATE TABLE IF NOT EXISTS queues (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    session_id VARCHAR NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    main_queue TEXT,
    main_queue_count INTEGER DEFAULT 0,
    subqueues JSONB DEFAULT '[]'::jsonb,
    subqueue_counts JSONB DEFAULT '{}'::jsonb,
    selected_subqueue TEXT,
    queue_count_old INTEGER DEFAULT 0,
    queue_count_new INTEGER DEFAULT 0,
    subqueue_count_old INTEGER DEFAULT 0,
    subqueue_count_new INTEGER DEFAULT 0,
    queue_id VARCHAR(50),
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT queues_session_id_name_key UNIQUE (session_id, name)
);

-- Session cards
CREATE TABLE IF NOT EXISTS cards (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    card_id VARCHAR NOT NULL,
    status VARCHAR(10) NOT NULL CHECK (status IN ('accept','reject')),
    queue_id VARCHAR NOT NULL,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (session_id, card_id)
);

-- ============================================
-- STEALTH MODULE TABLES
-- ============================================

-- App Configuration (Productive, Wasted, Neutral Apps/URLs)
CREATE TABLE IF NOT EXISTS app_config (
    id SERIAL PRIMARY KEY,
    config_type VARCHAR(255) NOT NULL UNIQUE, -- e.g., 'productivity_apps'
    data JSONB NOT NULL, -- Stores { "PRODUCTIVE_APPS": [...], ... }
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- User shifts table (extends users table for shift logic)
CREATE TABLE IF NOT EXISTS user_shifts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    shift_start TIME NOT NULL,
    shift_end TIME NOT NULL,
    breaktime_start TIME,
    breaktime_end TIME,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id)
);

-- Stealth bindings table (stores device binding and uninstall token)
CREATE TABLE IF NOT EXISTS stealth_bindings (
    id SERIAL PRIMARY KEY,
    device_id VARCHAR(255) NOT NULL UNIQUE,
    pc_name VARCHAR(255) NOT NULL,
    uninstall_token VARCHAR(255) NOT NULL,
    bound_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- User device mappings table (links users to authorized devices)
CREATE TABLE IF NOT EXISTS user_device_mappings (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, device_id)
);

-- User sessions table (stores stealth session data)
CREATE TABLE IF NOT EXISTS stealth_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    session_id VARCHAR(255) NOT NULL,
    date DATE NOT NULL,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ,
    productive_time NUMERIC DEFAULT 0,
    neutral_time NUMERIC DEFAULT 0,
    wasted_time NUMERIC DEFAULT 0,
    idle_time NUMERIC DEFAULT 0,
    break_time NUMERIC DEFAULT 0,
    total_time NUMERIC DEFAULT 0,
    device_id VARCHAR(255),
    last_updated TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    shift_status_start VARCHAR(50),
    shift_status_current VARCHAR(50),
    session_shift VARCHAR(50),
    system_name VARCHAR(255),
    os_version VARCHAR(255),
    domain VARCHAR(255),
    ip_address VARCHAR(50),
    user_in_db BOOLEAN DEFAULT false,
    is_mapped BOOLEAN DEFAULT false,
    windows_username VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, session_id)
);

-- Session usage breakdown table (stores categorized usage by domain/app)
CREATE TABLE IF NOT EXISTS session_usage_breakdown (
    id SERIAL PRIMARY KEY,
    user_session_id INTEGER NOT NULL REFERENCES stealth_sessions(id) ON DELETE CASCADE,
    category VARCHAR(50) NOT NULL CHECK (category IN ('productive', 'neutral', 'wasted', 'idle')),
    domain_or_app VARCHAR(255) NOT NULL,
    total_time NUMERIC NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_session_id, category, domain_or_app)
);

-- Session visits table (stores individual visits within usage breakdown)
CREATE TABLE IF NOT EXISTS session_visits (
    id SERIAL PRIMARY KEY,
    usage_breakdown_id INTEGER NOT NULL REFERENCES session_usage_breakdown(id) ON DELETE CASCADE,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================
-- BROWSER EXTENSION & WHITELISTING
-- ============================================

-- Whitelisted URLs table
CREATE TABLE IF NOT EXISTS whitelisted_urls (
    id SERIAL PRIMARY KEY,
    url VARCHAR(500) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Allowed Queues table
CREATE TABLE IF NOT EXISTS allowed_queues (
    id SERIAL PRIMARY KEY,
    queue_id VARCHAR(50),
    queue_name VARCHAR(500) NOT NULL,
    business_type VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================
-- INDEXES
-- ============================================

-- Indexes from base tables
CREATE INDEX IF NOT EXISTS idx_cards_queue_id ON cards (queue_id);
CREATE INDEX IF NOT EXISTS idx_cards_session_id ON cards (session_id);
CREATE INDEX IF NOT EXISTS idx_queues_session_id ON queues (session_id);

-- Indexes for stealth tables
CREATE INDEX IF NOT EXISTS idx_user_shifts_user_id ON user_shifts (user_id);
CREATE INDEX IF NOT EXISTS idx_stealth_bindings_device_id ON stealth_bindings (device_id);
CREATE INDEX IF NOT EXISTS idx_user_device_mappings_user_id ON user_device_mappings(user_id);
CREATE INDEX IF NOT EXISTS idx_user_device_mappings_device_id ON user_device_mappings(device_id);
CREATE INDEX IF NOT EXISTS idx_stealth_sessions_user_id ON stealth_sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_stealth_sessions_date ON stealth_sessions (date);
CREATE INDEX IF NOT EXISTS idx_stealth_sessions_session_id ON stealth_sessions (session_id);
CREATE INDEX IF NOT EXISTS idx_stealth_sessions_device_id ON stealth_sessions (device_id);
CREATE INDEX IF NOT EXISTS idx_stealth_sessions_windows_username ON stealth_sessions (windows_username);
CREATE INDEX IF NOT EXISTS idx_stealth_sessions_system_name ON stealth_sessions (system_name);
CREATE INDEX IF NOT EXISTS idx_session_usage_breakdown_user_session_id ON session_usage_breakdown (user_session_id);
CREATE INDEX IF NOT EXISTS idx_session_usage_breakdown_category ON session_usage_breakdown (category);
CREATE INDEX IF NOT EXISTS idx_session_visits_usage_breakdown_id ON session_visits (usage_breakdown_id);
CREATE INDEX IF NOT EXISTS idx_allowed_queues_queue_name ON allowed_queues (queue_name);
CREATE INDEX IF NOT EXISTS idx_allowed_queues_queue_id ON allowed_queues (queue_id);

-- ============================================
-- DEFAULT DATA
-- ============================================ 

-- Insert default user types
INSERT INTO usertypes (name, active) VALUES
    ('admin', true),
    ('moderator', true),
    ('qa', true),
    ('supervisor', true)
ON CONFLICT (name) DO NOTHING;
