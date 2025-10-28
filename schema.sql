-- PostgreSQL schema for Video Tracker Extension
-- Run this once to create the required tables

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(15) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(64) PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    starttime TIMESTAMP WITH TIME ZONE NOT NULL,
    endtime TIMESTAMP WITH TIME ZONE,
    duration NUMERIC,
    total_videos_watched INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS videos (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    video_id VARCHAR(1000) NOT NULL,
    duration NUMERIC DEFAULT 0,
    watched INTEGER DEFAULT 0,
    loop_time INTEGER DEFAULT 0,
    status VARCHAR(50) DEFAULT 'Not Watched',
    sound_muted VARCHAR(3) DEFAULT 'no',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (session_id, video_id)
);

CREATE TABLE IF NOT EXISTS video_keys (
    id SERIAL PRIMARY KEY,
    video_id INTEGER NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
    key_value VARCHAR(1000) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (video_id, key_value)
);

CREATE TABLE IF NOT EXISTS video_speeds (
    id SERIAL PRIMARY KEY,
    video_id INTEGER NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
    speed_value NUMERIC NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (video_id, speed_value)
);

CREATE TABLE IF NOT EXISTS inactivity (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    starttime TIMESTAMP WITH TIME ZONE,
    endtime TIMESTAMP WITH TIME ZONE,
    duration NUMERIC,
    type VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
