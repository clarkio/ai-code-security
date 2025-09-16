-- Migration: 001_initial_schema.sql
-- Description: Create initial database schema with security features
-- Created: 2024-01-01

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create users table with encrypted email storage
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email_encrypted TEXT NOT NULL UNIQUE,
  email_hash TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  is_active BOOLEAN DEFAULT true,
  failed_login_attempts INTEGER DEFAULT 0,
  last_failed_login TIMESTAMP WITH TIME ZONE,
  account_locked_until TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  last_login_at TIMESTAMP WITH TIME ZONE,
  
  -- Security constraints
  CONSTRAINT users_email_encrypted_not_empty CHECK (length(email_encrypted) > 0),
  CONSTRAINT users_email_hash_not_empty CHECK (length(email_hash) > 0),
  CONSTRAINT users_password_hash_not_empty CHECK (length(password_hash) > 0),
  CONSTRAINT users_failed_attempts_non_negative CHECK (failed_login_attempts >= 0),
  CONSTRAINT users_failed_attempts_reasonable CHECK (failed_login_attempts <= 100)
);

-- Create notes table with encrypted content
CREATE TABLE IF NOT EXISTS notes (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title_encrypted TEXT NOT NULL,
  content_encrypted TEXT NOT NULL,
  encryption_iv TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  is_deleted BOOLEAN DEFAULT false,
  
  -- Security constraints
  CONSTRAINT notes_title_encrypted_not_empty CHECK (length(title_encrypted) > 0),
  CONSTRAINT notes_content_encrypted_not_empty CHECK (length(content_encrypted) > 0),
  CONSTRAINT notes_encryption_iv_not_empty CHECK (length(encryption_iv) > 0),
  CONSTRAINT notes_content_length_limit CHECK (length(content_encrypted) <= 50000)
);

-- Create audit_logs table for security event tracking
CREATE TABLE IF NOT EXISTS audit_logs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  action VARCHAR(50) NOT NULL,
  resource VARCHAR(50) NOT NULL,
  resource_id UUID,
  ip_address INET,
  user_agent TEXT,
  success BOOLEAN NOT NULL,
  error_message TEXT,
  additional_data JSONB,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  
  -- Security constraints
  CONSTRAINT audit_logs_action_not_empty CHECK (length(action) > 0),
  CONSTRAINT audit_logs_resource_not_empty CHECK (length(resource) > 0),
  CONSTRAINT audit_logs_user_agent_length CHECK (length(user_agent) <= 1000)
);

-- Create sessions table for session management
CREATE TABLE IF NOT EXISTS sessions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  session_id VARCHAR(255) NOT NULL UNIQUE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_id UUID NOT NULL,
  ip_address INET,
  user_agent TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  is_active BOOLEAN DEFAULT true,
  last_activity TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  
  -- Security constraints
  CONSTRAINT sessions_session_id_not_empty CHECK (length(session_id) > 0),
  CONSTRAINT sessions_expires_at_future CHECK (expires_at > created_at),
  CONSTRAINT sessions_user_agent_length CHECK (length(user_agent) <= 1000)
);

-- Create indexes for performance and security

-- Users table indexes
CREATE INDEX IF NOT EXISTS idx_users_email_hash ON users(email_hash);
CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login_at);
CREATE INDEX IF NOT EXISTS idx_users_account_locked ON users(account_locked_until) WHERE account_locked_until IS NOT NULL;

-- Notes table indexes
CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id);
CREATE INDEX IF NOT EXISTS idx_notes_user_created ON notes(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notes_is_deleted ON notes(is_deleted);
CREATE INDEX IF NOT EXISTS idx_notes_updated_at ON notes(updated_at);
CREATE INDEX IF NOT EXISTS idx_notes_user_active ON notes(user_id, is_deleted) WHERE is_deleted = false;

-- Audit logs indexes
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_ip_address ON audit_logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_audit_logs_success ON audit_logs(success);
CREATE INDEX IF NOT EXISTS idx_audit_logs_security_events ON audit_logs(timestamp DESC) 
  WHERE success = false OR action IN ('login_failed', 'account_locked', 'unauthorized_access');

-- Sessions table indexes
CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON sessions(session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_is_active ON sessions(is_active);
CREATE INDEX IF NOT EXISTS idx_sessions_cleanup ON sessions(expires_at, is_active) WHERE is_active = false;

-- Create trigger function for automatic timestamp updates
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for automatic timestamp updates
CREATE TRIGGER update_users_updated_at
  BEFORE UPDATE ON users
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_notes_updated_at
  BEFORE UPDATE ON notes
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- Enable Row Level Security (RLS) for notes table
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;

-- Create RLS policy for notes - users can only access their own notes
-- Note: This policy requires setting app.current_user_id in the session
CREATE POLICY notes_user_policy ON notes
  FOR ALL TO current_user
  USING (user_id = current_setting('app.current_user_id', true)::UUID);

-- Create a function to set the current user context
CREATE OR REPLACE FUNCTION set_current_user_id(user_uuid UUID)
RETURNS void AS $$
BEGIN
  PERFORM set_config('app.current_user_id', user_uuid::text, true);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create a function to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
  deleted_count INTEGER;
BEGIN
  DELETE FROM sessions 
  WHERE expires_at < CURRENT_TIMESTAMP 
     OR (is_active = false AND last_activity < CURRENT_TIMESTAMP - INTERVAL '24 hours');
  
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Create a function to clean up old audit logs
CREATE OR REPLACE FUNCTION cleanup_old_audit_logs(retention_days INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE
  deleted_count INTEGER;
BEGIN
  DELETE FROM audit_logs 
  WHERE timestamp < CURRENT_TIMESTAMP - (retention_days || ' days')::INTERVAL;
  
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Create a view for security monitoring
CREATE OR REPLACE VIEW security_events AS
SELECT 
  al.id,
  al.user_id,
  u.email_hash,
  al.action,
  al.resource,
  al.resource_id,
  al.ip_address,
  al.user_agent,
  al.success,
  al.error_message,
  al.timestamp
FROM audit_logs al
LEFT JOIN users u ON al.user_id = u.id
WHERE al.success = false 
   OR al.action IN (
     'login_failed', 'account_locked', 'unauthorized_access', 
     'security_violation', 'rate_limit_exceeded', 'invalid_token'
   )
ORDER BY al.timestamp DESC;

-- Grant appropriate permissions
-- Note: In production, create specific roles with minimal required permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON users TO current_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO current_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_logs TO current_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON sessions TO current_user;
GRANT SELECT ON security_events TO current_user;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO current_user;

-- Insert migration record
CREATE TABLE IF NOT EXISTS schema_migrations (
  version VARCHAR(255) PRIMARY KEY,
  applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO schema_migrations (version) VALUES ('001_initial_schema')
ON CONFLICT (version) DO NOTHING;