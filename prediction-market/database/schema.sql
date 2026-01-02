-- ==================== TABLAS BASE ====================

-- Tabla de usuarios (compatible con tu modelo Flask)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    
    -- Compatible con Flask (FLOAT → NUMERIC)
    points_balance NUMERIC(15,2) DEFAULT 100.00,
    points_locked NUMERIC(15,2) DEFAULT 0.00,
    
    -- Campos adicionales de tu modelo Flask
    role VARCHAR(20) DEFAULT 'user',
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Estadísticas para compras (solo LONG)
    total_long_positions NUMERIC(15,4) DEFAULT 0,
    markets_traded_count INTEGER DEFAULT 0,
    total_buy_trades_count INTEGER DEFAULT 0,
    total_shares_bought NUMERIC(15,4) DEFAULT 0,
    
    -- Rate limiting
    buy_trades_last_hour INTEGER DEFAULT 0,
    shares_bought_last_hour NUMERIC(15,4) DEFAULT 0,
    rate_limit_reset_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Auditoría
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    session_token VARCHAR(64) UNIQUE
);

-- Índices para usuarios
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_session_token ON users(session_token);

-- Tabla de mercados (compatible con Flask)
CREATE TABLE markets (
    id SERIAL PRIMARY KEY,
    slug VARCHAR(100) UNIQUE NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    resolution_criteria TEXT NOT NULL,
    sources TEXT NOT NULL,
    notes TEXT,
    
    -- Parámetros LMSR (compatible con Flask)
    b NUMERIC(10,2) NOT NULL DEFAULT 100.00,
    q_yes NUMERIC(15,4) DEFAULT 0,
    q_no NUMERIC(15,4) DEFAULT 0,
    
    -- Estado del mercado
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'closed', 'resolved', 'voided')),
    result VARCHAR(10) CHECK (result IN ('YES', 'NO', 'CANCELED')),
    resolution_time TIMESTAMP,
    
    -- Tiempos importantes
    close_time TIMESTAMP NOT NULL,
    resolve_deadline TIMESTAMP NOT NULL,
    
    -- Límites específicos (del modelo Flask)
    max_long_position_per_user NUMERIC(15,4) DEFAULT 100000.0,
    max_shares_per_buy NUMERIC(15,4) DEFAULT 10000.0,
    
    -- Estadísticas (del modelo Flask)
    total_buy_trades INTEGER DEFAULT 0,
    unique_buyers INTEGER DEFAULT 0,
    
    -- Información de resolución
    resolved_by INTEGER REFERENCES users(id),
    resolution_evidence_url TEXT,
    resolution_notes TEXT,
    
    -- Contadores de integridad
    last_position_snapshot_id INTEGER,
    
    -- Bloqueo para prevenir doble resolución
    resolution_lock_token VARCHAR(64) UNIQUE,
    resolution_lock_expires TIMESTAMP,
    
    -- Auditoría
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    version INTEGER DEFAULT 1
);

-- Índices para mercados
CREATE INDEX idx_markets_status ON markets(status);
CREATE INDEX idx_markets_close_time ON markets(close_time);
CREATE INDEX idx_markets_resolved_by ON markets(resolved_by);
CREATE INDEX idx_markets_slug ON markets(slug);
CREATE INDEX idx_markets_created_at ON markets(created_at);

-- ==================== TABLAS DE TRADING (SIMPLIFICADAS PARA SOLO COMPRAS) ====================

-- Tabla de BUY trades (solo compras, compatible con Flask)
CREATE TABLE buy_trades (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    market_id INTEGER REFERENCES markets(id) ON DELETE CASCADE,
    outcome VARCHAR(10) NOT NULL CHECK (outcome IN ('YES', 'NO')),
    shares NUMERIC(15,4) NOT NULL CHECK (shares > 0), -- Solo positivo (compra)
    cost NUMERIC(15,4) NOT NULL, -- Siempre positivo (costo de compra)
    price_at_buy NUMERIC(10,4) NOT NULL,
    
    -- Auditoría
    ip_address VARCHAR(45),
    user_agent TEXT,
    session_token VARCHAR(64),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Índices para buy_trades
CREATE INDEX idx_buy_trades_user_id ON buy_trades(user_id);
CREATE INDEX idx_buy_trades_market_id ON buy_trades(market_id);
CREATE INDEX idx_buy_trades_timestamp ON buy_trades(timestamp);
CREATE INDEX idx_buy_trades_user_time ON buy_trades(user_id, timestamp);
CREATE INDEX idx_buy_trades_market_time ON buy_trades(market_id, timestamp);

-- Tabla de posiciones LONG (solo compras, compatible con Flask)
CREATE TABLE long_positions (
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    market_id INTEGER REFERENCES markets(id) ON DELETE CASCADE,
    
    -- Posición LONG actual (siempre positiva)
    shares_yes NUMERIC(15,4) DEFAULT 0 CHECK (shares_yes >= 0),
    shares_no NUMERIC(15,4) DEFAULT 0 CHECK (shares_no >= 0),
    total_shares NUMERIC(15,4) DEFAULT 0,
    total_invested NUMERIC(15,4) DEFAULT 0,
    
    -- Bloqueo para resolución
    locked_for_resolution BOOLEAN DEFAULT FALSE,
    
    -- Auditoría
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (user_id, market_id)
);

-- Índices para long_positions
CREATE INDEX idx_long_positions_market_id ON long_positions(market_id);
CREATE INDEX idx_long_positions_user_id ON long_positions(user_id);
CREATE INDEX idx_long_positions_locked ON long_positions(locked_for_resolution);

-- ==================== SISTEMA DE RESOLUCIÓN (MANTENIDO DE TU SCRIPT) ====================

-- SNAPSHOT de posiciones ANTES de resolución
CREATE TABLE market_position_snapshots (
    id SERIAL PRIMARY KEY,
    market_id INTEGER REFERENCES markets(id) ON DELETE CASCADE,
    
    -- Snapshot del mercado
    snapshot_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    pre_resolution_q_yes NUMERIC(15,4),
    pre_resolution_q_no NUMERIC(15,4),
    market_status_before VARCHAR(20),
    
    -- Total de acciones en el mercado (para verificación)
    total_shares_yes NUMERIC(15,4),
    total_shares_no NUMERIC(15,4),
    total_positions INTEGER,
    
    -- Usuario que creó el snapshot
    created_by INTEGER REFERENCES users(id),
    
    -- Checksum para integridad
    data_hash VARCHAR(64)
);

-- Tabla DETALLADA de snapshot de posiciones
CREATE TABLE position_snapshot_details (
    snapshot_id INTEGER REFERENCES market_position_snapshots(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    market_id INTEGER REFERENCES markets(id) ON DELETE CASCADE,
    
    -- Estado en el momento del snapshot
    shares_yes NUMERIC(15,4) DEFAULT 0,
    shares_no NUMERIC(15,4) DEFAULT 0,
    user_balance_before NUMERIC(15,4),
    
    PRIMARY KEY (snapshot_id, user_id, market_id)
);

-- LOTES de resolución (transacciones de pago grupales)
CREATE TABLE resolution_batches (
    id SERIAL PRIMARY KEY,
    market_id INTEGER REFERENCES markets(id) ON DELETE CASCADE,
    
    -- Información del batch
    batch_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    result VARCHAR(10) NOT NULL CHECK (result IN ('YES', 'NO', 'CANCELED')),
    
    -- Evidencia OBLIGATORIA
    evidence_url TEXT NOT NULL,
    evidence_description TEXT NOT NULL,
    evidence_source VARCHAR(100) NOT NULL,
    
    -- Usuario que ejecutó la resolución
    resolved_by INTEGER REFERENCES users(id),
    resolved_by_ip VARCHAR(45),
    resolved_by_user_agent TEXT,
    
    -- Estadísticas
    total_payout NUMERIC(15,4) DEFAULT 0,
    total_users_paid INTEGER DEFAULT 0,
    
    -- Estado del batch
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'reversed', 'failed')),
    reversal_reason TEXT,
    reversed_by INTEGER REFERENCES users(id),
    reversed_at TIMESTAMP,
    
    -- Checksum y auditoría
    data_hash VARCHAR(64),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- REGISTRO DETALLADO de pagos por usuario
CREATE TABLE resolution_payments (
    id SERIAL PRIMARY KEY,
    batch_id INTEGER REFERENCES resolution_batches(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    market_id INTEGER REFERENCES markets(id) ON DELETE CASCADE,
    
    -- Posición que generó el pago
    shares_yes NUMERIC(15,4) DEFAULT 0,
    shares_no NUMERIC(15,4) DEFAULT 0,
    
    -- Cálculo del pago
    payout_calculation TEXT,
    payout_amount NUMERIC(15,4) NOT NULL,
    
    -- Balance antes/después
    user_balance_before NUMERIC(15,4),
    user_balance_after NUMERIC(15,4),
    
    -- Estado
    payment_status VARCHAR(20) DEFAULT 'paid' CHECK (payment_status IN ('pending', 'paid', 'reversed', 'failed')),
    paid_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reversed_at TIMESTAMP
);

-- LOG de eventos de resolución (para auditoría completa)
CREATE TABLE resolution_audit_log (
    id SERIAL PRIMARY KEY,
    
    -- Evento
    event_type VARCHAR(50) NOT NULL CHECK (event_type IN (
        'snapshot_created',
        'resolution_started',
        'payment_processed',
        'resolution_completed',
        'resolution_reversed',
        'market_voided'
    )),
    
    -- Contexto
    market_id INTEGER REFERENCES markets(id) ON DELETE SET NULL,
    batch_id INTEGER REFERENCES resolution_batches(id) ON DELETE SET NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    
    -- Datos del evento
    event_data JSONB,
    
    -- Usuario y sistema
    performed_by INTEGER REFERENCES users(id),
    ip_address VARCHAR(45),
    user_agent TEXT,
    
    -- Timestamp
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de EVIDENCIA de resolución (múltiples fuentes)
CREATE TABLE resolution_evidence (
    id SERIAL PRIMARY KEY,
    market_id INTEGER REFERENCES markets(id) ON DELETE CASCADE,
    batch_id INTEGER REFERENCES resolution_batches(id) ON DELETE CASCADE,
    
    -- Tipo de evidencia
    evidence_type VARCHAR(50) NOT NULL CHECK (evidence_type IN (
        'official_statement',
        'news_article',
        'data_source',
        'screenshot',
        'video',
        'api_response'
    )),
    
    -- Contenido
    title VARCHAR(200) NOT NULL,
    description TEXT,
    url TEXT NOT NULL,
    source VARCHAR(100) NOT NULL,
    
    -- Metadatos
    publication_date DATE,
    retrieved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Validación
    is_official BOOLEAN DEFAULT FALSE,
    verified_by INTEGER REFERENCES users(id),
    verified_at TIMESTAMP
);

-- Tabla de CONFLICTOS de resolución
CREATE TABLE resolution_disputes (
    id SERIAL PRIMARY KEY,
    market_id INTEGER REFERENCES markets(id) ON DELETE CASCADE,
    batch_id INTEGER REFERENCES resolution_batches(id) ON DELETE CASCADE,
    
    -- Usuario que disputa
    disputed_by INTEGER REFERENCES users(id),
    dispute_reason TEXT NOT NULL,
    
    -- Evidencia de la disputa
    dispute_evidence_url TEXT,
    dispute_evidence_description TEXT,
    
    -- Estado
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'reviewing', 'resolved', 'dismissed')),
    resolution_notes TEXT,
    resolved_by INTEGER REFERENCES users(id),
    resolved_at TIMESTAMP,
    
    -- Auditoría
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de REVERSIÓN de resoluciones
CREATE TABLE resolution_reversals (
    id SERIAL PRIMARY KEY,
    
    -- Qué se revierte
    original_batch_id INTEGER REFERENCES resolution_batches(id) ON DELETE CASCADE,
    reversal_batch_id INTEGER REFERENCES resolution_batches(id) ON DELETE CASCADE,
    
    -- Motivo
    reason VARCHAR(100) NOT NULL CHECK (reason IN (
        'incorrect_result',
        'insufficient_evidence',
        'market_voided',
        'admin_error',
        'dispute_upheld'
    )),
    detailed_reason TEXT NOT NULL,
    
    -- Efecto
    markets_affected INTEGER DEFAULT 1,
    users_affected INTEGER,
    total_points_reversed NUMERIC(15,4),
    
    -- Auditoría
    reversed_by INTEGER REFERENCES users(id),
    reversed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    approval_by INTEGER REFERENCES users(id),
    approved_at TIMESTAMP
);

-- ==================== ÍNDICES ADICIONALES ====================

-- Índices para performance de resolución
CREATE INDEX idx_market_position_snapshots_market_id ON market_position_snapshots(market_id);
CREATE INDEX idx_market_position_snapshots_timestamp ON market_position_snapshots(snapshot_timestamp);

CREATE INDEX idx_position_snapshot_details_user_id ON position_snapshot_details(user_id);
CREATE INDEX idx_position_snapshot_details_market_id ON position_snapshot_details(market_id);

CREATE INDEX idx_resolution_batches_market_id ON resolution_batches(market_id);
CREATE INDEX idx_resolution_batches_status ON resolution_batches(status);
CREATE INDEX idx_resolution_batches_timestamp ON resolution_batches(batch_timestamp);

CREATE INDEX idx_resolution_payments_batch_id ON resolution_payments(batch_id);
CREATE INDEX idx_resolution_payments_user_id ON resolution_payments(user_id);
CREATE INDEX idx_resolution_payments_market_id ON resolution_payments(market_id);
CREATE INDEX idx_resolution_payments_payment_status ON resolution_payments(payment_status);

CREATE INDEX idx_resolution_audit_log_market_id ON resolution_audit_log(market_id);
CREATE INDEX idx_resolution_audit_log_batch_id ON resolution_audit_log(batch_id);
CREATE INDEX idx_resolution_audit_log_event_type ON resolution_audit_log(event_type);
CREATE INDEX idx_resolution_audit_log_created_at ON resolution_audit_log(created_at);

CREATE INDEX idx_resolution_evidence_market_id ON resolution_evidence(market_id);
CREATE INDEX idx_resolution_evidence_batch_id ON resolution_evidence(batch_id);
CREATE INDEX idx_resolution_evidence_source ON resolution_evidence(source);

CREATE INDEX idx_resolution_disputes_market_id ON resolution_disputes(market_id);
CREATE INDEX idx_resolution_disputes_batch_id ON resolution_disputes(batch_id);
CREATE INDEX idx_resolution_disputes_status ON resolution_disputes(status);

-- ==================== VISTAS (OPCIONALES, MANTENIDAS) ====================

-- Vista de mercados listos para resolver
CREATE OR REPLACE VIEW markets_ready_for_resolution AS
SELECT 
    m.id,
    m.slug,
    m.title,
    m.close_time,
    m.resolve_deadline,
    COUNT(DISTINCT lp.user_id) as total_traders,
    COUNT(bt.id) as total_trades,
    SUM(lp.shares_yes) as total_shares_yes,
    SUM(lp.shares_no) as total_shares_no,
    CASE 
        WHEN NOW() > m.resolve_deadline THEN 'OVERDUE'
        WHEN m.status = 'closed' THEN 'READY'
        ELSE 'NOT_READY'
    END as resolution_status
FROM markets m
LEFT JOIN long_positions lp ON m.id = lp.market_id
LEFT JOIN buy_trades bt ON m.id = bt.market_id
WHERE m.status = 'closed'
GROUP BY m.id, m.slug, m.title, m.close_time, m.resolve_deadline, m.status;

-- Vista de auditoría de resoluciones
CREATE OR REPLACE VIEW resolution_audit_summary AS
SELECT 
    rb.id as batch_id,
    m.slug,
    m.title,
    rb.result,
    rb.batch_timestamp,
    rb.resolved_by,
    u.username as resolver_username,
    rb.total_payout,
    rb.total_users_paid,
    rb.status as batch_status,
    COUNT(DISTINCT rp.id) as payments_count,
    COUNT(DISTINCT re.id) as evidence_count
FROM resolution_batches rb
JOIN markets m ON rb.market_id = m.id
LEFT JOIN users u ON rb.resolved_by = u.id
LEFT JOIN resolution_payments rp ON rb.id = rp.batch_id
LEFT JOIN resolution_evidence re ON rb.id = re.batch_id
GROUP BY rb.id, m.id, u.id;

-- ==================== COMENTARIOS ====================

COMMENT ON TABLE users IS 'Usuarios del sistema de predicciones (modo solo compras)';
COMMENT ON TABLE markets IS 'Mercados de predicción con LMSR (solo compras permitidas)';
COMMENT ON TABLE buy_trades IS 'Registro de todas las compras (no hay ventas)';
COMMENT ON TABLE long_positions IS 'Posiciones LONG actuales de los usuarios';
COMMENT ON TABLE resolution_batches IS 'Lotes de resolución con capacidad de rollback completo';
COMMENT ON TABLE market_position_snapshots IS 'Snapshots críticos para reversión de resoluciones';
COMMENT ON TABLE resolution_audit_log IS 'Auditoría completa de todas las acciones de resolución';

COMMENT ON COLUMN markets.resolution_evidence_url IS 'URL OBLIGATORIA a evidencia de resolución';
COMMENT ON COLUMN markets.resolution_lock_token IS 'Token para prevenir doble resolución concurrente';
COMMENT ON COLUMN users.role IS 'user, admin, moderator (del modelo Flask)';
COMMENT ON COLUMN users.is_active IS 'Si el usuario está activo (del modelo Flask)';

-- ==================== DATOS INICIALES (OPCIONAL) ====================

-- Insertar usuario admin por defecto (si quieres)
-- INSERT INTO users (username, email, password_hash, role, points_balance) 
-- VALUES ('admin', 'admin@predictionmarket.com', 'hashed_password_here', 'admin', 10000.00)
-- ON CONFLICT (username) DO NOTHING;
