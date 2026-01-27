-- ==================== MIGRACIÓN: CAMPOS PREMIUM ADICIONALES ====================
-- Ejecutar este script DESPUÉS de tener las columnas básicas de premium

-- 1. Agregar campos de nicho y perfil público
ALTER TABLE users ADD COLUMN IF NOT EXISTS niche VARCHAR(200);
ALTER TABLE users ADD COLUMN IF NOT EXISTS cta_links JSON;
ALTER TABLE users ADD COLUMN IF NOT EXISTS public_profile_slug VARCHAR(100) UNIQUE;

-- 2. Agregar campos de verificación y watermark
ALTER TABLE users ADD COLUMN IF NOT EXISTS backlink_verified BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS watermark_enabled BOOLEAN DEFAULT TRUE;

-- 3. Agregar campos de invitación
ALTER TABLE users ADD COLUMN IF NOT EXISTS invite_code VARCHAR(50);
ALTER TABLE users ADD COLUMN IF NOT EXISTS invited_by INTEGER REFERENCES users(id);

-- 4. Crear índices para búsquedas rápidas
CREATE INDEX IF NOT EXISTS idx_users_public_profile_slug ON users(public_profile_slug);
CREATE INDEX IF NOT EXISTS idx_users_is_premium ON users(is_premium);
CREATE INDEX IF NOT EXISTS idx_users_niche ON users(niche);

-- 5. Crear tabla de códigos de invitación
CREATE TABLE IF NOT EXISTS invite_codes (
    code VARCHAR(50) PRIMARY KEY,
    created_by INTEGER REFERENCES users(id),
    max_uses INTEGER DEFAULT 1,
    current_uses INTEGER DEFAULT 0,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_invite_codes_active ON invite_codes(is_active);
CREATE INDEX IF NOT EXISTS idx_invite_codes_expires ON invite_codes(expires_at);

-- 6. Insertar código de invitación inicial (468314)
INSERT INTO invite_codes (code, created_by, max_uses, is_active)
VALUES ('468314', 1, 9999, TRUE)
ON CONFLICT (code) DO NOTHING;

-- 7. Comentarios para documentación
COMMENT ON COLUMN users.niche IS 'Nicho del analista: "NBA drops", "EPL", "Tennis"';
COMMENT ON COLUMN users.cta_links IS 'Array JSON de {label, url} para CTAs del perfil';
COMMENT ON COLUMN users.public_profile_slug IS 'URL amigable del perfil público: /analyst/:slug';
COMMENT ON COLUMN users.backlink_verified IS 'Si el usuario tiene backlink verificado a la plataforma';
COMMENT ON COLUMN users.watermark_enabled IS 'Si se muestra watermark en su perfil público';
COMMENT ON COLUMN users.invite_code IS 'Código usado para activar cuenta premium';
COMMENT ON COLUMN users.invited_by IS 'ID del usuario que generó el código de invitación';

COMMENT ON TABLE invite_codes IS 'Códigos de invitación para cuentas premium';
