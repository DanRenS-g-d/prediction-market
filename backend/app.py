from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import select, update, and_, func, or_, text
from sqlalchemy.orm import Session, joinedload
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from datetime import datetime, timedelta
import math
import logging
import jwt
import bcrypt
import os
import re
import decimal
from functools import wraps
import json
import secrets
from dotenv import load_dotenv
from flask_cors import CORS

# Cargar variables de entorno
load_dotenv()

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

CORS(app, resources={r"/api/*": {"origins": "*"}})
logger.info("✅ CORS habilitado para todos los orígenes")

# ==================== CONFIGURACIÓN DE BASE DE DATOS ====================
# Configuración para Railway (PostgreSQL) o SQLite local
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL:
    # Railway proporciona DATABASE_URL, convertir a formato SQLAlchemy
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
    logger.info("Usando PostgreSQL (Railway)")
else:
    # Para desarrollo local
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///prediction_market.db'
    logger.info("Usando SQLite (desarrollo local)")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'pool_size': 10,
    'max_overflow': 20,
}

# ==================== VERIFICACIÓN DE VARIABLES DE ENTORNO ====================
# Variables críticas para producción
SECRET_KEY = os.environ.get('SECRET_KEY')
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')

# En producción, requerir secrets
if os.environ.get('FLASK_ENV') == 'production':
    if not SECRET_KEY or not JWT_SECRET_KEY:
        raise ValueError(
            "Faltan variables de entorno requeridas en producción: "
            "SECRET_KEY, JWT_SECRET_KEY"
        )
else:
    # En desarrollo, usar defaults seguros
    SECRET_KEY = SECRET_KEY or secrets.token_hex(32)
    JWT_SECRET_KEY = JWT_SECRET_KEY or secrets.token_hex(32)

# ==================== CONFIGURACIÓN MVP ====================
app.config['SECRET_KEY'] = SECRET_KEY
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
app.config['JWT_ALGORITHM'] = 'HS256'
app.config['JWT_EXPIRATION_HOURS'] = 24
app.config['BCRYPT_ROUNDS'] = 12

# Para MVP: SÓLO COMPRAS, NO VENTAS
app.config['ALLOW_SELLING'] = False  # Deshabilitar ventas completamente
app.config['ALLOW_SHORTING'] = False  # Deshabilitar short selling

# Límites por usuario (solo para compras)
app.config['LIMITS'] = {
    # Límites por trade (COMPRA)
    'MAX_SHARES_PER_TRADE': 10000.0,        # 10k acciones máximo por trade de COMPRA
    'MIN_SHARES_PER_TRADE': 0.01,           # Mínimo 0.01 acciones para COMPRA
    
    # Límites por posición (solo posiciones LARGAS)
    'MAX_POSITION_PER_MARKET': 100000.0,    # 100k acciones máximo por mercado (LONG)
    'MAX_EXPOSURE_PERCENT': 0.30,           # Máximo 30% del mercado (LONG)
    
    # Límites globales
    'MAX_TOTAL_POSITIONS': 500000.0,        # 500k acciones totales (LONG)
    'MAX_MARKETS_PER_USER': 50,             # Máximo 50 mercados diferentes
    
    # Rate limits
    'MAX_TRADES_PER_HOUR': 100,             # 100 trades de COMPRA por hora
    'MAX_SHARES_PER_HOUR': 100000.0,        # 100k acciones de COMPRA por hora
    
    # Protección de precio
    'MAX_PRICE_IMPACT_PER_TRADE': 0.05,     # Máximo 5% de impacto en precio por COMPRA
}

db = SQLAlchemy(app)

# ==================== MODELOS SIMPLIFICADOS ====================
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(100), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    
    role = db.Column(db.String(20), default='user', nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # PREMIUM ACCOUNT FIELDS - ADD THESE
    is_premium = db.Column(db.Boolean, default=False, nullable=False)
    display_name = db.Column(db.String(100))  # Real name for premium users
    profile_image_url = db.Column(db.String(500))  # Profile picture URL
    bio = db.Column(db.Text)  # User bio/description
    premium_since = db.Column(db.DateTime)  # When they became premium
    credentials = db.Column(db.Text)  # Professional credentials
    
    # Solo posiciones LONG
    points_balance = db.Column(db.Float, default=100.00, nullable=False)
    
    # Estadísticas para COMPRAS
    total_long_positions = db.Column(db.Float, default=0.0, nullable=False)  # Solo LONG
    markets_traded_count = db.Column(db.Integer, default=0, nullable=False)
    total_buy_trades_count = db.Column(db.Integer, default=0, nullable=False)
    total_shares_bought = db.Column(db.Float, default=0.0, nullable=False)
    
    # Rate limiting solo para COMPRAS
    buy_trades_last_hour = db.Column(db.Integer, default=0, nullable=False)
    shares_bought_last_hour = db.Column(db.Float, default=0.0, nullable=False)
    rate_limit_reset_time = db.Column(db.DateTime, default=datetime.utcnow)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    session_token = db.Column(db.String(64), unique=True, index=True)
    
    # Solo posiciones LONG
    long_positions = db.relationship('LongPosition', backref='user', lazy=True, cascade="all, delete-orphan")
    buy_trades = db.relationship('BuyTrade', backref='user', lazy=True, cascade="all, delete-orphan")
    
    # Métodos para manejo de contraseñas
    def set_password(self, password):
        """Hash y guarda la contraseña"""
        self.password_hash = bcrypt.hashpw(
            password.encode('utf-8'), 
            bcrypt.gensalt(app.config['BCRYPT_ROUNDS'])
        ).decode('utf-8')
    
    def check_password(self, password):
        """Verifica la contraseña"""
        if not self.password_hash:
            return False
        return bcrypt.checkpw(
            password.encode('utf-8'), 
            self.password_hash.encode('utf-8')
        )
    
    def generate_session_token(self):
        """Genera un token de sesión único"""
        self.session_token = secrets.token_hex(32)
        return self.session_token
    
def to_dict(self, include_sensitive=False):
        """Devuelve dict del usuario con manejo de premium"""
        data = {
            'id': self.id,
            'username': self.username if self.is_premium else f'Anon#{self.id}',
            'is_premium': self.is_premium,
            'role': self.role,  # Necesario para verificar admin en frontend
            'points_balance': self.points_balance,
            'stats': {
                'total_long_positions': self.total_long_positions,
                'markets_traded_count': self.markets_traded_count,
                'total_buy_trades': self.total_buy_trades_count,
                'total_shares_bought': self.total_shares_bought
            },
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
        
        # Solo mostrar detalles premium si el usuario es premium
        if self.is_premium:
            data.update({
                'display_name': self.display_name,
                'profile_image_url': self.profile_image_url,
                'bio': self.bio,
                'credentials': self.credentials,
                'premium_since': self.premium_since.isoformat() if self.premium_since else None
            })
        
        return data

class Market(db.Model):
    __tablename__ = 'markets'
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(100), unique=True, nullable=False, index=True)
    title = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text)
    resolution_criteria = db.Column(db.Text, nullable=False)
    sources = db.Column(db.Text, nullable=False)
    notes = db.Column(db.Text)
    
    # Parámetros LMSR (solo para COMPRAS)
    b = db.Column(db.Float, default=100.0, nullable=False)
    q_yes = db.Column(db.Float, default=0.0, nullable=False)  # COMPRAS de YES
    q_no = db.Column(db.Float, default=0.0, nullable=False)   # COMPRAS de NO
    
    # Estadísticas (solo COMPRAS)
    total_buy_trades = db.Column(db.Integer, default=0, nullable=False)
    unique_buyers = db.Column(db.Integer, default=0, nullable=False)
    
    status = db.Column(db.String(20), default='open', nullable=False, index=True)
    result = db.Column(db.String(10), index=True)
    resolution_time = db.Column(db.DateTime, index=True)
    
    close_time = db.Column(db.DateTime, nullable=False, index=True)
    resolve_deadline = db.Column(db.DateTime, nullable=False)
    
    resolved_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    resolution_evidence_url = db.Column(db.Text)
    resolution_notes = db.Column(db.Text)
    
    # Límites específicos (solo para COMPRAS)
    max_long_position_per_user = db.Column(db.Float, default=100000.0)
    max_shares_per_buy = db.Column(db.Float, default=10000.0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Solo posiciones LONG
    long_positions = db.relationship('LongPosition', backref='market', lazy=True, cascade="all, delete-orphan")
    buy_trades = db.relationship('BuyTrade', backref='market', lazy=True, cascade="all, delete-orphan")
    
    @property
    def price_yes(self):
        return self._calculate_price('YES')
    
    @property
    def price_no(self):
        return self._calculate_price('NO')
    
    @property
    def total_liquidity(self):
        """Liquidez total (solo posiciones LONG)"""
        return self.q_yes + self.q_no
    
    def _calculate_price(self, outcome):
        """Calcula precio para COMPRA"""
        try:
            if outcome == 'YES':
                exp = math.exp(self.q_yes / self.b)
                exp_other = math.exp(self.q_no / self.b)
            else:
                exp = math.exp(self.q_no / self.b)
                exp_other = math.exp(self.q_yes / self.b)
            
            total = exp + exp_other
            return exp / total if total > 0 else 0.5
        except Exception as e:
            logger.error(f"Error calculando precio: {str(e)}")
            return 0.5

class LongPosition(db.Model):
    """Solo posiciones LONG (compradas, nunca vendidas)"""
    __tablename__ = 'long_positions'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    market_id = db.Column(db.Integer, db.ForeignKey('markets.id'), primary_key=True)
    
    # Solo posiciones LONG positivas
    shares_yes = db.Column(db.Float, default=0.0, nullable=False)  # COMPRADAS
    shares_no = db.Column(db.Float, default=0.0, nullable=False)   # COMPRADAS
    total_shares = db.Column(db.Float, default=0.0, nullable=False)  # Total LONG
    
    # Solo inversión en COMPRAS
    total_invested = db.Column(db.Float, default=0.0, nullable=False)
    
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    __table_args__ = (
        db.Index('idx_long_position_user', 'user_id'),
        db.Index('idx_long_position_market', 'market_id'),
    )
    
    @property
    def current_value(self):
        """Valor actual de la posición LONG"""
        market = Market.query.get(self.market_id)
        if market:
            return (self.shares_yes * market.price_yes + 
                    self.shares_no * market.price_no)
        return 0.0
    
    @property
    def profit_loss(self):
        """P&L de la posición LONG"""
        return self.current_value - self.total_invested

class BuyTrade(db.Model):
    """Solo trades de COMPRA (nunca ventas)"""
    __tablename__ = 'buy_trades'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    market_id = db.Column(db.Integer, db.ForeignKey('markets.id'), nullable=False, index=True)
    
    outcome = db.Column(db.String(10), nullable=False)  # 'YES' o 'NO' (COMPRA)
    shares = db.Column(db.Float, nullable=False)        # Shares COMPRADAS
    cost = db.Column(db.Float, nullable=False)          # Puntos gastados en COMPRA
    price_at_buy = db.Column(db.Float, nullable=False)  # Precio en momento de COMPRA
    
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    session_token = db.Column(db.String(64), index=True)
    
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    __table_args__ = (
        db.Index('idx_buy_trade_user_time', 'user_id', 'timestamp'),
        db.Index('idx_buy_trade_market_time', 'market_id', 'timestamp'),
    )

# ==================== MODELOS DE RESOLUCIÓN ====================

class MarketPositionSnapshot(db.Model):
    """Snapshot de posiciones antes de resolución"""
    __tablename__ = 'market_position_snapshots'
    id = db.Column(db.Integer, primary_key=True)
    market_id = db.Column(db.Integer, db.ForeignKey('markets.id'), nullable=False)
    
    # Snapshot del mercado
    snapshot_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    pre_resolution_q_yes = db.Column(db.Float, nullable=False)
    pre_resolution_q_no = db.Column(db.Float, nullable=False)
    market_status_before = db.Column(db.String(20), nullable=False)
    
    # Total de acciones en el mercado
    total_shares_yes = db.Column(db.Float, nullable=False)
    total_shares_no = db.Column(db.Float, nullable=False)
    total_positions = db.Column(db.Integer, nullable=False)
    
    # Usuario que creó el snapshot
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Checksum para integridad
    data_hash = db.Column(db.String(64))
    
    # Relaciones
    market = db.relationship('Market', backref='snapshots')
    details = db.relationship('PositionSnapshotDetail', backref='snapshot', cascade='all, delete-orphan')
    
    __table_args__ = (
        db.Index('idx_snapshots_market', 'market_id'),
        db.Index('idx_snapshots_timestamp', 'snapshot_timestamp'),
    )

class PositionSnapshotDetail(db.Model):
    """Detalle de snapshot de posición individual"""
    __tablename__ = 'position_snapshot_details'
    snapshot_id = db.Column(db.Integer, db.ForeignKey('market_position_snapshots.id'), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    market_id = db.Column(db.Integer, db.ForeignKey('markets.id'), primary_key=True)
    
    # Estado en el momento del snapshot
    shares_yes = db.Column(db.Float, default=0.0)
    shares_no = db.Column(db.Float, default=0.0)
    user_balance_before = db.Column(db.Float, nullable=False)
    
    # Relaciones
    user = db.relationship('User', backref='snapshot_details')
    market = db.relationship('Market', backref='position_snapshots')
    
    __table_args__ = (
        db.Index('idx_snapshot_details_user', 'user_id'),
        db.Index('idx_snapshot_details_market', 'market_id'),
    )

class ResolutionBatch(db.Model):
    """Lote de resolución"""
    __tablename__ = 'resolution_batches'
    id = db.Column(db.Integer, primary_key=True)
    market_id = db.Column(db.Integer, db.ForeignKey('markets.id'), nullable=False)
    
    # Información del batch
    batch_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    result = db.Column(db.String(10), nullable=False)
    
    # Evidencia OBLIGATORIA
    evidence_url = db.Column(db.Text, nullable=False)
    evidence_description = db.Column(db.Text, nullable=False)
    evidence_source = db.Column(db.String(100), nullable=False)
    
    # Usuario que ejecutó la resolución
    resolved_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    resolved_by_ip = db.Column(db.String(45))
    
    # Estadísticas
    total_payout = db.Column(db.Float, default=0.0)
    total_users_paid = db.Column(db.Integer, default=0)
    
    # Estado del batch
    status = db.Column(db.String(20), default='pending')
    reversal_reason = db.Column(db.Text)
    reversed_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    reversed_at = db.Column(db.DateTime)
    
    # Checksum y auditoría
    data_hash = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relaciones
    market = db.relationship('Market', backref='resolution_batches')
    resolver = db.relationship('User', foreign_keys=[resolved_by])
    payments = db.relationship('ResolutionPayment', backref='batch', cascade='all, delete-orphan')
    evidence = db.relationship(
        'ResolutionEvidence', 
        backref='resolution_batch', 
        cascade='all, delete-orphan',
        overlaps="batch_evidence,batch"
    )
    
    __table_args__ = (
        db.Index('idx_batches_market', 'market_id'),
        db.Index('idx_batches_status', 'status'),
        db.Index('idx_batches_timestamp', 'batch_timestamp'),
    )

class ResolutionPayment(db.Model):
    """Pago individual por resolución"""
    __tablename__ = 'resolution_payments'
    id = db.Column(db.Integer, primary_key=True)
    batch_id = db.Column(db.Integer, db.ForeignKey('resolution_batches.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    market_id = db.Column(db.Integer, db.ForeignKey('markets.id'), nullable=False)
    
    # Posición que generó el pago
    shares_yes = db.Column(db.Float, default=0.0)
    shares_no = db.Column(db.Float, default=0.0)
    
    # Cálculo del pago
    payout_calculation = db.Column(db.Text)
    payout_amount = db.Column(db.Float, nullable=False)
    
    # Balance antes/después
    user_balance_before = db.Column(db.Float)
    user_balance_after = db.Column(db.Float)
    
    # Estado
    payment_status = db.Column(db.String(20), default='paid')
    paid_at = db.Column(db.DateTime, default=datetime.utcnow)
    reversed_at = db.Column(db.DateTime)
    
    # Relaciones
    user = db.relationship('User', backref='resolution_payments')
    market = db.relationship('Market', backref='payments')
    
    __table_args__ = (
        db.Index('idx_payments_batch', 'batch_id'),
        db.Index('idx_payments_user', 'user_id'),
        db.Index('idx_payments_market', 'market_id'),
        db.Index('idx_payments_payment_status', 'payment_status'),
    )

class ResolutionAuditLog(db.Model):
    """Log de auditoría de resolución"""
    __tablename__ = 'resolution_audit_log'
    id = db.Column(db.Integer, primary_key=True)
    
    # Evento
    event_type = db.Column(db.String(50), nullable=False)
    
    # Contexto
    market_id = db.Column(db.Integer, db.ForeignKey('markets.id'))
    batch_id = db.Column(db.Integer, db.ForeignKey('resolution_batches.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Datos del evento
    event_data = db.Column(db.JSON)
    
    # Usuario y sistema
    performed_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    
    # Timestamp
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Relaciones
    market = db.relationship('Market', backref='audit_logs')
    batch = db.relationship('ResolutionBatch', backref='audit_logs')
    performer = db.relationship('User', foreign_keys=[performed_by])
    
    __table_args__ = (
        db.Index('idx_audit_market', 'market_id'),
        db.Index('idx_audit_batch', 'batch_id'),
        db.Index('idx_audit_event_type', 'event_type'),
        db.Index('idx_audit_created_at', 'created_at'),
    )

class ResolutionEvidence(db.Model):
    """Evidencia de resolución"""
    __tablename__ = 'resolution_evidence'
    id = db.Column(db.Integer, primary_key=True)
    market_id = db.Column(db.Integer, db.ForeignKey('markets.id'), nullable=False)
    batch_id = db.Column(db.Integer, db.ForeignKey('resolution_batches.id'), nullable=False)
    
    # Tipo de evidencia
    evidence_type = db.Column(db.String(50), nullable=False)
    
    # Contenido
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    url = db.Column(db.Text, nullable=False)
    source = db.Column(db.String(100), nullable=False)
    
    # Metadatos
    publication_date = db.Column(db.Date)
    retrieved_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Validación
    is_official = db.Column(db.Boolean, default=False)
    verified_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    verified_at = db.Column(db.DateTime)
    
    # Relaciones
    market = db.relationship('Market', backref='evidence')
    batch = db.relationship(
        'ResolutionBatch', 
        backref='batch_evidence',
        overlaps="evidence,resolution_batch"
    )
    verifier = db.relationship('User', foreign_keys=[verified_by])
    
    __table_args__ = (
        db.Index('idx_evidence_market', 'market_id'),
        db.Index('idx_evidence_batch', 'batch_id'),
        db.Index('idx_evidence_source', 'source'),
    )
    
# ==================== DECORADORES ====================
def require_auth(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Autenticación requerida'}), 401
        
        token = auth_header.split(' ')[1]
        try:
            payload = jwt.decode(
                token, 
                app.config['JWT_SECRET_KEY'], 
                algorithms=[app.config['JWT_ALGORITHM']]
            )
            user = User.query.filter_by(
                id=payload['user_id'],
                is_active=True
            ).first()
            
            if not user:
                return jsonify({'error': 'Usuario no encontrado'}), 404
            
            return func(*args, **kwargs, current_user=user)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token inválido'}), 401
        except Exception as e:
            logger.error(f"Error de autenticación: {str(e)}")
            return jsonify({'error': 'Error de autenticación'}), 401
    return wrapper

def transactional(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        session = Session(db.engine)
        try:
            # PostgreSQL usa SERIALIZABLE, SQLite no lo soporta completamente
            if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI']:
                session.connection(
                    execution_options={'isolation_level': 'SERIALIZABLE'}
                )
            result = func(session, *args, **kwargs)
            session.commit()
            return result
        except Exception as e:
            session.rollback()
            logger.error(f"Transaction failed: {str(e)}", exc_info=True)
            return jsonify({'error': 'Transacción fallida', 'details': str(e)}), 500
        finally:
            session.close()
    return wrapper

# ==================== DECORADOR ADMIN ====================
def require_admin(func):
    """Decorador que requiere que el usuario sea admin"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Autenticación requerida'}), 401
        
        token = auth_header.split(' ')[1]
        try:
            payload = jwt.decode(
                token, 
                app.config['JWT_SECRET_KEY'], 
                algorithms=[app.config['JWT_ALGORITHM']]
            )
            user = User.query.filter_by(
                id=payload['user_id'],
                is_active=True,
                role='admin'  # Solo admin
            ).first()
            
            if not user:
                return jsonify({'error': 'Acceso denegado. Requiere rol admin'}), 403
            
            return func(*args, **kwargs, current_user=user)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token inválido'}), 401
    return wrapper

# ==================== SISTEMA DE LÍMITES (SOLO COMPRAS) ====================
class BuyLimitManager:
    """Gestor de límites solo para COMPRAS"""
    
    @staticmethod
    def check_buy_limits(session, user_id: int, market_id: int, 
                        outcome: str, shares: float) -> list:
        """Verifica límites para una COMPRA"""
        errors = []
        
        try:
            user = session.execute(
                select(User).where(User.id == user_id).with_for_update()
            ).scalar_one()
            
            market = session.execute(
                select(Market).where(Market.id == market_id).with_for_update()
            ).scalar_one()
            
            # 1. Límite por trade de COMPRA
            max_per_buy = min(
                app.config['LIMITS']['MAX_SHARES_PER_TRADE'],
                market.max_shares_per_buy
            )
            
            if shares > max_per_buy:
                errors.append(f"Máximo por compra: {max_per_buy:.2f} acciones")
            
            if shares < app.config['LIMITS']['MIN_SHARES_PER_TRADE']:
                errors.append(f"Mínimo por compra: {app.config['LIMITS']['MIN_SHARES_PER_TRADE']:.2f} acciones")
            
            # 2. Obtener posición LONG actual
            position = session.execute(
                select(LongPosition)
                .where(
                    and_(
                        LongPosition.user_id == user_id,
                        LongPosition.market_id == market_id
                    )
                )
            ).scalar_one_or_none()
            
            current_shares = position.total_shares if position else 0.0
            
            # 3. Límite de posición LONG por mercado
            new_total = current_shares + shares
            max_position = min(
                app.config['LIMITS']['MAX_POSITION_PER_MARKET'],
                market.max_long_position_per_user
            )
            
            if new_total > max_position:
                errors.append(f"Máximo por mercado: {max_position:.2f} acciones")
            
            # 4. Límite de exposición (solo LONG)
            new_market_liquidity = market.total_liquidity + shares
            
            # Solo verificar exposición si el mercado ya tiene liquidez
            if new_market_liquidity > shares: #Si no es la primera compra
                user_exposure = new_total / new_market_liquidity
                if user_exposure > app.config['LIMITS']['MAX_EXPOSURE_PERCENT']:
                    errors.append(f"Máxima exposición: {app.config['LIMITS']['MAX_EXPOSURE_PERCENT']*100:.1f}%")
            
            # 5. Límite total de posiciones LONG
            new_total_long = user.total_long_positions + shares
            if new_total_long > app.config['LIMITS']['MAX_TOTAL_POSITIONS']:
                errors.append(f"Máximo total: {app.config['LIMITS']['MAX_TOTAL_POSITIONS']:.2f} acciones")
            
            # 6. Límite de mercados (solo para nuevas posiciones LONG)
            if position is None and user.markets_traded_count >= app.config['LIMITS']['MAX_MARKETS_PER_USER']:
                errors.append(f"Máximo {app.config['LIMITS']['MAX_MARKETS_PER_USER']} mercados")
            
            # 7. Rate limits para COMPRAS
            BuyLimitManager._check_buy_rate_limits(user, shares, errors)
            
            # 8. Impacto en precio por COMPRA
            BuyLimitManager._check_buy_price_impact(market, shares, outcome, errors)
            
            return errors
            
        except Exception as e:
            logger.error(f"Error checking buy limits: {str(e)}")
            return [f"Error interno: {str(e)}"]
    
    @staticmethod
    def _check_buy_rate_limits(user: User, shares: float, errors: list):
        """Rate limits solo para COMPRAS"""
        # Reset si ha pasado una hora
        reset_time = user.rate_limit_reset_time or datetime.utcnow()
        if datetime.utcnow() > reset_time + timedelta(hours=1):
            user.buy_trades_last_hour = 0
            user.shares_bought_last_hour = 0.0
            user.rate_limit_reset_time = datetime.utcnow()
        
        # Límite de compras por hora
        if user.buy_trades_last_hour >= app.config['LIMITS']['MAX_TRADES_PER_HOUR']:
            time_left = (reset_time + timedelta(hours=1) - datetime.utcnow())
            minutes = int(time_left.total_seconds() / 60)
            errors.append(f"Máximo {app.config['LIMITS']['MAX_TRADES_PER_HOUR']} compras por hora. Espera {minutes} min")
        
        # Límite de acciones compradas por hora
        new_hourly = user.shares_bought_last_hour + shares
        if new_hourly > app.config['LIMITS']['MAX_SHARES_PER_HOUR']:
            time_left = (reset_time + timedelta(hours=1) - datetime.utcnow())
            minutes = int(time_left.total_seconds() / 60)
            errors.append(f"Máximo {app.config['LIMITS']['MAX_SHARES_PER_HOUR']:.0f} acciones por hora. Espera {minutes} min")
    
    @staticmethod
    def _check_buy_price_impact(market: Market, shares: float, outcome: str, errors: list):
        """Impacto en precio por COMPRA"""
        try:
            # Calcular precio actual
            if outcome == 'YES':
                price_before = market.price_yes
                new_q_yes = market.q_yes + shares
                new_q_no = market.q_no
            else:
                price_before = market.price_no
                new_q_yes = market.q_yes
                new_q_no = market.q_no + shares
            
            # Calcular precio después
            if outcome == 'YES':
                exp_after = math.exp(new_q_yes / market.b)
                exp_other = math.exp(new_q_no / market.b)
            else:
                exp_after = math.exp(new_q_no / market.b)
                exp_other = math.exp(new_q_yes / market.b)
            
            total_after = exp_after + exp_other
            price_after = exp_after / total_after if total_after > 0 else 0.5
            
            # Calcular impacto
            if price_before > 0:
                impact = abs(price_after - price_before) / price_before
            else:
                impact = 0
            
            if impact > app.config['LIMITS']['MAX_PRICE_IMPACT_PER_TRADE']:
                errors.append(f"Impacto en precio muy alto: {impact*100:.1f}% (máx: {app.config['LIMITS']['MAX_PRICE_IMPACT_PER_TRADE']*100:.1f}%)")
                
        except Exception as e:
            logger.warning(f"Error calculando impacto: {str(e)}")

# ==================== FUNCIONES DE IMPORTACIÓN DE MERCADOS ====================

def import_markets_from_json(filename: str):
    """Importa mercados desde un archivo JSON"""
    try:
        import json
        from datetime import datetime
        
        logger.info(f"Intentando importar mercados desde {filename}")
        
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Manejar diferentes formatos de JSON
        # Formato 1: Array directo de mercados
        # Formato 2: Objeto con clave "markets" (como tu archivo actual)
        if isinstance(data, dict) and 'markets' in data:
            logger.info(f"Detectado formato con clave 'markets', extrayendo {len(data['markets'])} mercados")
            markets_data = data['markets']
        elif isinstance(data, list):
            logger.info(f"Detectado formato array directo con {len(data)} mercados")
            markets_data = data
        else:
            logger.error(f"Formato JSON no reconocido. Esperado: array o objeto con clave 'markets'")
            raise ValueError("Formato JSON no reconocido")
        
        imported_count = 0
        skipped_count = 0
        
        for market_data in markets_data:
            # Verificar si el mercado ya existe
            existing_market = Market.query.filter_by(slug=market_data['slug']).first()
            if existing_market:
                logger.info(f"✅ Mercado ya existe: {market_data['slug']}")
                skipped_count += 1
                continue
            
            # Parsear fechas - manejar diferentes formatos
            close_time_str = market_data['close_time']
            resolve_deadline_str = market_data['resolve_deadline']
            
            # Normalizar formato de fecha (agregar Z si no tiene zona horaria)
            if 'Z' not in close_time_str and '+' not in close_time_str:
                close_time_str = close_time_str + 'Z'
            if 'Z' not in resolve_deadline_str and '+' not in resolve_deadline_str:
                resolve_deadline_str = resolve_deadline_str + 'Z'
            
            # Convertir a datetime
            close_time = datetime.fromisoformat(close_time_str.replace('Z', '+00:00'))
            resolve_deadline = datetime.fromisoformat(resolve_deadline_str.replace('Z', '+00:00'))
            
            # Crear nuevo mercado
            market = Market(
                slug=market_data['slug'],
                title=market_data['title'],
                description=market_data.get('description', ''),
                resolution_criteria=market_data['resolution_criteria'],
                sources=market_data.get('sources', ''),
                notes=market_data.get('notes', 'Mercado de solo compras'),
                b=float(market_data.get('b', 100.0)),
                q_yes=float(market_data.get('q_yes', 0.0)),
                q_no=float(market_data.get('q_no', 0.0)),
                close_time=close_time,
                resolve_deadline=resolve_deadline,
                max_shares_per_buy=float(market_data.get('max_shares_per_buy', 10000.0)),
                max_long_position_per_user=float(market_data.get('max_long_position_per_user', 100000.0)),
                status=market_data.get('status', 'open')
            )
            
            db.session.add(market)
            imported_count += 1
            
            logger.info(f"➕ Mercado creado: {market.slug} (cierre: {close_time})")
        
        db.session.commit()
        
        logger.info(f"✅ Importación completada: {imported_count} nuevos, {skipped_count} existentes")
        
        # Log metadata si existe
        if isinstance(data, dict) and 'metadata' in data:
            logger.info(f"📊 Metadata: {data['metadata']}")
        
        return imported_count
        
    except FileNotFoundError:
        logger.error(f"❌ Archivo no encontrado: {filename}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"❌ Error de JSON: {str(e)}")
        raise
    except KeyError as e:
        logger.error(f"❌ Faltan campos requeridos en JSON: {str(e)}")
        raise
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ Error importando mercados: {str(e)}", exc_info=True)
        raise

def initialize_markets():
    """Inicializa mercados por código (fallback)"""
    markets = [
        Market(
            slug='conflicto-usa-venezuela-2026',
            title='¿Estados Unidos y Venezuela entrarán en conflicto bélico antes del 1 de abril de 2026?',
            description='Conflicto militar directo entre fuerzas oficiales',
            resolution_criteria='SÍ si: acción militar directa reconocida. NO si: sanciones, retórica sin acción.',
            sources='Departamento de Defensa EE.UU., Gobierno de Venezuela',
            notes='Mercado de solo compras',
            b=100.0,
            close_time=datetime(2026, 4, 1, 0, 0, 0),
            resolve_deadline=datetime(2026, 4, 7, 0, 0, 0),
            max_shares_per_buy=5000.0,
            max_long_position_per_user=50000.0
        ),
        Market(
            slug='bitcoin-100k-junio-2026',
            title='¿Bitcoin caerá por debajo de USD 100,000 antes del 1 de junio de 2026?',
            description='Precio spot BTC/USD',
            resolution_criteria='SÍ si precio < 100,000 en cualquier momento. NO si nunca cae.',
            sources='CoinMarketCap',
            notes='Solo compras permitidas',
            b=100.0,
            close_time=datetime(2026, 6, 1, 23, 59, 0),
            resolve_deadline=datetime(2026, 6, 2, 23, 59, 0),
            max_shares_per_buy=10000.0,
            max_long_position_per_user=100000.0
        )
    ]
    
    for market in markets:
        db.session.add(market)
    
    logger.info(f"{len(markets)} mercados de ejemplo creados")
    db.session.commit()

# ==================== ENDPOINTS DE AUTENTICACIÓN ====================
@app.route('/api/auth/register', methods=['POST'])
def register():
    """Registro de usuario"""
    try:
        data = request.json
        
        # Validación
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not username or not email or not password:
            return jsonify({'error': 'Faltan campos requeridos'}), 400
        
        # Validar email
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return jsonify({'error': 'Email inválido'}), 400
        
        # Verificar si usuario ya existe
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Usuario ya existe'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email ya registrado'}), 400
        
        # Crear usuario
        user = User(
            username=username,
            email=email,
            points_balance=100.00,
            is_active=True,
            role='user'
        )
        user.set_password(password)
        user.generate_session_token()
        
        db.session.add(user)
        db.session.commit()
        
        # Generar token JWT
        token = jwt.encode(
            {
                'user_id': user.id,
                'username': user.username,
                'exp': datetime.utcnow() + timedelta(hours=app.config['JWT_EXPIRATION_HOURS'])
            },
            app.config['JWT_SECRET_KEY'],
            algorithm=app.config['JWT_ALGORITHM']
        )
        
        logger.info(f"Usuario registrado: {username}")
        
        return jsonify({
            'success': True,
            'message': 'Usuario registrado exitosamente',
            'user': user.to_dict(),
            'token': token,
            'expires_in': app.config['JWT_EXPIRATION_HOURS'] * 3600
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error en registro: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error en registro'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login de usuario"""
    try:
        data = request.json
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'error': 'Faltan credenciales'}), 400
        
        # Buscar usuario por username o email
        user = User.query.filter(
            or_(
                User.username == username,
                User.email == username
            )
        ).first()
        
        if not user or not user.is_active:
            return jsonify({'error': 'Credenciales inválidas'}), 401
        
        if not user.check_password(password):
            return jsonify({'error': 'Credenciales inválidas'}), 401
        
        # Actualizar session token
        user.generate_session_token()
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Generar token JWT
        token = jwt.encode(
            {
                'user_id': user.id,
                'username': user.username,
                'exp': datetime.utcnow() + timedelta(hours=app.config['JWT_EXPIRATION_HOURS'])
            },
            app.config['JWT_SECRET_KEY'],
            algorithm=app.config['JWT_ALGORITHM']
        )
        
        logger.info(f"Login exitoso: {username}")
        
        return jsonify({
            'success': True,
            'message': 'Login exitoso',
            'user': user.to_dict(),
            'token': token,
            'expires_in': app.config['JWT_EXPIRATION_HOURS'] * 3600
        })
        
    except Exception as e:
        logger.error(f"Error en login: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error en login'}), 500

# ==================== ENDPOINTS (SOLO COMPRAS) ====================
@app.route('/api/markets', methods=['GET'])
def get_markets():
    """Obtiene mercados (público)"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        query = Market.query.filter_by(status='open')\
            .filter(Market.close_time > datetime.utcnow())\
            .order_by(Market.close_time.asc())
        
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        markets = pagination.items
        
        markets_data = []
        for market in markets:
            # Extract category from slug or notes
            category = 'general'
            if 'bitcoin' in market.slug or 'crypto' in market.slug.lower():
                category = 'crypto'
            elif 'presidente' in market.slug or 'cepeda' in market.slug:
                category = 'politica'
            elif 'inflacion' in market.slug or 'salario' in market.slug:
                category = 'economia'
            elif 'campeon' in market.slug or 'mundial' in market.slug or 'futbol' in market.slug:
                category = 'deportes'
            elif 'conflicto' in market.slug or 'venezuela' in market.slug or 'usa' in market.slug:
                category = 'geopolitica'
            
            markets_data.append({
                'id': market.id,
                'slug': market.slug,
                'title': market.title,
                'description': market.description,
                'category': category,  # ADD THIS LINE
                'price_yes': round(market.price_yes, 4),
                'price_no': round(market.price_no, 4),
                'total_liquidity': round(market.total_liquidity, 2),
                'close_time': market.close_time.isoformat() if market.close_time else None,
                'created_at': market.created_at.isoformat() if market.created_at else None,  # ADD THIS LINE
                'status': 'OPEN',
                'trading_type': 'BUY_ONLY',
                'buy_limits': {
                    'max_shares_per_buy': market.max_shares_per_buy,
                    'max_position_per_user': market.max_long_position_per_user
                }
            })
        
        return jsonify({
            'success': True,
            'markets': markets_data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': pagination.total,
                'pages': pagination.pages
            },
            'trading_rules': {
                'selling_allowed': False,
                'shorting_allowed': False,
                'only_buy_trades': True,
                'explanation': 'Este mercado solo permite comprar acciones. No se permite vender acciones previamente compradas.'
            }
        })
    except Exception as e:
        logger.error(f"Error getting markets: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error obteniendo mercados'}), 500

@app.route('/api/market/<int:market_id>', methods=['GET'])
def get_market_detail(market_id):
    """Obtiene detalles de un mercado específico"""
    try:
        market = Market.query.get_or_404(market_id)
        
        # Extract category from slug
        category = 'general'
        if 'bitcoin' in market.slug or 'crypto' in market.slug.lower():
            category = 'crypto'
        elif 'presidente' in market.slug or 'cepeda' in market.slug:
            category = 'politica'
        elif 'inflacion' in market.slug or 'salario' in market.slug:
            category = 'economia'
        elif 'campeon' in market.slug or 'mundial' in market.slug or 'futbol' in market.slug:
            category = 'deportes'
        elif 'conflicto' in market.slug or 'venezuela' in market.slug or 'usa' in market.slug:
            category = 'geopolitica'
        
        market_data = {
            'id': market.id,
            'slug': market.slug,
            'title': market.title,
            'description': market.description,
            'category': category,  # ADD THIS LINE
            'resolution_criteria': market.resolution_criteria,
            'sources': market.sources,
            'notes': market.notes,
            'price_yes': round(market.price_yes, 4),
            'price_no': round(market.price_no, 4),
            'total_liquidity': round(market.total_liquidity, 2),
            'status': market.status,
            'close_time': market.close_time.isoformat() if market.close_time else None,
            'resolve_deadline': market.resolve_deadline.isoformat() if market.resolve_deadline else None,
            'created_at': market.created_at.isoformat() if market.created_at else None,  # ADD THIS LINE
            'trading_type': 'BUY_ONLY',
            'statistics': {
                'total_buy_trades': market.total_buy_trades,
                'unique_buyers': market.unique_buyers
            },
            'buy_limits': {
                'max_shares_per_buy': market.max_shares_per_buy,
                'max_position_per_user': market.max_long_position_per_user
            }
        }
        
        return jsonify({
            'success': True,
            'market': market_data
        })
        
    except Exception as e:
        logger.error(f"Error getting market detail: {str(e)}")
        return jsonify({'error': 'Error obteniendo mercado'}), 500
        
# Add this near the other market endpoints (after get_market_detail)

@app.route('/api/market/<int:market_id>/price-history', methods=['GET'])
def get_market_price_history(market_id):
    """Obtiene historial de precios del mercado"""
    try:
        market = Market.query.get_or_404(market_id)
        
        # Get all trades for this market to reconstruct price history
        trades = BuyTrade.query.filter_by(market_id=market_id)\
            .order_by(BuyTrade.timestamp.asc())\
            .all()
        
        price_history = []
        
        # Start with initial prices (50/50)
        if trades:
            price_history.append({
                'timestamp': market.created_at.isoformat() if market.created_at else trades[0].timestamp.isoformat(),
                'price_yes': 0.5,
                'price_no': 0.5,
                'liquidity': 0.0
            })
        
        # Reconstruct prices from trades
        q_yes = 0.0
        q_no = 0.0
        
        for trade in trades:
            if trade.outcome == 'YES':
                q_yes += trade.shares
            else:
                q_no += trade.shares
            
            # Calculate price at this point
            b = market.b
            exp_yes = math.exp(q_yes / b)
            exp_no = math.exp(q_no / b)
            total = exp_yes + exp_no
            
            price_history.append({
                'timestamp': trade.timestamp.isoformat(),
                'price_yes': round(exp_yes / total if total > 0 else 0.5, 4),
                'price_no': round(exp_no / total if total > 0 else 0.5, 4),
                'liquidity': round(q_yes + q_no, 2)
            })
        
        return jsonify({
            'success': True,
            'market_id': market_id,
            'price_history': price_history
        })
        
    except Exception as e:
        logger.error(f"Error getting price history: {str(e)}")
        return jsonify({'error': 'Error obteniendo historial de precios'}), 500
        
@app.route('/api/market/<int:market_id>/buy', methods=['POST'])
@require_auth
@transactional
def buy_only_endpoint(session, market_id, current_user):
    """SOLO COMPRAS - No hay endpoint de venta"""
    try:
        data = request.json
        
        # Validación básica
        outcome = data.get('outcome', '').upper()
        if outcome not in ['YES', 'NO']:
            return jsonify({'error': 'Outcome debe ser YES o NO'}), 400
        
        shares = float(data.get('shares', 0))
        if shares <= 0:
            return jsonify({'error': 'Shares debe ser positivo'}), 400
        
        # Verificar que el mercado exista y esté abierto
        market = session.execute(
            select(Market).where(Market.id == market_id).with_for_update()
        ).scalar_one()
        
        if market.status != 'open':
            return jsonify({'error': 'Mercado cerrado'}), 400
        
        if market.close_time < datetime.utcnow():
            return jsonify({'error': 'Mercado expirado'}), 400
        
        # Verificar límites de COMPRA
        errors = BuyLimitManager.check_buy_limits(
            session, current_user.id, market_id, outcome, shares
        )
        
        if errors:
            return jsonify({
                'success': False,
                'error': 'Límites excedidos',
                'details': errors
            }), 400
        
        # Bloquear usuario
        user = session.execute(
            select(User).where(User.id == current_user.id).with_for_update()
        ).scalar_one()
        
        # Calcular nuevo estado del mercado
        if outcome == 'YES':
            new_q_yes = market.q_yes + shares
            new_q_no = market.q_no
        else:
            new_q_yes = market.q_yes
            new_q_no = market.q_no + shares
        
        # Calcular costo de COMPRA (LMSR)
        def cost_function(q_y, q_n):
            return market.b * math.log(math.exp(q_y / market.b) + math.exp(q_n / market.b))
        
        cost_before = cost_function(market.q_yes, market.q_no)
        cost_after = cost_function(new_q_yes, new_q_no)
        cost = cost_after - cost_before
        
        # Verificar saldo suficiente para COMPRA
        if user.points_balance < cost:
            return jsonify({
                'error': 'Saldo insuficiente para compra',
                'required': round(cost, 6),
                'available': round(user.points_balance, 6)
            }), 400
        
        # Precio actual de COMPRA
        price_at_buy = market.price_yes if outcome == 'YES' else market.price_no
        
        # Actualizar mercado
        market.q_yes = new_q_yes
        market.q_no = new_q_no
        
        # Actualizar usuario (restar puntos por COMPRA)
        user.points_balance -= cost
        
        # Actualizar o crear posición LONG
        position = session.execute(
            select(LongPosition)
            .where(
                and_(
                    LongPosition.user_id == user.id,
                    LongPosition.market_id == market_id
                )
            )
            .with_for_update()
        ).scalar_one_or_none()
        
        if position:
            # Sumar a posición LONG existente
            if outcome == 'YES':
                position.shares_yes += shares
            else:
                position.shares_no += shares
            
            position.total_shares = position.shares_yes + position.shares_no
            position.total_invested += cost
            position.last_updated = datetime.utcnow()
        else:
            # Crear nueva posición LONG
            position = LongPosition(
                user_id=user.id,
                market_id=market_id,
                shares_yes=shares if outcome == 'YES' else 0,
                shares_no=shares if outcome == 'NO' else 0,
                total_shares=shares,
                total_invested=cost,
                last_updated=datetime.utcnow()
            )
            session.add(position)
        
        # Registrar trade de COMPRA
        buy_trade = BuyTrade(
            user_id=user.id,
            market_id=market_id,
            outcome=outcome,
            shares=shares,
            cost=cost,
            price_at_buy=price_at_buy,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            session_token=user.session_token,
            timestamp=datetime.utcnow()
        )
        session.add(buy_trade)
        
        # Actualizar estadísticas
        market.total_buy_trades += 1
        user.total_buy_trades_count += 1
        user.total_shares_bought += shares
        user.total_long_positions += shares
        user.buy_trades_last_hour += 1
        user.shares_bought_last_hour += shares
        
        # Actualizar contador de mercados si es nueva posición
        if not position:
            user.markets_traded_count += 1
        
        # Actualizar compradores únicos
        unique_buyers = session.execute(
            select(func.count(func.distinct(LongPosition.user_id)))
            .where(LongPosition.market_id == market_id)
        ).scalar()
        market.unique_buyers = unique_buyers or 0
        
        # Nuevo precio después de la COMPRA
        new_price_yes = market.price_yes
        new_price_no = market.price_no
        
        logger.info(f"COMPRA exitosa: user={user.id}, market={market_id}, "
                   f"outcome={outcome}, shares={shares:.2f}, cost={cost:.2f}")
        
        return jsonify({
            'success': True,
            'message': 'Compra exitosa',
            'trade_type': 'BUY_ONLY',
            'trade_id': buy_trade.id,
            'cost': round(cost, 6),
            'price_at_buy': round(price_at_buy, 6),
            'new_prices': {
                'yes': round(new_price_yes, 6),
                'no': round(new_price_no, 6)
            },
            'new_balance': round(user.points_balance, 6),
            'position': {
                'shares_yes': round(position.shares_yes, 6),
                'shares_no': round(position.shares_no, 6),
                'total_shares': round(position.total_shares, 6),
                'total_invested': round(position.total_invested, 6),
                'current_value': round(position.current_value, 6),
                'profit_loss': round(position.profit_loss, 6)
            },
            'market_info': {
                'new_liquidity': round(market.total_liquidity, 2),
                'your_exposure': f"{(position.total_shares / market.total_liquidity * 100):.1f}%" if market.total_liquidity > 0 else "0%"
            },
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error en compra: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error en compra', 'details': str(e)}), 500

# ==================== ENDPOINTS DE USUARIO ====================
@app.route('/api/user/profile', methods=['GET'])
@require_auth
def get_user_profile(current_user):
    """Obtiene perfil del usuario"""
    try:
        return jsonify({
            'success': True,
            'user': current_user.to_dict()
        })
    except Exception as e:
        logger.error(f"Error getting profile: {str(e)}")
        return jsonify({'error': 'Error obteniendo perfil'}), 500

@app.route('/api/user/positions', methods=['GET'])
@require_auth
def get_user_positions(current_user):
    """Obtiene posiciones LONG del usuario"""
    try:
        positions = LongPosition.query.filter_by(user_id=current_user.id)\
            .options(joinedload(LongPosition.market))\
            .all()
        
        positions_data = []
        for pos in positions:
            market = pos.market
            positions_data.append({
                'market_id': market.id,
                'market_slug': market.slug,
                'market_title': market.title[:100] if market.title else '',
                'shares_yes': round(pos.shares_yes, 4),
                'shares_no': round(pos.shares_no, 4),
                'total_shares': round(pos.total_shares, 4),
                'total_invested': round(pos.total_invested, 6),
                'current_value': round(pos.current_value, 6),
                'profit_loss': round(pos.profit_loss, 6),
                'current_prices': {
                    'yes': round(market.price_yes, 4),
                    'no': round(market.price_no, 4)
                },
                'last_updated': pos.last_updated.isoformat() if pos.last_updated else None
            })
        
        return jsonify({
            'success': True,
            'positions': positions_data,
            'total_positions': len(positions_data),
            'total_invested': sum(p['total_invested'] for p in positions_data),
            'total_current_value': sum(p['current_value'] for p in positions_data),
            'total_profit_loss': sum(p['profit_loss'] for p in positions_data),
            'trading_rules_note': 'Posiciones son solo de COMPRA. No se permite vender.'
        })
    except Exception as e:
        logger.error(f"Error getting positions: {str(e)}")
        return jsonify({'error': 'Error obteniendo posiciones'}), 500

@app.route('/api/user/buy-history', methods=['GET'])
@require_auth
def get_user_buy_history(current_user):
    """Historial de COMPRAS del usuario"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        
        query = BuyTrade.query.filter_by(user_id=current_user.id)\
            .options(joinedload(BuyTrade.market))\
            .order_by(BuyTrade.timestamp.desc())
        
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        trades = pagination.items
        
        trades_data = []
        for trade in trades:
            trades_data.append({
                'id': trade.id,
                'market_id': trade.market_id,
                'market_title': trade.market.title[:100] if trade.market else 'N/A',
                'outcome': trade.outcome,
                'shares': round(trade.shares, 4),
                'cost': round(trade.cost, 6),
                'price_at_buy': round(trade.price_at_buy, 4),
                'timestamp': trade.timestamp.isoformat() if trade.timestamp else None,
                'type': 'BUY'
            })
        
        return jsonify({
            'success': True,
            'trades': trades_data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': pagination.total,
                'pages': pagination.pages
            },
            'total_buy_trades': current_user.total_buy_trades_count,
            'total_shares_bought': round(current_user.total_shares_bought, 2)
        })
    except Exception as e:
        logger.error(f"Error getting buy history: {str(e)}")
        return jsonify({'error': 'Error obteniendo historial'}), 500

@app.route('/api/user/limits', methods=['GET'])
@require_auth
def get_user_limits(current_user):
    """Obtiene límites de COMPRA del usuario"""
    try:
        # Reset rate limits si es necesario
        reset_time = current_user.rate_limit_reset_time or datetime.utcnow()
        if datetime.utcnow() > reset_time + timedelta(hours=1):
            current_user.buy_trades_last_hour = 0
            current_user.shares_bought_last_hour = 0.0
            current_user.rate_limit_reset_time = datetime.utcnow()
            db.session.commit()
        
        limits = {
            'buy_limits': {
                'max_shares_per_buy': app.config['LIMITS']['MAX_SHARES_PER_TRADE'],
                'min_shares_per_buy': app.config['LIMITS']['MIN_SHARES_PER_TRADE'],
                'max_position_per_market': app.config['LIMITS']['MAX_POSITION_PER_MARKET'],
                'max_exposure_percent': app.config['LIMITS']['MAX_EXPOSURE_PERCENT'] * 100,
                'max_total_positions': app.config['LIMITS']['MAX_TOTAL_POSITIONS'],
                'max_markets': app.config['LIMITS']['MAX_MARKETS_PER_USER']
            },
            'rate_limits': {
                'max_buy_trades_per_hour': app.config['LIMITS']['MAX_TRADES_PER_HOUR'],
                'max_shares_bought_per_hour': app.config['LIMITS']['MAX_SHARES_PER_HOUR'],
                'current_buy_trades_this_hour': current_user.buy_trades_last_hour,
                'current_shares_bought_this_hour': round(current_user.shares_bought_last_hour, 2),
                'rate_limit_reset_in': max(0, int((reset_time + timedelta(hours=1) - datetime.utcnow()).total_seconds() / 60))
            },
            'price_protection': {
                'max_price_impact_per_buy': app.config['LIMITS']['MAX_PRICE_IMPACT_PER_TRADE'] * 100
            },
            'current_usage': {
                'total_long_positions': round(current_user.total_long_positions, 2),
                'markets_traded': current_user.markets_traded_count,
                'total_buy_trades': current_user.total_buy_trades_count
            }
        }
        
        return jsonify({
            'success': True,
            'limits': limits,
            'trading_rules': {
                'selling_allowed': False,
                'shorting_allowed': False,
                'explanation': 'Este sistema solo permite comprar acciones. Las compras aumentan tu posición LONG.'
            }
        })
    except Exception as e:
        logger.error(f"Error getting limits: {str(e)}")
        return jsonify({'error': 'Error obteniendo límites'}), 500

@app.route('/api/leaderboard', methods=['GET'])
def get_leaderboard():
    """Obtiene leaderboard de usuarios"""
    try:
        # Get top users by total profit/value
        users = User.query.filter_by(is_active=True).all()
        
        leaderboard_data = []
        for user in users:
            # Calculate total portfolio value
            positions = LongPosition.query.filter_by(user_id=user.id).all()
            total_invested = sum(p.total_invested for p in positions)
            total_current_value = sum(p.current_value for p in positions)
            total_pl = total_current_value - total_invested
            net_worth = user.points_balance + total_current_value
            
            leaderboard_data.append({
                'user_id': user.id,
                'username': user.username if user.is_premium else f'Anon#{user.id}',
                'display_name': user.display_name if user.is_premium else None,
                'profile_image_url': user.profile_image_url if user.is_premium else None,
                'is_premium': user.is_premium,
                'net_worth': round(net_worth, 2),
                'total_pl': round(total_pl, 2),
                'markets_traded': user.markets_traded_count,
                'total_trades': user.total_buy_trades_count,
                'credentials': user.credentials if user.is_premium else None
            })
        
        # Sort by net worth
        leaderboard_data.sort(key=lambda x: x['net_worth'], reverse=True)
        
        # Add rank
        for i, entry in enumerate(leaderboard_data):
            entry['rank'] = i + 1
        
        return jsonify({
            'success': True,
            'leaderboard': leaderboard_data[:100]  # Top 100
        })
        
    except Exception as e:
        logger.error(f"Error getting leaderboard: {str(e)}")
        return jsonify({'error': 'Error obteniendo leaderboard'}), 500


# ==================== ENDPOINTS DE SISTEMA ====================
@app.route('/api/system/rules', methods=['GET'])
def get_system_rules():
    """Obtiene reglas del sistema (público)"""
    return jsonify({
        'success': True,
        'system_rules': {
            'trading_type': 'BUY_ONLY',
            'selling_allowed': False,
            'short_selling_allowed': False,
            'position_types': 'LONG_ONLY',
            'explanation': 'Este mercado de predicciones opera bajo el modelo "Solo Compras". Los usuarios pueden comprar acciones YES o NO, pero no pueden venderlas antes de la resolución del mercado. Todas las posiciones son LONG.',
            'resolution': 'Al resolver el mercado, las acciones del outcome ganador valen 1 punto cada una, las del perdedor valen 0.',
            'liquidity': 'Los precios se determinan automáticamente mediante el modelo LMSR (Logarithmic Market Scoring Rule).',
            'limits': 'Existen límites por usuario para proteger la señal informativa del mercado.'
        },
        'buy_limits': app.config['LIMITS'],
        'version': '1.0.0',
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/api/system/status', methods=['GET'])
def system_status():
    """Estado del sistema"""
    try:
        market_count = Market.query.count()
        user_count = User.query.count()
        buy_trade_count = BuyTrade.query.count()
        
        active_markets = Market.query.filter_by(status='open')\
            .filter(Market.close_time > datetime.utcnow())\
            .count()
        
        total_liquidity = db.session.query(func.sum(Market.q_yes + Market.q_no)).scalar() or 0
        
        return jsonify({
            'status': 'operational',
            'trading_mode': 'BUY_ONLY',
            'timestamp': datetime.utcnow().isoformat(),
            'statistics': {
                'markets': {
                    'total': market_count,
                    'active': active_markets,
                    'closed': market_count - active_markets
                },
                'users': user_count,
                'buy_trades': buy_trade_count,
                'total_liquidity': round(total_liquidity, 2)
            },
            'database': 'PostgreSQL' if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI'] else 'SQLite'
        })
    except Exception as e:
        logger.error(f"Error en system status: {str(e)}")
        return jsonify({
            'status': 'degraded',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check para Railway"""
    try:
        # Verificar conexión a la base de datos
        db.session.execute(text('SELECT 1'))
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'database': 'connected'
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

# ==================== ENDPOINT DE ERROR PARA VENTAS ====================
@app.route('/api/market/<int:market_id>/sell', methods=['POST'])
def sell_not_allowed(market_id):
    """Endpoint explícitamente deshabilitado para ventas"""
    return jsonify({
        'success': False,
        'error': 'Ventas no permitidas',
        'message': 'Este sistema solo permite comprar acciones. No se permite vender acciones previamente compradas.',
        'code': 'SELLING_DISABLED',
        'documentation': '/api/system/rules'
    }), 403

@app.route('/api/market/<int:market_id>/short', methods=['POST'])
def short_not_allowed(market_id):
    """Endpoint explícitamente deshabilitado para short selling"""
    return jsonify({
        'success': False,
        'error': 'Short selling no permitido',
        'message': 'Short selling no está disponible en este sistema.',
        'code': 'SHORTING_DISABLED',
        'documentation': '/api/system/rules'
    }), 403

# ==================== DOCUMENTACIÓN FRONTEND ====================
@app.route('/api/docs/trading', methods=['GET'])
def trading_documentation():
    """Documentación para frontend sobre trading"""
    return jsonify({
        'success': True,
        'trading_system': {
            'model': 'LMSR (Logarithmic Market Scoring Rule)',
            'allowed_actions': ['BUY_YES', 'BUY_NO'],
            'disallowed_actions': ['SELL_YES', 'SELL_NO', 'SHORT_YES', 'SHORT_NO'],
            'position_management': 'Posiciones son automáticamente LONG. No hay gestión manual de posiciones.'
        },
        'frontend_implementation': {
            'buy_flow': {
                '1': 'Usuario selecciona mercado y outcome (YES/NO)',
                '2': 'Frontend muestra precio actual y límites',
                '3': 'Usuario ingresa cantidad de acciones a COMPRAR',
                '4': 'Frontend valida límites locales',
                '5': 'Enviar POST a /api/market/{id}/buy con {outcome, shares}',
                '6': 'Mostrar confirmación con nuevo balance y posición'
            },
            'ui_elements_needed': {
                'buy_button': 'Solo botón de COMPRAR (sin vender)',
                'position_display': 'Mostrar posiciones LONG actuales',
                'limits_display': 'Mostrar límites de compra restantes',
                'warning': 'Mostrar claramente "Solo compras permitidas"'
            }
        },
        'example_buy_request': {
            'endpoint': 'POST /api/market/1/buy',
            'headers': {
                'Authorization': 'Bearer {jwt_token}',
                'Content-Type': 'application/json'
            },
            'body': {
                'outcome': 'YES',  # o 'NO'
                'shares': 100.0
            },
            'success_response': {
                'success': True,
                'trade_type': 'BUY_ONLY',
                'cost': 45.67,
                'new_balance': 954.33,
                'position': {
                    'shares_yes': 100.0,
                    'shares_no': 0.0,
                    'total_shares': 100.0
                }
            }
        }
    })

# ==================== INICIALIZACIÓN ====================
def init_database():
    """Inicializa DB con reglas claras de solo compras"""
    with app.app_context():
        db.create_all()
        
        # Crear admin si no existe
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@predictionmarket.com',
                role='admin',
                is_active=True,
                points_balance=10000.00
            )
            admin.set_password('Admin123!')
            admin.generate_session_token()
            db.session.add(admin)
            logger.info("Usuario admin creado")
        
        # Crear usuario demo si no existe
        demo = User.query.filter_by(username='demo').first()
        if not demo:
            demo = User(
                username='demo',
                email='demo@predictionmarket.com',
                role='user',
                is_active=True,
                points_balance=500.00
            )
            demo.set_password('Demo123!')
            demo.generate_session_token()
            db.session.add(demo)
            logger.info("Usuario demo creado")
        
        # Crear mercados desde JSON si no hay mercados
        if Market.query.count() == 0:
            try:
                import_markets_from_json('backend/data/markets.json')
            except FileNotFoundError:
                # Fallback a inicialización por código
                initialize_markets()
        
        try:
            db.session.commit()
            print("=" * 50)
            print("✅ Sistema inicializado en modo SOLO COMPRAS")
            print("❌ Ventas explícitamente deshabilitadas")
            print(f"📊 Base de datos: {app.config['SQLALCHEMY_DATABASE_URI'].split(':')[0]}")
            print("📚 Documentación disponible en /api/docs/trading")
            print("🏥 Health check en /api/health")
            print("=" * 50)
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error inicializando base de datos: {str(e)}")
            raise

# ==================== INICIALIZACIÓN AUTOMÁTICA DE BASE DE DATOS ====================
# Crear tablas automáticamente en Railway/Heroku
with app.app_context():
    try:
        db.create_all()
        logger.info("✅ Tablas de base de datos verificadas/creadas")
        
        # Verificar si hay mercados, si no, crear algunos
        if Market.query.count() == 0:
            try:
                # Railway ejecuta "cd backend", así que estamos en backend/
                # La ruta correcta es relativa al directorio actual
                current_dir = os.path.dirname(os.path.abspath(__file__))
                markets_file = os.path.join(current_dir, 'data', 'markets.json')
                
                logger.info(f"Intentando importar mercados desde {markets_file}")
                import_markets_from_json(markets_file)
                
            except FileNotFoundError as e:
                logger.error(f"❌ Archivo no encontrado: {markets_file}")
                logger.info("📝 Creando mercados de ejemplo por código...")
                initialize_markets()
                
            except Exception as e:
                logger.error(f"❌ Error importando mercados: {str(e)}", exc_info=True)
                logger.info("📝 Creando mercados de ejemplo por código...")
                initialize_markets()
            
            logger.info(f"✅ {Market.query.count()} mercados inicializados")
            
    except Exception as e:
        logger.error(f"❌ Error inicializando base de datos: {str(e)}", exc_info=True)
        # No lanzar excepción para no bloquear el inicio

# ==================== CONFIGURACIÓN DE EJECUCIÓN ====================
if __name__ == '__main__':
    # Configurar puerto
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    print(f"🚀 Iniciando servidor en puerto {port} (modo {'desarrollo' if debug else 'producción'})")
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug,
        threaded=True
    )

















