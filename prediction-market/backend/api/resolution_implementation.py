# resolution_manager.py
import hashlib
import json
from datetime import datetime, timedelta
from decimal import Decimal
from sqlalchemy import text, func, and_, or_
import logging

logger = logging.getLogger(__name__)

class ResolutionManager:
    def __init__(self, db_session, db_model):
        self.db = db_session
        self.db_model = db_model  # Para acceder a modelos como User, Market, etc.
        
    def create_resolution_snapshot(self, market_id, admin_id):
        """Crea snapshot de todas las posiciones antes de resolver"""
        try:
            # 1. Bloquear mercado para evitar cambios durante snapshot
            lock_token = self._acquire_market_lock(market_id, admin_id)
            
            # 2. Crear snapshot en base de datos usando SQLAlchemy
            snapshot_result = self._create_snapshot_using_sqlalchemy(market_id, admin_id)
            
            # 3. Bloquear posiciones
            self._lock_positions(market_id)
            
            # 4. Registrar en log
            self._log_audit_event(
                event_type='snapshot_created',
                market_id=market_id,
                user_id=admin_id,
                data={'snapshot_id': snapshot_result['id']}
            )
            
            return snapshot_result['id']
            
        except Exception as e:
            logger.error(f"Error creating snapshot: {str(e)}")
            raise
    
    def _create_snapshot_using_sqlalchemy(self, market_id, admin_id):
        """Crea snapshot usando SQLAlchemy en lugar de funciones PostgreSQL"""
        # Obtener mercado
        market = self.db.query(self.db_model.Market).get(market_id)
        if not market:
            raise ValueError(f"Market {market_id} not found")
        
        # Calcular totales de posiciones
        positions = self.db.query(
            func.sum(self.db_model.LongPosition.shares_yes),
            func.sum(self.db_model.LongPosition.shares_no),
            func.count()
        ).filter(
            self.db_model.LongPosition.market_id == market_id
        ).first()
        
        total_shares_yes = positions[0] or Decimal('0')
        total_shares_no = positions[1] or Decimal('0')
        total_positions = positions[2] or 0
        
        # Crear snapshot principal
        snapshot = self.db_model.MarketPositionSnapshot(
            market_id=market_id,
            pre_resolution_q_yes=market.q_yes,
            pre_resolution_q_no=market.q_no,
            market_status_before=market.status,
            total_shares_yes=total_shares_yes,
            total_shares_no=total_shares_no,
            total_positions=total_positions,
            created_by=admin_id,
            data_hash=hashlib.md5(
                f"{market_id}{total_shares_yes}{total_shares_no}{datetime.utcnow()}".encode()
            ).hexdigest()
        )
        self.db.add(snapshot)
        self.db.flush()  # Para obtener el ID
        
        # Crear detalles del snapshot
        positions_details = self.db.query(
            self.db_model.LongPosition,
            self.db_model.User.points_balance
        ).join(
            self.db_model.User,
            self.db_model.LongPosition.user_id == self.db_model.User.id
        ).filter(
            self.db_model.LongPosition.market_id == market_id
        ).all()
        
        for position, balance in positions_details:
            detail = self.db_model.PositionSnapshotDetail(
                snapshot_id=snapshot.id,
                user_id=position.user_id,
                market_id=market_id,
                shares_yes=position.shares_yes,
                shares_no=position.shares_no,
                user_balance_before=balance
            )
            self.db.add(detail)
        
        return {'id': snapshot.id}
    
    def _lock_positions(self, market_id):
        """Bloquea posiciones para resolución"""
        self.db.query(self.db_model.LongPosition).filter(
            self.db_model.LongPosition.market_id == market_id
        ).update({
            'locked_for_resolution': True
        })
    
    def _acquire_market_lock(self, market_id, admin_id):
        """Adquiere lock exclusivo usando SQLAlchemy"""
        lock_token = hashlib.sha256(
            f"{market_id}-{admin_id}-{datetime.utcnow()}".encode()
        ).hexdigest()
        
        # Verificar si ya hay lock
        market = self.db.query(self.db_model.Market).get(market_id)
        if market.resolution_lock_token:
            if market.resolution_lock_expires and market.resolution_lock_expires > datetime.utcnow():
                raise Exception("Market is already being resolved by another process")
        
        # Establecer lock
        market.resolution_lock_token = lock_token
        market.resolution_lock_expires = datetime.utcnow() + timedelta(minutes=5)
        
        return lock_token
    
    def verify_resolution_prerequisites(self, market_id):
        """Verifica que se cumplan todos los requisitos para resolver"""
        checks = []
        
        # Verificar mercado
        market = self.db.query(self.db_model.Market).get(market_id)
        if not market:
            checks.append({
                'check_name': 'market_exists',
                'check_result': False,
                'details': f'Market {market_id} not found'
            })
            return checks
        
        # 1. Verificar que el mercado esté cerrado
        checks.append({
            'check_name': 'market_closed',
            'check_result': market.status == 'closed',
            'details': 'Market must be closed before resolution'
        })
        
        # 2. Verificar que no esté ya resuelto
        checks.append({
            'check_name': 'not_already_resolved',
            'check_result': market.status not in ['resolved', 'voided'],
            'details': 'Market is already resolved or voided'
        })
        
        # 3. Verificar integridad de posiciones
        positions_q = self.db.query(
            func.sum(self.db_model.LongPosition.shares_yes),
            func.sum(self.db_model.LongPosition.shares_no)
        ).filter(
            self.db_model.LongPosition.market_id == market_id
        ).first()
        
        total_shares_yes = positions_q[0] or Decimal('0')
        total_shares_no = positions_q[1] or Decimal('0')
        
        # Comparar con valores del mercado (con tolerancia)
        diff_yes = abs(float(total_shares_yes) - float(market.q_yes))
        diff_no = abs(float(total_shares_no) - float(market.q_no))
        
        checks.append({
            'check_name': 'positions_integrity',
            'check_result': diff_yes < 0.01 and diff_no < 0.01,
            'details': f'Positions must match market q values. Diff YES: {diff_yes:.4f}, NO: {diff_no:.4f}'
        })
        
        # 4. Verificar criterios de resolución
        checks.append({
            'check_name': 'has_resolution_criteria',
            'check_result': bool(market.resolution_criteria),
            'details': 'Market must have resolution criteria defined'
        })
        
        # 5. Verificar fecha de cierre
        checks.append({
            'check_name': 'market_has_closed',
            'check_result': market.close_time < datetime.utcnow(),
            'details': f'Market close time ({market.close_time}) must be in the past'
        })
        
        return checks
    
    def resolve_market_with_rollback(self, market_id, result, evidence, admin_id):
        """Resuelve mercado con capacidad de rollback completo"""
        
        # 1. VERIFICACIONES PREVIAS
        checks = self.verify_resolution_prerequisites(market_id)
        failed_checks = [c for c in checks if not c['check_result']]
        
        if failed_checks:
            raise ValueError(f"Pre-resolución checks failed: {failed_checks}")
        
        # 2. CREAR SNAPSHOT
        snapshot_id = self.create_resolution_snapshot(market_id, admin_id)
        
        # 3. CREAR BATCH DE RESOLUCIÓN
        batch = self._create_resolution_batch(
            market_id=market_id,
            result=result,
            evidence=evidence,
            admin_id=admin_id,
            snapshot_id=snapshot_id
        )
        
        try:
            # 4. CALCULAR Y APLICAR PAGOS
            payments = self._calculate_and_apply_payments(
                market_id=market_id,
                result=result,
                batch_id=batch['id']
            )
            
            # 5. MARCAR MERCADO COMO RESUELTO
            self._mark_market_resolved(
                market_id=market_id,
                result=result,
                batch_id=batch['id'],
                admin_id=admin_id
            )
            
            # 6. COMPLETAR BATCH
            self._complete_resolution_batch(
                batch_id=batch['id'],
                total_payout=payments['total_payout'],
                users_paid=payments['users_paid']
            )
            
            # 7. REGISTRAR ÉXITO
            self._log_audit_event(
                event_type='resolution_completed',
                market_id=market_id,
                user_id=admin_id,
                data={
                    'batch_id': batch['id'],
                    'result': result,
                    'total_payout': payments['total_payout'],
                    'users_paid': payments['users_paid']
                }
            )
            
            return {
                'success': True,
                'batch_id': batch['id'],
                'snapshot_id': snapshot_id,
                'total_payout': payments['total_payout'],
                'users_paid': payments['users_paid']
            }
            
        except Exception as e:
            # ROLLBACK AUTOMÁTICO
            self.db.rollback()  # Rollback de SQLAlchemy
            logger.error(f"Resolution failed, rolling back: {str(e)}")
            
            # Intentar rollback específico
            try:
                self._rollback_resolution(market_id, batch['id'], admin_id, str(e))
            except Exception as rollback_error:
                logger.critical(f"Rollback also failed: {str(rollback_error)}")
                # Necesita intervención manual
            
            raise
    
    def _create_resolution_batch(self, market_id, result, evidence, admin_id, snapshot_id):
        """Crea un nuevo batch de resolución usando SQLAlchemy"""
        
        # VALIDAR EVIDENCIA OBLIGATORIA
        if not evidence.get('url'):
            raise ValueError("Evidence URL is required")
        if not evidence.get('source'):
            raise ValueError("Evidence source is required")
        
        # Crear batch
        batch = self.db_model.ResolutionBatch(
            market_id=market_id,
            result=result,
            evidence_url=evidence['url'],
            evidence_description=evidence.get('description', ''),
            evidence_source=evidence['source'],
            resolved_by=admin_id,
            resolved_by_ip=evidence.get('ip_address'),
            data_hash=hashlib.sha256(json.dumps(evidence).encode()).hexdigest()
        )
        
        self.db.add(batch)
        self.db.flush()  # Para obtener el ID
        
        # Registrar evidencia adicional si existe
        if evidence.get('additional_evidence'):
            for ev in evidence['additional_evidence']:
                evidence_record = self.db_model.ResolutionEvidence(
                    market_id=market_id,
                    batch_id=batch.id,
                    evidence_type=ev.get('type', 'official_statement'),
                    title=ev['title'],
                    description=ev.get('description', ''),
                    url=ev['url'],
                    source=ev['source'],
                    is_official=ev.get('is_official', False)
                )
                self.db.add(evidence_record)
        
        return {'id': batch.id, 'timestamp': batch.batch_timestamp}
    
    def _calculate_and_apply_payments(self, market_id, result, batch_id):
        """Calcula y aplica pagos basados en posiciones actuales"""
        
        # Obtener todas las posiciones (ya bloqueadas)
        positions = self.db.query(
            self.db_model.LongPosition,
            self.db_model.User
        ).join(
            self.db_model.User,
            self.db_model.LongPosition.user_id == self.db_model.User.id
        ).filter(
            self.db_model.LongPosition.market_id == market_id,
            self.db_model.LongPosition.locked_for_resolution == True
        ).all()
        
        total_payout = Decimal('0')
        users_paid = 0
        
        for position, user in positions:
            # Calcular pago basado en result
            if result == 'YES':
                payout = Decimal(str(position.shares_yes))
                calculation = f"shares_yes * 1.0 = {position.shares_yes} * 1.0"
            else:  # 'NO'
                payout = Decimal(str(position.shares_no))
                calculation = f"shares_no * 1.0 = {position.shares_no} * 1.0"
            
            if payout > Decimal('0.0001'):
                # Actualizar balance del usuario
                new_balance = Decimal(str(user.points_balance)) + payout
                user.points_balance = float(new_balance)
                
                # Registrar pago
                payment = self.db_model.ResolutionPayment(
                    batch_id=batch_id,
                    user_id=user.id,
                    market_id=market_id,
                    shares_yes=float(position.shares_yes),
                    shares_no=float(position.shares_no),
                    payout_calculation=calculation,
                    payout_amount=float(payout),
                    user_balance_before=float(user.points_balance - payout),
                    user_balance_after=float(new_balance)
                )
                self.db.add(payment)
                
                total_payout += payout
                users_paid += 1
                
                # Registrar en log
                self._log_audit_event(
                    event_type='payment_processed',
                    market_id=market_id,
                    user_id=user.id,
                    data={
                        'batch_id': batch_id,
                        'payout': float(payout),
                        'shares_yes': position.shares_yes,
                        'shares_no': position.shares_no
                    }
                )
        
        return {
            'total_payout': total_payout,
            'users_paid': users_paid
        }
    
    def _mark_market_resolved(self, market_id, result, batch_id, admin_id):
        """Marca mercado como resuelto"""
        market = self.db.query(self.db_model.Market).get(market_id)
        market.status = 'resolved'
        market.result = result
        market.resolution_time = datetime.utcnow()
        market.resolved_by = admin_id
        market.resolution_evidence_url = f"/api/resolution/batch/{batch_id}"
        
        # Liberar lock
        market.resolution_lock_token = None
        market.resolution_lock_expires = None
    
    def _complete_resolution_batch(self, batch_id, total_payout, users_paid):
        """Completa batch de resolución"""
        batch = self.db.query(self.db_model.ResolutionBatch).get(batch_id)
        batch.status = 'completed'
        batch.total_payout = float(total_payout)
        batch.total_users_paid = users_paid
    
    def _rollback_resolution(self, market_id, batch_id, admin_id, error_msg):
        """Rollback completo de una resolución fallida"""
        try:
            # 1. Revertir pagos si se aplicaron
            payments = self.db.query(self.db_model.ResolutionPayment).filter(
                self.db_model.ResolutionPayment.batch_id == batch_id
            ).all()
            
            for payment in payments:
                user = self.db.query(self.db_model.User).get(payment.user_id)
                if user:
                    user.points_balance -= payment.payout_amount
                    payment.payment_status = 'reversed'
                    payment.reversed_at = datetime.utcnow()
            
            # 2. Desbloquear posiciones
            self.db.query(self.db_model.LongPosition).filter(
                self.db_model.LongPosition.market_id == market_id
            ).update({
                'locked_for_resolution': False
            })
            
            # 3. Liberar lock del mercado
            market = self.db.query(self.db_model.Market).get(market_id)
            market.resolution_lock_token = None
            market.resolution_lock_expires = None
            
            # 4. Marcar batch como fallido
            batch = self.db.query(self.db_model.ResolutionBatch).get(batch_id)
            batch.status = 'failed'
            
            # 5. Registrar rollback en log
            self._log_audit_event(
                event_type='resolution_reversed',
                market_id=market_id,
                user_id=admin_id,
                data={
                    'batch_id': batch_id,
                    'reason': 'rollback_after_error',
                    'error': error_msg
                }
            )
            
        except Exception as rollback_error:
            self._log_critical_error(
                f"ROLLBACK FAILED for market {market_id}, batch {batch_id}: {rollback_error}"
            )
            raise
    
    def _log_audit_event(self, event_type, market_id=None, user_id=None, data=None):
        """Registra evento en log de auditoría"""
        # Obtener IP real si está disponible
        import flask
        try:
            ip_address = flask.request.remote_addr if flask.request else '127.0.0.1'
        except:
            ip_address = '127.0.0.1'
        
        audit_log = self.db_model.ResolutionAuditLog(
            event_type=event_type,
            market_id=market_id,
            user_id=user_id,
            event_data=data,
            performed_by=user_id,
            ip_address=ip_address
        )
        self.db.add(audit_log)
    
    def _log_critical_error(self, message):
        """Registra error crítico que requiere intervención manual"""
        logger.critical(f"CRITICAL ERROR: {message}")
        # Aquí podrías enviar email, notificación, etc.
        # Registrar en tabla especial de errores críticos si existe
