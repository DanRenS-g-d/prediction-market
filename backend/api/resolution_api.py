# ==================== DECORADOR PARA ADMIN ====================
def require_admin(func):
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
                role='admin'  # SOLO admin
            ).first()
            
            if not user:
                return jsonify({'error': 'Acceso denegado. Se requiere rol admin'}), 403
            
            return func(*args, **kwargs, current_user=user)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token inválido'}), 401
    return wrapper

# ==================== ENDPOINTS DE RESOLUCIÓN ====================

@app.route('/api/market/<int:market_id>/prepare-resolution', methods=['POST'])
@require_admin
@transactional
def prepare_resolution(session, market_id, current_user):
    """Prepara mercado para resolución creando snapshot"""
    try:
        resolution_mgr = ResolutionManager(session, {
            'Market': Market,
            'User': User,
            'LongPosition': LongPosition,
            'BuyTrade': BuyTrade,
            'MarketPositionSnapshot': MarketPositionSnapshot,
            'PositionSnapshotDetail': PositionSnapshotDetail,
            'ResolutionBatch': ResolutionBatch,
            'ResolutionPayment': ResolutionPayment,
            'ResolutionAuditLog': ResolutionAuditLog,
            'ResolutionEvidence': ResolutionEvidence
        })
        
        # Verificar requisitos
        checks = resolution_mgr.verify_resolution_prerequisites(market_id)
        failed_checks = [c for c in checks if not c['check_result']]
        
        if failed_checks:
            return jsonify({
                'success': False,
                'error': 'Pre-resolution checks failed',
                'checks': failed_checks
            }), 400
        
        # Crear snapshot
        snapshot_id = resolution_mgr.create_resolution_snapshot(market_id, current_user.id)
        
        return jsonify({
            'success': True,
            'snapshot_id': snapshot_id,
            'checks_passed': True,
            'timestamp': datetime.utcnow().isoformat(),
            'admin': current_user.username
        })
        
    except Exception as e:
        logger.error(f"Error preparing resolution: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Error preparing resolution: {str(e)}'
        }), 500

@app.route('/api/market/<int:market_id>/resolve', methods=['POST'])
@require_admin
@transactional
def resolve_market_with_audit(session, market_id, current_user):
    """Resuelve mercado con auditoría completa"""
    try:
        data = request.json
        result = data.get('result', '').upper()
        admin_id = current_user.id
        
        if result not in ['YES', 'NO']:
            return jsonify({
                'success': False,
                'error': 'Result must be YES or NO'
            }), 400
        
        # EVIDENCIA OBLIGATORIA
        evidence = {
            'url': data.get('evidence_url'),
            'source': data.get('evidence_source'),
            'description': data.get('evidence_description', ''),
            'additional_evidence': data.get('additional_evidence', []),
            'ip_address': request.remote_addr
        }
        
        # Validar evidencia mínima
        if not evidence['url'] or not evidence['source']:
            return jsonify({
                'success': False,
                'error': 'Evidence URL and source are required'
            }), 400
        
        resolution_mgr = ResolutionManager(session, {
            'Market': Market,
            'User': User,
            'LongPosition': LongPosition,
            'BuyTrade': BuyTrade,
            'MarketPositionSnapshot': MarketPositionSnapshot,
            'PositionSnapshotDetail': PositionSnapshotDetail,
            'ResolutionBatch': ResolutionBatch,
            'ResolutionPayment': ResolutionPayment,
            'ResolutionAuditLog': ResolutionAuditLog,
            'ResolutionEvidence': ResolutionEvidence
        })
        
        result_data = resolution_mgr.resolve_market_with_rollback(
            market_id=market_id,
            result=result,
            evidence=evidence,
            admin_id=admin_id
        )
        
        return jsonify({
            'success': True,
            'batch_id': result_data['batch_id'],
            'snapshot_id': result_data['snapshot_id'],
            'total_payout': float(result_data['total_payout']),
            'users_paid': result_data['users_paid'],
            'resolved_at': datetime.utcnow().isoformat(),
            'admin': current_user.username
        })
        
    except Exception as e:
        logger.error(f"Error resolving market: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e),
            'requires_manual_intervention': 'rollback_attempted' in str(e).lower()
        }), 500

@app.route('/api/resolution/<int:batch_id>/reverse', methods=['POST'])
@require_admin
@transactional
def reverse_resolution(session, batch_id, current_user):
    """Revierte una resolución usando snapshot"""
    try:
        data = request.json
        admin_id = current_user.id
        reason = data.get('reason', '').strip()
        
        if not reason:
            return jsonify({
                'success': False,
                'error': 'Reason is required for reversal'
            }), 400
        
        resolution_mgr = ResolutionManager(session, {
            'Market': Market,
            'User': User,
            'LongPosition': LongPosition,
            'BuyTrade': BuyTrade,
            'MarketPositionSnapshot': MarketPositionSnapshot,
            'PositionSnapshotDetail': PositionSnapshotDetail,
            'ResolutionBatch': ResolutionBatch,
            'ResolutionPayment': ResolutionPayment,
            'ResolutionAuditLog': ResolutionAuditLog,
            'ResolutionEvidence': ResolutionEvidence
        })
        
        result = resolution_mgr.reverse_resolution(
            batch_id=batch_id,
            reason=reason,
            admin_id=admin_id
        )
        
        return jsonify({
            'success': True,
            'reversal_batch_id': result['reversal_batch_id'],
            'points_reversed': float(result['points_reversed']),
            'users_affected': result['users_affected'],
            'reversed_at': datetime.utcnow().isoformat(),
            'admin': current_user.username
        })
        
    except Exception as e:
        logger.error(f"Error reversing resolution: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e),
            'requires_manual_intervention': True
        }), 500

@app.route('/api/market/<int:market_id>/resolution-audit', methods=['GET'])
def get_resolution_audit(market_id):
    """Obtiene auditoría completa de resoluciones de un mercado"""
    try:
        # Verificar que el mercado exista
        market = Market.query.get(market_id)
        if not market:
            return jsonify({'error': 'Market not found'}), 404
        
        # Auditoría usando SQLAlchemy ORM
        audit_log = db.session.query(
            ResolutionAuditLog.event_type,
            ResolutionAuditLog.created_at,
            User.username.label('performed_by'),
            ResolutionAuditLog.event_data,
            ResolutionBatch.result,
            ResolutionBatch.evidence_url
        ).outerjoin(
            User, ResolutionAuditLog.performed_by == User.id
        ).outerjoin(
            ResolutionBatch, ResolutionAuditLog.batch_id == ResolutionBatch.id
        ).filter(
            ResolutionAuditLog.market_id == market_id
        ).order_by(
            ResolutionAuditLog.created_at.desc()
        ).limit(100).all()
        
        # Snapshots
        snapshots = db.session.query(
            MarketPositionSnapshot.id,
            MarketPositionSnapshot.snapshot_timestamp,
            User.username.label('created_by'),
            MarketPositionSnapshot.total_shares_yes,
            MarketPositionSnapshot.total_shares_no,
            MarketPositionSnapshot.total_positions
        ).outerjoin(
            User, MarketPositionSnapshot.created_by == User.id
        ).filter(
            MarketPositionSnapshot.market_id == market_id
        ).order_by(
            MarketPositionSnapshot.snapshot_timestamp.desc()
        ).all()
        
        # Batches de resolución
        batches = db.session.query(
            ResolutionBatch.id,
            ResolutionBatch.result,
            ResolutionBatch.batch_timestamp,
            ResolutionBatch.status,
            ResolutionBatch.total_payout,
            ResolutionBatch.total_users_paid,
            User.username.label('resolved_by'),
            ResolutionBatch.evidence_url,
            ResolutionBatch.evidence_source
        ).outerjoin(
            User, ResolutionBatch.resolved_by == User.id
        ).filter(
            ResolutionBatch.market_id == market_id
        ).order_by(
            ResolutionBatch.batch_timestamp.desc()
        ).all()
        
        # Pagos asociados
        payments_by_batch = {}
        for batch in batches:
            payments = db.session.query(
                ResolutionPayment.user_id,
                User.username,
                ResolutionPayment.payout_amount,
                ResolutionPayment.payment_status
            ).join(
                User, ResolutionPayment.user_id == User.id
            ).filter(
                ResolutionPayment.batch_id == batch.id
            ).limit(10).all()
            
            payments_by_batch[batch.id] = [
                {
                    'user_id': p.user_id,
                    'username': p.username,
                    'payout_amount': float(p.payout_amount),
                    'status': p.payment_status
                } for p in payments
            ]
        
        return jsonify({
            'success': True,
            'market_id': market_id,
            'market_slug': market.slug,
            'market_title': market.title,
            'audit_log': [
                {
                    'event_type': row.event_type,
                    'timestamp': row.created_at.isoformat() if row.created_at else None,
                    'performed_by': row.performed_by,
                    'event_data': row.event_data,
                    'result': row.result,
                    'evidence_url': row.evidence_url
                } for row in audit_log
            ],
            'snapshots': [
                {
                    'id': row.id,
                    'timestamp': row.snapshot_timestamp.isoformat() if row.snapshot_timestamp else None,
                    'created_by': row.created_by,
                    'total_shares_yes': float(row.total_shares_yes),
                    'total_shares_no': float(row.total_shares_no),
                    'total_positions': row.total_positions
                } for row in snapshots
            ],
            'resolution_batches': [
                {
                    'id': row.id,
                    'result': row.result,
                    'timestamp': row.batch_timestamp.isoformat() if row.batch_timestamp else None,
                    'status': row.status,
                    'total_payout': float(row.total_payout),
                    'users_paid': row.total_users_paid,
                    'resolved_by': row.resolved_by,
                    'evidence_url': row.evidence_url,
                    'evidence_source': row.evidence_source,
                    'sample_payments': payments_by_batch.get(row.id, [])
                } for row in batches
            ]
        })
        
    except Exception as e:
        logger.error(f"Error getting resolution audit: {str(e)}")
        return jsonify({'error': 'Error obteniendo auditoría'}), 500

@app.route('/api/system/integrity-check', methods=['GET'])
@require_admin
def system_integrity_check(current_user):
    """Verifica integridad de todo el sistema de resoluciones"""
    try:
        # 1. Verificar mercados resueltos sin snapshots
        markets_without_snapshots = Market.query.filter(
            Market.status == 'resolved'
        ).outerjoin(
            MarketPositionSnapshot, Market.id == MarketPositionSnapshot.market_id
        ).filter(
            MarketPositionSnapshot.id.is_(None)
        ).limit(10).all()
        
        # 2. Verificar batches sin pagos
        batches_without_payments = ResolutionBatch.query.filter(
            ResolutionBatch.status == 'completed'
        ).outerjoin(
            ResolutionPayment, ResolutionBatch.id == ResolutionPayment.batch_id
        ).filter(
            ResolutionPayment.id.is_(None)
        ).limit(10).all()
        
        # 3. Verificar inconsistencias en balances (CORREGIDO)
        all_users = User.query.all()
        balance_issues = []
        
        for user in all_users:
            # Calcular balance teórico (más preciso)
            theoretical_balance = _calculate_user_balance(user.id)
            current_balance = user.points_balance
            
            # Tolerancia de 0.01 puntos
            discrepancy = abs(current_balance - theoretical_balance)
            
            if discrepancy > 0.01:
                balance_issues.append({
                    'user_id': user.id,
                    'username': user.username,
                    'current_balance': current_balance,
                    'theoretical_balance': theoretical_balance,
                    'discrepancy': discrepancy
                })
        
        # 4. Verificar posiciones bloqueadas pero mercado no en resolución
        locked_positions_issues = LongPosition.query.filter(
            LongPosition.locked_for_resolution == True
        ).join(
            Market, LongPosition.market_id == Market.id
        ).filter(
            Market.status.notin_(['resolved', 'voided'])
        ).limit(10).all()
        
        return jsonify({
            'success': True,
            'integrity_check': {
                'timestamp': datetime.utcnow().isoformat(),
                'admin': current_user.username,
                'summary': {
                    'markets_without_snapshots': len(markets_without_snapshots),
                    'batches_without_payments': len(batches_without_payments),
                    'balance_inconsistencies': len(balance_issues),
                    'locked_positions_issues': len(locked_positions_issues)
                },
                'issues': {
                    'markets_without_snapshots': [
                        {
                            'id': m.id, 
                            'slug': m.slug,
                            'resolved_at': m.resolution_time.isoformat() if m.resolution_time else None
                        } for m in markets_without_snapshots
                    ],
                    'batches_without_payments': [
                        {
                            'id': b.id, 
                            'market_id': b.market_id,
                            'created_at': b.created_at.isoformat() if b.created_at else None
                        } for b in batches_without_payments
                    ],
                    'balance_inconsistencies': [
                        {
                            'user_id': b['user_id'],
                            'username': b['username'],
                            'discrepancy': float(b['discrepancy'])
                        } for b in balance_issues[:10]
                    ],
                    'locked_positions_issues': [
                        {
                            'user_id': p.user_id,
                            'market_id': p.market_id,
                            'market_status': p.market.status
                        } for p in locked_positions_issues
                    ]
                },
                'health_status': 'healthy' if not any([
                    markets_without_snapshots,
                    batches_without_payments,
                    balance_issues,
                    locked_positions_issues
                ]) else 'needs_attention',
                'recommendations': _generate_integrity_recommendations(
                    markets_without_snapshots,
                    batches_without_payments,
                    balance_issues,
                    locked_positions_issues
                )
            }
        })
        
    except Exception as e:
        logger.error(f"Integrity check failed: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Integrity check failed',
            'details': str(e)
        }), 500

def _calculate_user_balance(user_id):
    """Calcula balance teórico considerando TODAS las transacciones"""
    from decimal import Decimal
    
    user = User.query.get(user_id)
    if not user:
        return 0.0
    
    # Balance inicial (de init_database)
    if user.username == 'admin':
        initial_balance = Decimal('10000.00')
    elif user.username == 'demo':
        initial_balance = Decimal('500.00')
    else:
        initial_balance = Decimal('100.00')
    
    # 1. Restar costos de todas las compras
    total_spent = db.session.query(func.sum(BuyTrade.cost)).filter(
        BuyTrade.user_id == user_id
    ).scalar() or Decimal('0.00')
    
    # 2. Sumar pagos de resoluciones (solo pagados)
    total_payouts = db.session.query(func.sum(ResolutionPayment.payout_amount)).filter(
        ResolutionPayment.user_id == user_id,
        ResolutionPayment.payment_status == 'paid'
    ).scalar() or Decimal('0.00')
    
    # 3. Restar pagos revertidos
    total_reversed = db.session.query(func.sum(ResolutionPayment.payout_amount)).filter(
        ResolutionPayment.user_id == user_id,
        ResolutionPayment.payment_status == 'reversed'
    ).scalar() or Decimal('0.00')
    
    # Fórmula: Balance inicial - gastos en compras + pagos recibidos - pagos revertidos
    theoretical = initial_balance - Decimal(str(total_spent)) + Decimal(str(total_payouts)) - Decimal(str(total_reversed))
    
    return float(theoretical)

def _generate_integrity_recommendations(markets_without_snapshots, batches_without_payments, balance_issues, locked_positions_issues):
    """Genera recomendaciones basadas en los issues encontrados"""
    recommendations = []
    
    if markets_without_snapshots:
        recommendations.append({
            'priority': 'high',
            'issue': 'markets_without_snapshots',
            'recommendation': 'Crear snapshots manuales para mercados resueltos sin backup',
            'action': 'Usar endpoint POST /api/market/<id>/prepare-resolution',
            'affected_count': len(markets_without_snapshots)
        })
    
    if batches_without_payments:
        recommendations.append({
            'priority': 'high',
            'issue': 'batches_without_payments',
            'recommendation': 'Verificar batches de resolución sin pagos asociados',
            'action': 'Revisar logs de auditoría y considerar reversión',
            'affected_count': len(batches_without_payments)
        })
    
    if balance_issues:
        recommendations.append({
            'priority': 'medium',
            'issue': 'balance_inconsistencies',
            'recommendation': 'Corregir balances de usuarios inconsistentes',
            'action': 'Usar herramientas administrativas para ajustar balances',
            'affected_count': len(balance_issues)
        })
    
    if locked_positions_issues:
        recommendations.append({
            'priority': 'low',
            'issue': 'locked_positions_issues',
            'recommendation': 'Desbloquear posiciones en mercados no resueltos',
            'action': 'Ejecutar script de limpieza de locks',
            'affected_count': len(locked_positions_issues)
        })
    
    return recommendations

# Endpoint adicional para ajustar balances manualmente
@app.route('/api/admin/adjust-balance/<int:user_id>', methods=['POST'])
@require_admin
@transactional
def admin_adjust_balance(session, user_id, current_user):
    """Ajusta balance de usuario manualmente (solo admin)"""
    try:
        data = request.json
        adjustment = float(data.get('adjustment', 0))
        reason = data.get('reason', '').strip()
        
        if not reason:
            return jsonify({
                'success': False,
                'error': 'Reason is required for balance adjustment'
            }), 400
        
        user = session.query(User).get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Registrar balance antes
        balance_before = user.points_balance
        
        # Aplicar ajuste
        user.points_balance += adjustment
        
        # Registrar en log de auditoría
        audit_log = ResolutionAuditLog(
            event_type='balance_adjusted',
            user_id=user_id,
            event_data={
                'admin_id': current_user.id,
                'admin_username': current_user.username,
                'balance_before': balance_before,
                'adjustment': adjustment,
                'balance_after': user.points_balance,
                'reason': reason,
                'timestamp': datetime.utcnow().isoformat()
            },
            performed_by=current_user.id,
            ip_address=request.remote_addr
        )
        session.add(audit_log)
        
        logger.info(f"Balance adjusted for user {user_id} by admin {current_user.id}: {adjustment} ({reason})")
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'username': user.username,
            'adjustment': adjustment,
            'balance_before': balance_before,
            'balance_after': user.points_balance,
            'reason': reason,
            'admin': current_user.username,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error adjusting balance: {str(e)}")
        return jsonify({'error': 'Error adjusting balance'}), 500
