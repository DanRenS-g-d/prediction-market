import json
from datetime import datetime
from decimal import Decimal

def import_markets_from_json(json_file_path):
    """
    Importa mercados desde archivo JSON a la base de datos
    """
    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        imported_count = 0
        updated_count = 0
        
        for market_data in data.get('markets', []):
            # Verificar si ya existe
            existing = Market.query.filter_by(slug=market_data['slug']).first()
            
            if existing:
                # Actualizar mercado existente
                existing.title = market_data['title']
                existing.description = market_data.get('description', '')
                existing.resolution_criteria = market_data['resolution_criteria']
                existing.sources = market_data['sources']
                existing.notes = market_data.get('notes', '')
                existing.b = float(market_data['b'])
                existing.status = market_data.get('status', 'open')
                existing.close_time = datetime.fromisoformat(market_data['close_time'].replace('Z', '+00:00'))
                existing.resolve_deadline = datetime.fromisoformat(market_data['resolve_deadline'].replace('Z', '+00:00'))
                existing.max_shares_per_buy = float(market_data.get('max_shares_per_buy', 10000.0))
                existing.max_long_position_per_user = float(market_data.get('max_long_position_per_user', 50000.0))
                updated_count += 1
                print(f"✓ Actualizado: {market_data['slug']}")
            else:
                # Crear nuevo mercado
                market = Market(
                    slug=market_data['slug'],
                    title=market_data['title'],
                    description=market_data.get('description', ''),
                    resolution_criteria=market_data['resolution_criteria'],
                    sources=market_data['sources'],
                    notes=market_data.get('notes', ''),
                    b=float(market_data['b']),
                    q_yes=0.0,
                    q_no=0.0,
                    status=market_data.get('status', 'open'),
                    close_time=datetime.fromisoformat(market_data['close_time'].replace('Z', '+00:00')),
                    resolve_deadline=datetime.fromisoformat(market_data['resolve_deadline'].replace('Z', '+00:00')),
                    max_shares_per_buy=float(market_data.get('max_shares_per_buy', 10000.0)),
                    max_long_position_per_user=float(market_data.get('max_long_position_per_user', 50000.0)),
                    total_buy_trades=0,
                    unique_buyers=0
                )
                db.session.add(market)
                imported_count += 1
                print(f"✓ Importado: {market_data['slug']}")
        
        db.session.commit()
        
        print(f"\n{'='*50}")
        print("RESUMEN DE IMPORTACIÓN:")
        print(f"{'='*50}")
        print(f"✅ Mercados importados: {imported_count}")
        print(f"🔄 Mercados actualizados: {updated_count}")
        print(f"📊 Total en sistema: {Market.query.count()}")
        print(f"{'='*50}")
        
        return {
            'imported': imported_count,
            'updated': updated_count,
            'total': Market.query.count()
        }
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error importando mercados: {str(e)}")
        raise
