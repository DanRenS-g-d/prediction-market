# Script para inicializar los 5 mercados específicos
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

def initialize_markets():
    """
    Inicializa los 5 mercados específicos para la aplicación.
    
    IMPORTANTE: Todos los mercados son MODO SOLO COMPRAS
    Basado en los 5 mercados definidos por el usuario.
    """
    try:
        # Verificar si ya existen mercados
        existing_count = Market.query.count()
        if existing_count >= 5:
            logger.info(f"Ya existen {existing_count} mercados. Saltando inicialización.")
            return
        
        logger.info("Inicializando 5 mercados específicos...")
        
        # Fecha de referencia para deadlines
        now = datetime.utcnow()
        
        markets = [
            # ==================== MERCADO 1: Conflicto USA-Venezuela ====================
            {
                'slug': 'conflicto-usa-venezuela-abril-2026',
                'title': '¿Estados Unidos y Venezuela entrarán en un conflicto bélico abierto antes del 1 de abril de 2026 a las 00:00 (hora UTC)?',
                'description': '''Posibilidad de conflicto militar directo entre Estados Unidos y Venezuela. 
                
                Contexto: Tensiones geopolíticas, sanciones económicas y diferencias ideológicas han caracterizado la relación bilateral. Este mercado predice si escalará a un conflicto bélico abierto.''',
                
                'resolution_criteria': '''SE RESUELVE COMO SÍ si ocurre CUALQUIERA de estos eventos:
                1. Acción militar directa y reconocida públicamente
                   - Ataques militares de fuerzas armadas de EE.UU. contra objetivos militares o estatales venezolanos, o viceversa.
                2. Enfrentamiento armado entre fuerzas oficiales
                   - Combate directo entre fuerzas armadas regulares de ambos países.
                3. Declaración oficial de hostilidades
                   - Reconocimiento oficial de operaciones militares entre ambos Estados por alguno de los gobiernos.
                
                SE RESUELVE COMO NO si:
                1. Solo hay sanciones económicas
                2. Solo ciberataques no reconocidos oficialmente
                3. Solo escaramuzas con actores no estatales
                4. Solo retórica política o amenazas
                5. Solo movimientos militares sin enfrentamiento
                6. No ocurre ningún evento que cumpla los criterios de SÍ antes de la fecha límite.
                
                NOTAS ACLARATORIAS (CRÍTICAS):
                • No cuentan conflictos por terceros (grupos armados no estatales)
                • No cuentan acciones encubiertas no reconocidas
                • No cuentan incidentes aislados sin confirmación oficial
                • Debe existir reconocimiento público verificable''',
                
                'sources': '''FUENTES OFICIALES:
                1. Comunicados del Departamento de Defensa de EE.UU.
                2. Comunicados del Gobierno de Venezuela
                3. Confirmación por organismos internacionales:
                   - Naciones Unidas (ONU)
                   - Organización de Estados Americanos (OEA)
                
                FUENTES SECUNDARIAS (para verificación):
                • Reuters
                • Associated Press
                • AFP
                • Medios oficiales de ambos países''',
                
                'notes': 'Mercado geopolítico de alto impacto. Basado en fuentes oficiales. Considerar contexto de tensiones históricas.',
                'b': 100.0,  # Liquidez media-alta por ser mercado sensible
                'q_yes': 0.0,
                'q_no': 0.0,
                'status': 'open',
                'close_time': datetime(2026, 4, 1, 0, 0, 0),  # 1 de abril 2026, 00:00 UTC
                'resolve_deadline': datetime(2026, 4, 15, 0, 0, 0),  # 2 semanas para verificar
                'max_shares_per_buy': 5000.0,
                'max_long_position_per_user': 25000.0,
                'total_buy_trades': 0,
                'unique_buyers': 0
            },
            
            # ==================== MERCADO 2: Bitcoin 100K ====================
            {
                'slug': 'bitcoin-100k-junio-2026',
                'title': '¿El precio de Bitcoin (BTC) caerá por debajo de USD 100.000 en algún momento antes del 1 de junio de 2026 a las 23:59 (hora UTC)?',
                'description': '''Predicción sobre la volatilidad de Bitcoin. 
                
                Contexto: Bitcoin ha mostrado alta volatilidad histórica. Este mercado predice si durante el período especificado el precio caerá por debajo del umbral psicológico de USD 100,000, independientemente de su precio inicial o final.''',
                
                'resolution_criteria': '''EL MERCADO SE RESUELVE COMO SÍ si:
                • El precio spot BTC/USD es estrictamente menor a USD 100,000
                • En cualquier momento antes del límite temporal (1 junio 2026, 23:59 UTC)
                • No importa si ocurre por segundos, minutos u horas
                
                EL MERCADO SE RESUELVE COMO NO si:
                • Bitcoin nunca cae por debajo de USD 100,000 durante todo el período
                • El precio se mantiene en o por encima de USD 100,000
                
                DEFINICIONES:
                • "Precio spot": Precio de mercado actual para compra/venta inmediata
                • "USD 100,000": Exactamente 100,000 dólares estadounidenses
                • "Momento": Cualquier instante de tiempo dentro del período''',
                
                'sources': '''FUENTE PRIMARIA OBLIGATORIA:
                • CoinMarketCap — Precio spot BTC/USD (promedio ponderado por volumen)
                
                FUENTES DE RESERVA (en caso de indisponibilidad):
                • CoinGecko API
                • Binance API (BTC/USDT convertido a USD)
                • Coinbase API
                
                METODOLOGÍA:
                Se usará el precio spot agregado de CoinMarketCap.
                En caso de discrepancia, prevalecerá CoinMarketCap.''',
                
                'notes': '''Mercado financiero. 
                Considerar: Halving de Bitcoin 2024, adopción institucional, regulaciones.
                Umbral psicológico importante: USD 100,000.''',
                'b': 150.0,  # Alta liquidez por ser mercado financiero
                'q_yes': 0.0,
                'q_no': 0.0,
                'status': 'open',
                'close_time': datetime(2026, 6, 1, 23, 59, 0),  # 1 junio 2026, 23:59 UTC
                'resolve_deadline': datetime(2026, 6, 8, 23, 59, 0),  # 1 semana para verificar
                'max_shares_per_buy': 10000.0,
                'max_long_position_per_user': 50000.0,
                'total_buy_trades': 0,
                'unique_buyers': 0
            },
            
            # ==================== MERCADO 3: Colombia Mundial 2026 ====================
            {
                'slug': 'colombia-campeon-mundial-2026',
                'title': '¿La selección masculina de fútbol de Colombia ganará la Copa Mundial de la FIFA 2026?',
                'description': '''Predicción sobre el desempeño de la selección colombiana en el Mundial 2026.
                
                Contexto: Colombia tiene tradición futbolística y ha tenido participaciones destacadas en mundiales anteriores. Mundial 2026 será en USA, Canadá y México.''',
                
                'resolution_criteria': '''SE RESUELVE COMO SÍ si:
                • La Selección Colombia masculina gana la final del Mundial FIFA 2026
                • Es declarada campeona oficial del torneo por la FIFA
                • Se le otorga la Copa del Mundo
                
                SE RESUELVE COMO NO en cualquier otro caso:
                • Eliminación en cualquier fase (grupos, octavos, cuartos, semifinal)
                • Subcampeón (pierde la final)
                • No se clasifica al torneo
                • Descalificación
                • Abandono
                • Cualquier resultado que no sea campeón
                
                ACLARACIONES:
                • Solo cuenta la selección masculina mayor
                • Solo cuenta el Mundial FIFA 2026 (no otros torneos)
                • Resultado basado en el partido final oficial''',
                
                'sources': '''FUENTE OFICIAL ÚNICA:
                • FIFA — Comunicado oficial del campeón del Mundial FIFA 2026
                
                FUENTE DE VERIFICACIÓN:
                • Sitio web oficial FIFA.com
                • Conferencia de prensa post-final
                
                NO SE USAN:
                • Medios deportivos (ESPN, Fox Sports, etc.)
                • Redes sociales
                • Rankings o resultados parciales
                • Encuestas o pronósticos''',
                
                'notes': '''Mercado deportivo de alto interés en Colombia.
                Considerar: Lesiones clave, rendimiento histórico, sorteo de grupos.
                Mundial 2026: 48 selecciones, formato expandido.''',
                'b': 120.0,  # Buena liquidez por interés popular
                'q_yes': 0.0,
                'q_no': 0.0,
                'status': 'open',
                'close_time': datetime(2026, 7, 19, 23, 59, 0),  # Final Mundial ~19 julio 2026
                'resolve_deadline': datetime(2026, 7, 26, 23, 59, 0),  # 1 semana post-final
                'max_shares_per_buy': 8000.0,
                'max_long_position_per_user': 40000.0,
                'total_buy_trades': 0,
                'unique_buyers': 0
            },
            
            # ==================== MERCADO 4: Inflación Colombia 2026 ====================
            {
                'slug': 'inflacion-colombia-2026-mayor-2025',
                'title': '¿La inflación anual en Colombia en diciembre de 2026 será mayor que la de diciembre de 2025, tras el aumento del salario mínimo decretado para 2026?',
                'description': '''Predicción sobre inflación en Colombia, considerando efecto del aumento salarial.
                
                Contexto: Colombia ha enfrentado presiones inflacionarias post-pandemia. Aumentos salariales pueden impactar la inflación vía costos.''',
                
                'resolution_criteria': '''SE RESUELVE COMO SÍ si:
                • La inflación anual (IPC interanual) de diciembre 2026
                • Es estrictamente mayor que la inflación anual de diciembre 2025
                • Comparación: IPC_dic2026 > IPC_dic2025
                
                SE RESUELVE COMO NO si:
                • La inflación anual de diciembre 2026 es igual a la de diciembre 2025
                • La inflación anual de diciembre 2026 es menor que la de diciembre 2025
                • IPC_dic2026 ≤ IPC_dic2025
                
                DEFINICIONES:
                • "Inflación anual": Variación porcentual del IPC últimos 12 meses
                • "IPC interanual": Índice de Precios al Consumidor
                • "Diciembre 2025/2026": Datos publicados en enero 2026/2027 respectivamente
                
                FACTOR SALARIO MÍNIMO:
                • El aumento decretado para 2026 es un factor contextual
                • No afecta criterio de resolución (solo datos oficiales del IPC)''',
                
                'sources': '''FUENTE OFICIAL OBLIGATORIA:
                • DANE (Departamento Administrativo Nacional de Estadística)
                • Boletín oficial del Índice de Precios al Consumidor (IPC)
                • Publicación mensual de inflación
                
                FUENTES ESPECÍFICAS:
                • Boletín "IPC e inflación" de diciembre 2025 (publicado enero 2026)
                • Boletín "IPC e inflación" de diciembre 2026 (publicado enero 2027)
                
                METODOLOGÍA:
                • Se usarán cifras oficiales finales (no preliminares)
                • Redondeo a dos decimales
                • Comparación directa de porcentajes''',
                
                'notes': '''Mercado económico técnico.
                Considerar: Política monetaria del Banco de la República, precios de commodities, tasa de cambio.
                El aumento salarial 2026 es ~10-12% estimado.''',
                'b': 90.0,  # Liquidez media por mercado especializado
                'q_yes': 0.0,
                'q_no': 0.0,
                'status': 'open',
                'close_time': datetime(2026, 12, 31, 23, 59, 0),  # Fin de año 2026
                'resolve_deadline': datetime(2027, 2, 15, 23, 59, 0),  # Tiempo para publicación DANE
                'max_shares_per_buy': 6000.0,
                'max_long_position_per_user': 30000.0,
                'total_buy_trades': 0,
                'unique_buyers': 0
            },
            
            # ==================== MERCADO 5: Presidente Colombia 2026 ====================
            {
                'slug': 'ivan-cepeda-presidente-colombia-2026',
                'title': '¿Iván Cepeda Castro será elegido presidente de la República de Colombia en las elecciones presidenciales de 2026?',
                'description': '''Predicción sobre resultados electorales presidenciales en Colombia 2026.
                
                Contexto: Iván Cepeda Castro es senador y figura política reconocida. Elecciones 2026 serán cruciales para el rumbo del país.''',
                
                'resolution_criteria': '''SE RESUELVE COMO SÍ si:
                • Iván Cepeda Castro es declarado presidente electo
                • Tras la segunda vuelta presidencial de 2026 (si aplica)
                • Según el resultado oficial certificado
                • Asume la presidencia en agosto 2026
                
                SE RESUELVE COMO NO en cualquier otro caso:
                • Pierde en primera o segunda vuelta
                • No se presenta como candidato
                • Se retira antes de las elecciones
                • Elecciones son anuladas y no resulta electo
                • Cualquier otro candidato es declarado ganador
                • Fallece o queda inhabilitado antes de la posesión
                
                ACLARACIONES:
                • Solo cuenta como presidente electo (no designado/interino)
                • Debe completar proceso de certificación oficial
                • Posibilidad de segunda vuelta incluida''',
                
                'sources': '''FUENTE OFICIAL OBLIGATORIA:
                • Registraduría Nacional del Estado Civil
                • Certificación oficial de resultados electorales
                • Acta de escrutinio nacional
                
                FUENTES DE VERIFICACIÓN:
                • Consejo Nacional Electoral
                • Jurados de votación (actas escaneadas)
                • Transmisión de resultados en tiempo real
                
                NO SE ACEPTAN:
                • Encuestas o sondeos
                • Declaraciones de candidatos
                • Medios de comunicación (solo para contexto)
                • Redes sociales''',
                
                'notes': '''Mercado político de alto interés.
                Considerar: Coaliciones políticas, polarización, participación electoral.
                Elecciones 2026: Primer domingo de marzo (1a vuelta), junio (2a vuelta).''',
                'b': 110.0,  # Buena liquidez por interés político
                'q_yes': 0.0,
                'q_no': 0.0,
                'status': 'open',
                'close_time': datetime(2026, 6, 30, 23, 59, 0),  # Después de posibles 2da vuelta
                'resolve_deadline': datetime(2026, 7, 15, 23, 59, 0),  # Tiempo para certificación
                'max_shares_per_buy': 7000.0,
                'max_long_position_per_user': 35000.0,
                'total_buy_trades': 0,
                'unique_buyers': 0
            }
        ]
        
        created_markets = []
        for market_data in markets:
            # Verificar si ya existe
            existing = Market.query.filter_by(slug=market_data['slug']).first()
            if existing:
                logger.info(f"Mercado {market_data['slug']} ya existe. Actualizando información.")
                # Actualizar información si es necesario
                existing.title = market_data['title']
                existing.description = market_data.get('description', existing.description)
                existing.resolution_criteria = market_data['resolution_criteria']
                existing.sources = market_data['sources']
                existing.notes = market_data.get('notes', existing.notes)
                existing.b = market_data['b']
                existing.max_shares_per_buy = market_data.get('max_shares_per_buy', existing.max_shares_per_buy)
                existing.max_long_position_per_user = market_data.get('max_long_position_per_user', existing.max_long_position_per_user)
                created_markets.append(market_data['slug'])
                continue
            
            # Crear mercado nuevo
            market = Market(
                slug=market_data['slug'],
                title=market_data['title'],
                description=market_data.get('description', ''),
                resolution_criteria=market_data['resolution_criteria'],
                sources=market_data['sources'],
                notes=market_data.get('notes', ''),
                b=market_data['b'],
                q_yes=market_data['q_yes'],
                q_no=market_data['q_no'],
                status=market_data['status'],
                close_time=market_data['close_time'],
                resolve_deadline=market_data.get('resolve_deadline', 
                    market_data['close_time'] + timedelta(days=14)),
                max_shares_per_buy=market_data.get('max_shares_per_buy', 10000.0),
                max_long_position_per_user=market_data.get('max_long_position_per_user', 50000.0),
                total_buy_trades=market_data.get('total_buy_trades', 0),
                unique_buyers=market_data.get('unique_buyers', 0)
            )
            
            db.session.add(market)
            created_markets.append(market_data['slug'])
        
        # Commit solo si hay cambios
        if created_markets:
            db.session.commit()
            logger.info(f"✅ {len(created_markets)} mercados procesados:")
            for slug in created_markets:
                market = Market.query.filter_by(slug=slug).first()
                logger.info(f"   - {slug}: {market.title[:50]}...")
            
            # Mostrar resumen en consola
            print("\n" + "=" * 70)
            print("🎯 5 MERCADOS ESPECÍFICOS INICIALIZADOS")
            print("=" * 70)
            
            markets_summary = Market.query.order_by(Market.created_at.asc()).all()
            for i, market in enumerate(markets_summary, 1):
                close_date = market.close_time.strftime("%d/%m/%Y") if market.close_time else "N/A"
                price_yes = f"{market.price_yes:.3f}" if hasattr(market, 'price_yes') else "0.500"
                price_no = f"{market.price_no:.3f}" if hasattr(market, 'price_no') else "0.500"
                
                print(f"{i}. {market.slug}")
                print(f"   📌 {market.title[:60]}...")
                print(f"   ⏰ Cierra: {close_date}")
                print(f"   📊 Precios: SÍ={price_yes} | NO={price_no}")
                print(f"   🔢 Liquidez: b={market.b}")
                print()
            
            print("=" * 70)
            print(f"📈 Total: {len(markets_summary)} mercados activos")
            print("=" * 70)
            
        else:
            logger.info("No se procesaron nuevos mercados")
        
        return created_markets
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ Error inicializando mercados: {str(e)}", exc_info=True)
        print(f"❌ Error inicializando mercados: {str(e)}")
        raise
