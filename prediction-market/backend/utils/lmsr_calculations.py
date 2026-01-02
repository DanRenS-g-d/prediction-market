import math
from decimal import Decimal, getcontext
import logging

logger = logging.getLogger(__name__)

# Configurar precisión para Decimal
getcontext().prec = 28  # Suficiente para cálculos financieros

class LMSRMarket:
    def __init__(self, b=100.0, q_yes=0.0, q_no=0.0):
        """
        Inicializa un mercado LMSR (SOLO COMPRAS)
        
        Args:
            b: Parámetro de liquidez (positivo)
            q_yes: Cantidad de acciones YES emitidas (no negativo)
            q_no: Cantidad de acciones NO emitidas (no negativo)
        """
        # Validar parámetros
        if float(b) <= 0:
            raise ValueError("Parámetro b debe ser positivo")
        if float(q_yes) < 0 or float(q_no) < 0:
            raise ValueError("q_yes y q_no no pueden ser negativos")
        
        # Convertir a Decimal para precisión
        self.b = Decimal(str(b))
        self.q_yes = Decimal(str(q_yes))
        self.q_no = Decimal(str(q_no))
        
        logger.debug(f"LMSRMarket inicializado: b={self.b}, q_yes={self.q_yes}, q_no={self.q_no}")
    
    def cost_function(self, q_y, q_n):
        """
        Función de costo C(q_yes, q_no)
        
        Args:
            q_y: q_yes como Decimal o convertible a Decimal
            q_n: q_no como Decimal o convertible a Decimal
            
        Returns:
            Decimal: Costo en puntos
        """
        try:
            q_y = Decimal(str(q_y))
            q_n = Decimal(str(q_n))
            
            # Evitar overflow en exp()
            # Si q/b es muy grande, usar aproximación
            exp_y = q_y / self.b
            exp_n = q_n / self.b
            
            # Para valores grandes, usar log-sum-exp trick
            max_val = max(exp_y, exp_n)
            
            # exp(x - max_val) para estabilidad numérica
            term1 = math.exp(float(exp_y - max_val))
            term2 = math.exp(float(exp_n - max_val))
            
            # C(q) = b * (max_val + log(exp(exp_y - max_val) + exp(exp_n - max_val)))
            result = self.b * (Decimal(str(max_val)) + Decimal(str(math.log(term1 + term2))))
            
            return result
            
        except Exception as e:
            logger.error(f"Error en cost_function: {str(e)}")
            raise
    
    def price_yes(self):
        """
        Calcula el precio implícito de YES (probabilidad)
        
        Returns:
            float: Precio entre 0 y 1
        """
        try:
            if self.q_yes == 0 and self.q_no == 0:
                return 0.5  # Mercado sin trades
            
            exp_yes = math.exp(float(self.q_yes / self.b))
            exp_no = math.exp(float(self.q_no / self.b))
            
            total = exp_yes + exp_no
            if total == 0:
                return 0.5
            
            price = exp_yes / total
            
            # Asegurar que esté entre 0 y 1 (por errores de redondeo)
            return max(0.0, min(1.0, price))
            
        except Exception as e:
            logger.error(f"Error calculando price_yes: {str(e)}")
            return 0.5
    
    def price_no(self):
        """
        Calcula el precio implícito de NO (probabilidad)
        
        Returns:
            float: Precio entre 0 y 1
        """
        price_yes = self.price_yes()
        return 1.0 - price_yes
    
    def current_prices(self):
        """
        Obtiene ambos precios simultáneamente
        
        Returns:
            dict: {'yes': price_yes, 'no': price_no}
        """
        price_yes = self.price_yes()
        return {
            'yes': price_yes,
            'no': 1.0 - price_yes
        }
    
    def buy_shares(self, outcome, shares):
        """
        Compra acciones de un resultado (SOLO COMPRAS PERMITIDAS)
        
        Args:
            outcome: 'YES' o 'NO'
            shares: cantidad de acciones a comprar (positivo)
            
        Returns:
            dict: {
                'cost': costo en puntos (Decimal),
                'new_q_yes': nueva cantidad YES (Decimal),
                'new_q_no': nueva cantidad NO (Decimal),
                'price_at_buy': precio en momento de compra (float),
                'shares_bought': shares compradas (Decimal)
            }
            
        Raises:
            ValueError: Si outcome no es válido o shares no es positivo
        """
        # Validaciones
        outcome = outcome.upper().strip()
        if outcome not in ['YES', 'NO']:
            raise ValueError("Outcome debe ser 'YES' o 'NO'")
        
        try:
            shares = Decimal(str(shares))
        except:
            raise ValueError("shares debe ser un número válido")
        
        if shares <= Decimal('0'):
            raise ValueError("shares debe ser positivo (solo compras permitidas)")
        
        logger.info(f"Compra LMSR: outcome={outcome}, shares={shares}, q_yes={self.q_yes}, q_no={self.q_no}")
        
        # Estado actual
        old_cost = self.cost_function(self.q_yes, self.q_no)
        
        # Nuevo estado
        if outcome == 'YES':
            new_q_yes = self.q_yes + shares
            new_q_no = self.q_no
            price_at_buy = self.price_yes()
        else:  # 'NO'
            new_q_yes = self.q_yes
            new_q_no = self.q_no + shares
            price_at_buy = self.price_no()
        
        # Calcular costo
        new_cost = self.cost_function(new_q_yes, new_q_no)
        cost = new_cost - old_cost
        
        # Validar que costo sea positivo (siempre debería ser para compras)
        if cost < Decimal('0'):
            logger.warning(f"Costo negativo detectado: {cost}. Ajustando a 0.")
            cost = Decimal('0')
        
        # Preparar resultado
        result = {
            'cost': cost,
            'new_q_yes': new_q_yes,
            'new_q_no': new_q_no,
            'price_at_buy': float(price_at_buy),
            'shares_bought': shares
        }
        
        logger.debug(f"Resultado compra: {result}")
        return result
    
    def get_liquidity(self):
        """
        Calcula la liquidez total del mercado
        
        Returns:
            Decimal: Liquidez total (q_yes + q_no)
        """
        return self.q_yes + self.q_no
    
    def get_market_depth(self):
        """
        Calcula la profundidad del mercado (sensibilidad del precio)
        
        Returns:
            float: Cuánto cambia el precio por unidad comprada
        """
        try:
            # Derivada del precio: dp/dq = p*(1-p)/b
            p = self.price_yes()
            return float(p * (1 - p) / self.b)
        except:
            return 0.0
    
    def calculate_price_impact(self, outcome, shares):
        """
        Calcula el impacto en el precio de una compra potencial
        
        Args:
            outcome: 'YES' o 'NO'
            shares: cantidad a comprar
            
        Returns:
            dict: {
                'price_before': precio antes de compra,
                'price_after': precio después de compra,
                'impact_percent': cambio porcentual,
                'estimated_cost': costo estimado
            }
        """
        try:
            outcome = outcome.upper()
            shares = Decimal(str(shares))
            
            # Precio antes
            price_before = self.price_yes() if outcome == 'YES' else self.price_no()
            
            # Simular compra (sin modificar estado)
            temp_market = LMSRMarket(
                b=float(self.b),
                q_yes=float(self.q_yes),
                q_no=float(self.q_no)
            )
            
            result = temp_market.buy_shares(outcome, float(shares))
            
            # Precio después
            if outcome == 'YES':
                price_after = temp_market.price_yes()
            else:
                price_after = temp_market.price_no()
            
            # Calcular impacto
            impact = abs(price_after - price_before)
            impact_percent = (impact / price_before * 100) if price_before > 0 else 0
            
            return {
                'price_before': price_before,
                'price_after': price_after,
                'impact_absolute': impact,
                'impact_percent': impact_percent,
                'estimated_cost': float(result['cost'])
            }
            
        except Exception as e:
            logger.error(f"Error calculando impacto: {str(e)}")
            return {
                'price_before': 0.0,
                'price_after': 0.0,
                'impact_absolute': 0.0,
                'impact_percent': 0.0,
                'estimated_cost': 0.0
            }
    
    def to_dict(self):
        """Convierte el estado del mercado a dict"""
        return {
            'b': float(self.b),
            'q_yes': float(self.q_yes),
            'q_no': float(self.q_no),
            'price_yes': self.price_yes(),
            'price_no': self.price_no(),
            'liquidity': float(self.get_liquidity()),
            'market_depth': self.get_market_depth()
        }
    
    @classmethod
    def from_dict(cls, data):
        """Crea una instancia desde un dict"""
        return cls(
            b=data.get('b', 100.0),
            q_yes=data.get('q_yes', 0.0),
            q_no=data.get('q_no', 0.0)
        )


# ==================== FUNCIONES DE UTILIDAD ====================

def calculate_lmsr_cost(b, q_yes_before, q_no_before, outcome, shares):
    """
    Función de conveniencia para calcular costo de compra
    
    Args:
        b: parámetro de liquidez
        q_yes_before: q_yes antes de la compra
        q_no_before: q_no antes de la compra
        outcome: 'YES' o 'NO'
        shares: acciones a comprar
        
    Returns:
        float: costo en puntos
    """
    market = LMSRMarket(b=b, q_yes=q_yes_before, q_no=q_no_before)
    result = market.buy_shares(outcome, shares)
    return float(result['cost'])


def calculate_price_from_q(b, q_yes, q_no, outcome='YES'):
    """
    Calcula precio directamente desde valores q
    
    Args:
        b: parámetro de liquidez
        q_yes: cantidad YES
        q_no: cantidad NO
        outcome: 'YES' o 'NO' (qué precio calcular)
        
    Returns:
        float: precio entre 0 y 1
    """
    market = LMSRMarket(b=b, q_yes=q_yes, q_no=q_no)
    if outcome.upper() == 'YES':
        return market.price_yes()
    else:
        return market.price_no()


# ==================== TESTS (para desarrollo) ====================

if __name__ == "__main__":
    # Configurar logging para pruebas
    logging.basicConfig(level=logging.DEBUG)
    
    print("=== Pruebas LMSRMarket ===")
    
    # Test 1: Mercado vacío
    print("\n1. Mercado vacío (b=100):")
    market1 = LMSRMarket(b=100)
    print(f"   Precio YES: {market1.price_yes():.4f}")
    print(f"   Precio NO:  {market1.price_no():.4f}")
    
    # Test 2: Compra de YES
    print("\n2. Comprar 100 YES:")
    result = market1.buy_shares('YES', 100)
    print(f"   Costo: {float(result['cost']):.2f} puntos")
    print(f"   Nuevo precio YES: {market1.price_yes():.4f}")
    print(f"   Nuevo precio NO:  {market1.price_no():.4f}")
    
    # Test 3: Compra de NO
    print("\n3. Comprar 50 NO:")
    market2 = LMSRMarket(b=100, q_yes=100, q_no=0)
    result = market2.buy_shares('NO', 50)
    print(f"   Costo: {float(result['cost']):.2f} puntos")
    print(f"   Nuevo precio YES: {market2.price_yes():.4f}")
    print(f"   Nuevo precio NO:  {market2.price_no():.4f}")
    
    # Test 4: Impacto en precio
    print("\n4. Impacto de compra grande:")
    market3 = LMSRMarket(b=100)
    impact = market3.calculate_price_impact('YES', 1000)
    print(f"   Precio antes: {impact['price_before']:.4f}")
    print(f"   Precio después: {impact['price_after']:.4f}")
    print(f"   Impacto: {impact['impact_percent']:.1f}%")
    
    # Test 5: Decimal precision
    print("\n5. Precisión Decimal:")
    market4 = LMSRMarket(b=100, q_yes=123.456, q_no=78.912)
    print(f"   q_yes: {market4.q_yes}")
    print(f"   q_no:  {market4.q_no}")
    print(f"   Precio YES: {market4.price_yes():.6f}")
    
    print("\n✅ Todas las pruebas completadas")
