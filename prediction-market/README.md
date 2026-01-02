# Prediction Market Platform

Mercado de predicciones sin dinero real, diseñado para evaluar la calidad del análisis y la información de los usuarios mediante competencia reputacional.

## Descripción general

Esta plataforma permite a los usuarios comprar participaciones **YES / NO** sobre eventos definidos previamente.  
El sistema utiliza un **market maker automatizado basado en LMSR (Logarithmic Market Scoring Rule)** y un diseño **solo-compras** para evitar manipulación y simplificar incentivos.

No existe retiro de dinero ni trading financiero real.

## Características

- Sistema **Buy-Only** (no se permite vender)
- Precios dinámicos mediante **LMSR**
- Límites por usuario y por mercado
- Resolución determinística de eventos
- Capacidad de rollback administrativo
- API REST con control de acceso por roles

## Stack tecnológico

**Backend**
- Python 3.9+
- Flask
- SQLAlchemy
- PostgreSQL / SQLite

**Infraestructura**
- Preparado para Railway
- Variables de entorno mediante `.env`

## Estructura del proyecto

```
prediction-market/
├── backend/          # API Flask
├── database/         # Esquemas SQL
├── scripts/          # Scripts de inicialización
├── docs/             # Documentación
├── README.md
└── .gitignore
```

## Instalación rápida (desarrollo local)

```bash
git clone https://github.com/tu-usuario/prediction-market.git
cd prediction-market

cd backend
cp .env.example .env
pip install -r requirements.txt

python -c "from app import db; db.create_all()"
python ../scripts/initialize_markets.py

python app.py
```

La API quedará disponible en:
```
http://localhost:5000
```

## Reglas del mercado

- Solo se permiten compras
- Las posiciones son siempre largas
- El precio es calculado exclusivamente por LMSR
- Los mercados resuelven a un resultado binario

## Propósito del proyecto

Este proyecto fue construido como:
- Producto funcional
- Demostración de ingeniería backend
- Experimento de diseño de mercados informacionales

No es un producto financiero.

## Licencia

MIT License
