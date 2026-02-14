# Deploy Flask + PostgreSQL en Railway

## 1) Requisitos del repositorio

Este proyecto ya incluye lo necesario:

- `requirements.txt`
- `Procfile` (`web: gunicorn app:app`)
- `railway.toml` con `startCommand = "gunicorn app:app"`

## 2) Crear el proyecto en Railway

1. Entra a Railway y selecciona **New Project**.
2. Elige **Deploy from GitHub repo**.
3. Selecciona este repositorio.
4. Railway detectará Python automáticamente por `requirements.txt`.

## 3) Base de datos PostgreSQL en Railway

1. Dentro del proyecto, agrega **PostgreSQL**.
2. Railway creará automáticamente la variable `DATABASE_URL`.

## 4) Variables de entorno

Configura al menos:

- `DATABASE_URL` (normalmente auto-creada por Railway PostgreSQL)
- `SECRET_KEY` (cadena larga aleatoria)
- `SESSION_COOKIE_SECURE=true` (recomendado en producción HTTPS)

## 5) Comandos de build y start

- Build: `pip install -r requirements.txt`
- Start: `gunicorn app:app`

> Nota: el proyecto ya usa `DATABASE_URL` en `app.py` y normaliza `postgres://` a `postgresql://` para SQLAlchemy.

## 6) Verificación rápida post deploy

1. Abre la URL pública de Railway.
2. Verifica que `/landing` carga correctamente.
3. Revisa logs para confirmar que Gunicorn inicia sin errores.
