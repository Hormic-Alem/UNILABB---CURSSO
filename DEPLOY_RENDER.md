# Deploy Flask + Gunicorn en Render (paso a paso)

## 1) Archivos necesarios (ya incluidos)

- `requirements.txt`
- `Procfile`
- `runtime.txt`

## 2) Configuración en Render Dashboard

Al crear el servicio **Web Service**:

- **Runtime**: `Python 3`
- **Build Command**:
  ```bash
  pip install -r requirements.txt
  ```
- **Start Command**:
  ```bash
  gunicorn app:app
  ```

## 3) Variables de entorno (Environment)

En `Environment Variables`, agrega:

- `DATABASE_URL` = URL de PostgreSQL (Render)
- `SECRET_KEY` = una clave larga aleatoria (ejemplo 64+ caracteres)
- `SESSION_COOKIE_SECURE` = `true` (en producción HTTPS)

## 4) Conectar GitHub con Render

1. En Render: **New +** → **Web Service**.
2. Conecta tu cuenta de GitHub.
3. Selecciona el repositorio.
4. Completa:
   - **Name**: nombre de tu app
   - **Branch**: `main`
   - **Root Directory**: *(déjalo vacío, porque `app.py` está en la raíz del repo)*
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
5. Agrega variables de entorno y presiona **Create Web Service**.
