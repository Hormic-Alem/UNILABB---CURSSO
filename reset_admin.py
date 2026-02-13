import json
from werkzeug.security import generate_password_hash

USERS_FILE = 'data/users.json'

# Cargar los usuarios existentes
with open(USERS_FILE, 'r', encoding='utf-8') as f:
    users = json.load(f)

# Nueva contraseña que quieras asignar
nueva_contraseña = 'Admin1234'  # Cambia esto por la que quieras

# Buscar el usuario admin y resetear la contraseña
admin_encontrado = False
for user in users:
    if user['username'] == 'admin':
        user['password'] = generate_password_hash(nueva_contraseña)
        user['active'] = True  # Asegúrate de que esté activo
        admin_encontrado = True
        break

if not admin_encontrado:
    print("No se encontró un usuario 'admin' en users.json")
else:
    # Guardar de nuevo el archivo
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=4, ensure_ascii=False)
    print(f"✅ Contraseña del admin reseteada a '{nueva_contraseña}'")
