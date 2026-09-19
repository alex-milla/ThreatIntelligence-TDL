# CHECKPOINT v1.3.55 — Migración a estructura public_html

> Generado el 2026-09-19

## Resumen

Se ha completado la reorganización de la estructura de directorios del proyecto, moviendo todos los archivos y directorios accesibles por web al directorio `public_html/`.

## Cambios realizados

### Archivos movidos a `public_html/`

**Archivos PHP en raíz:**
- account.php
- index.php
- install.php
- keywords.php
- login.php
- logout.php
- notifications.php
- register.php
- watchlist.php
- ajax_recheck_status.php
- ajax_tag_domain.php
- ajax_tld_status.php
- ajax_watchlist.php
- ajax_whois.php
- ajax_whois_cache.php
- ajax_whois_request.php
- ajax_whois_result.php
- .htaccess

**Directorios:**
- admin/
- api/
- assets/
- includes/
- templates/
- css/
- js/

### Estructura resultante

```
ThreatIntelligence-TDL/
├── CHANGELOG.md
├── README.md
├── VERSION (1.3.54 -> 1.3.55)
├── data/              # Datos sensibles (FUERA de public_html)
│   └── app.db
├── env/               # Configuración de entorno
│   └── .env
├── md/                # Documentación y checkpoints
│   └── CHECKPOINT-*.md
├── public_html/       # DocumentRoot del servidor web
│   ├── .htaccess
│   ├── account.php
│   ├── index.php
│   ├── install.php
│   ├── keywords.php
│   ├── login.php
│   ├── logout.php
│   ├── notifications.php
│   ├── register.php
│   ├── watchlist.php
│   ├── ajax_*.php
│   ├── admin/
│   │   ├── index.php
│   │   ├── tlds.php
│   │   ├── update.php
│   │   ├── cleanup.php
│   │   └── .htaccess
│   ├── api/
│   │   └── v1/
│   │       ├── commands.php
│   │       ├── keywords.php
│   │       ├── matches.php
│   │       └── ...
│   ├── assets/
│   │   ├── css/
│   │   │   └── main.css
│   │   └── whois.js
│   ├── css/
│   │   ├── materialize.css
│   │   ├── materialize.min.css
│   │   └── ...
│   ├── includes/
│   │   ├── auth.php
│   │   ├── db.php
│   │   ├── mail.php
│   │   └── whois.php
│   ├── js/
│   │   └── materialize.js
│   └── templates/
│       ├── header.php
│       └── footer.php
└── worker/            # Worker Python (FUERA de public_html)
    ├── scheduler.py
    ├── downloader.py
    ├── parser.py
    ├── matcher.py
    ├── sync_client.py
    ├── logger.py
    └── ...
```

## Verificación de paths

### Paths PHP (require/require_once)

Todos los paths relativos en los archivos PHP siguen funcionando correctamente porque usan `__DIR__`:

- `templates/header.php`: `__DIR__ . '/../includes/auth.php'` → `public_html/templates/../includes/auth.php` = `public_html/includes/auth.php` ✓
- `admin/index.php`: `__DIR__ . '/../includes/db.php'` → `public_html/admin/../includes/db.php` = `public_html/includes/db.php` ✓
- `admin/index.php`: `__DIR__ . '/../templates/header.php'` → `public_html/admin/../templates/header.php` = `public_html/templates/header.php` ✓
- `index.php`: `__DIR__ . '/includes/db.php'` → `public_html/includes/db.php` ✓

### Paths de assets (CSS/JS)

Los paths absolutos de document root funcionan correctamente:

- `/assets/css/main.css` → `public_html/assets/css/main.css` ✓
- `/assets/whois.js` → `public_html/assets/whois.js` ✓

### Paths AJAX

Todos los endpoints AJAX usan paths absolutos:

- `/ajax_whois.php` → `public_html/ajax_whois.php` ✓
- `/api/v1/worker_status.php` → `public_html/api/v1/worker_status.php` ✓

## Configuración del servidor

### Apache (recomendado)

```apache
<VirtualHost *:80>
    ServerName tdl.example.com
    DocumentRoot /ruta/ThreatIntelligence-TDL/public_html
    
    <Directory /ruta/ThreatIntelligence-TDL/public_html>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    # Bloquear acceso directo a directorios sensibles
    <Directory /ruta/ThreatIntelligence-TDL/data>
        Require all denied
    </Directory>
    
    <Directory /ruta/ThreatIntelligence-TDL/env>
        Require all denied
    </Directory>
    
    <Directory /ruta/ThreatIntelligence-TDL/worker>
        Require all denied
    </Directory>
</VirtualHost>
```

### Nginx

```nginx
server {
    listen 80;
    server_name tdl.example.com;
    root /ruta/ThreatIntelligence-TDL/public_html;
    
    index index.php;
    
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
    
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.x-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }
    
    # Bloquear acceso a directorios sensibles
    location ^~ /../ {
        deny all;
        return 403;
    }
}
```

## .htaccess actualizado

El archivo `public_html/.htaccess` ha sido actualizado para:
- Bloquear acceso a archivos ocultos (que comienzan con .)
- Bloquear intentos de acceso a directorios padre (../)
- Mantener las reglas opcionales de Pretty URLs comentadas

## Impacto en el worker

El worker Python **NO requiere cambios** porque:
- Se ejecuta fuera del web server
- Las URLs de la API que consume ya usan paths absolutos (ej: `https://tdl.example.com/api/v1/matches.php`)
- La configuración del worker (config.ini) apunta a la URL base del sitio, no a paths de sistema de archivos

## Próximos pasos

1. **Configurar el servidor web** para que el DocumentRoot apunte a `public_html/`
2. **Verificar permisos** de archivos en `public_html/`
3. **Testear la aplicación** completamente:
   - Navegación entre páginas
   - Funcionalidad de login/registro
   - API endpoints
   - Admin panel
   - AJAX requests
4. **Actualizar VERSION** a 1.3.55

## Notas de seguridad

- El directorio `data/` ahora está fuera del DocumentRoot, mejorando la seguridad
- El directorio `env/` con credenciales también está fuera del DocumentRoot
- El directorio `worker/` con el código Python está protegido
- Se recomienda mantener los permisos restrictivos en todos los directorios sensibles

---

*Checkpoint generado automáticamente tras migración a estructura public_html.*
