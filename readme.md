# Finovra Phishing Detector

Herramienta de escritorio para revisar correos (`.eml`) y URLs sospechosas antes de hacer clic en ellas. Todo el análisis se realiza de forma local en tu equipo: **no se abre ninguna URL, no se ejecuta ningún adjunto y no se envía información a internet**.

---

## Características principales

* **Escáner de URLs:** Pegas un enlace y la herramienta evalúa su estructura en busca de direcciones IP en lugar de dominios, acortadores, *typosquatting* (nombres que imitan marcas conocidas), caracteres codificados y subdominios excesivos, entre otros indicadores.
* **Analizador de correos:** Permite abrir archivos `.eml` para inspeccionar el remitente, la dirección de respuesta (`Reply-To`), el asunto, los enlaces incrustados, los adjuntos y las cabeceras de autenticación (`SPF`, `DKIM` y `DMARC`, leídas tal como vienen en el mensaje).
* **Detección de campañas:** Con dos o más correos analizados, agrupa automáticamente aquellos que parecen formar parte de una misma campaña basándose en enlaces compartidos, remitente, asunto o similitud de texto.
* **Historial y resumen:** Almacena cada análisis en una base de datos local. La vista de resumen incluye gráficas con la distribución porcentual de riesgo y permite limpiar el historial cuando lo desees.
* **Lista local de dominios maliciosos (opcional):** Permite cargar tu propia lista de bloqueo. Si una URL pertenece a alguno de esos dominios, su clasificación sube automáticamente a **Alto riesgo**.
* **Método transparente:** Incluye una pestaña dedicada que explica exactamente cómo se calcula cada nivel de riesgo.

---

## Niveles de riesgo

| Nivel | Significado |
| :--- | :--- |
| **Bajo riesgo** | No se encontraron indicadores relevantes, o se detectó únicamente uno débil. |
| **Sospechosa** | Existe un indicador moderado o varios débiles. Conviene revisarla con cautela. |
| **Alto riesgo** | Existe un indicador fuerte o dos o más sospechosos. Se recomienda evitarla. |

> **Nota:** Un solo indicador débil nunca marcará un elemento como sospechoso. Esta herramienta sirve como apoyo para priorizar qué revisar primero, no como un veredicto definitivo.

---

## Requisitos del sistema

* **Sistema operativo:** Linux (probado en Pop!_OS)
* **Bibliotecas:** GTK 4.10 o superior, SQLite 3
* **Herramientas de compilación:** CMake 3.20 o superior y un compilador de C (GCC o Clang)

En distribuciones basadas en **Debian, Ubuntu o Pop!_OS**, instala las dependencias con:

```bash
sudo apt install build-essential cmake pkg-config libgtk-4-dev libsqlite3-dev
```

---

## Compilación, pruebas y ejecución

### 1. Compilar el proyecto
```bash
cmake -S . -B build
cmake --build build
```

### 2. Ejecutar las pruebas unitarias
```bash
ctest --test-dir build --output-on-failure
```
Deberías ver **7 pruebas aprobadas**: análisis de URLs, análisis de correos, motor de riesgo, detección de campañas, lista local, características de dominios y base de datos.

### 3. Iniciar la aplicación
```bash
./build/finovra-phishing-detector
```
Al abrirse, encontrarás cuatro pestañas principales: **Resumen**, **URL Scanner**, **Email Analyzer** y **Método**.

---

## Datos, privacidad y listas de dominios

Toda la información generada se guarda exclusivamente en tu directorio de usuario:

* **Base de datos:** `~/.local/share/finovra-phishing/analisis.db`
* **Lista local (opcional):** `~/.local/share/finovra-phishing/blocklist.txt`

Para eliminar tus registros, utiliza el botón **Borrar historial** dentro de la pestaña *Resumen* (la aplicación solicitará confirmación antes de proceder).

### Importar listas públicas de bloqueo
Puedes alimentar tu lista local utilizando el script incluido en el repositorio:

```bash
bash tools/import_blocklist.sh archivo1.txt archivo2.txt
```

El script admite formato `hosts`, listas de URLs y dominios sueltos. Filtra automáticamente dominios legítimos críticos para evitar falsos positivos y fusiona el resultado con tu lista local. *(Asegúrate de revisar la licencia de cada fuente externa antes de importarla).*

### Datos de demostración
Si deseas probar la interfaz con datos de ejemplo sin alterar tu historial real, consulta el archivo `tools/demo_seed.sql`.

---

## Estructura del proyecto

```text
├── include/   # Cabeceras públicas (análisis, base de datos, lista local, interfaz)
├── src/       # Lógica de análisis, motor de riesgo, base de datos y lista local
├── ui/        # Interfaz gráfica en GTK4 (Resumen, URL Scanner, Email Analyzer y Método)
├── tests/     # Pruebas unitarias configuradas con CTest
└── tools/     # Scripts de importación de listas y datos de demostración
```

---

## Limitaciones actuales

* Las palabras clave analizadas están en español e inglés y funcionan como indicios heurísticos, no como pruebas concluyentes.
* Las cabeceras `SPF`, `DKIM` y `DMARC` se leen directamente del texto del correo; no se realiza validación criptográfica ni consultas DNS en vivo.
* El catálogo interno de marcas suplantadas y acortadores es reducido (aunque puede ampliarse en el código).
* La lista local únicamente actúa sobre los dominios registrados en ella; los dominios nuevos dependen del análisis heurístico de características.
* Por el momento, la lista local de bloqueo solo se evalúa en el **Escáner de URLs** y aún no se aplica a los enlaces extraídos dentro de los correos `.eml`.

---

## Licencia

Este proyecto se distribuye bajo la licencia **MIT**.