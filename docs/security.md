# Seguridad de la versión experimental

La garantía buscada es restringida: el agente llama acciones predefinidas sin recibir bytes de la credencial. El custodio y proveedor sí usan el secreto en memoria y por TLS. No se ofrece seguridad absoluta, certificación, resistencia a root ni zeroization garantizada en Python.

## Frontera

Se confía en código/configuración, bibliotecas, SO, GUI y proceso custodio. Se considera hostil al agente y a su entrada; una inyección puede controlar sus solicitudes. La identidad de cliente sale de `SO_PEERCRED`, nunca del JSON. Las acciones públicas no permiten descifrar, leer/exportar, definir URL, authheaders, código o comandos.

AES-256-GCM autentica cabecera y contenido; scrypt n=32768,r=8,p=1 deriva una clave de 32 bytes, salt de 16 bytes y nonce de 12 bytes nuevos. El formato limita tamaño, parámetros y tipos antes de operaciones caras. Esto no convierte una contraseña débil en una fuerte ni evita adivinarla con una copia del archivo. La dependencia PyCA [cryptography](https://cryptography.io/en/latest/) se instala como wheel, fijada a 50.0.2; no se desarrolló criptografía propia.

Se rechazan symlinks/hardlinks y permisos inseguros en la bóveda; escritura atómica y detección de otra instancia evitan sobrescritura obsoleta. Bloquear elimina referencias de Python; copias internas, swap, core dumps y memoria residual quedan fuera de la garantía de borrado. El entorno de producción debe añadir controles del SO y evitar volcados.

## Gobierno de acciones

El catálogo pertenece al custodio. Cada plan liga identidad, acción, entradas exactas, destino y expiración. Es de un uso, se consume antes del acceso remoto y se invalida al bloquear/cambiar sesión. Las escrituras requieren aprobación humana explícita en la GUI. No basta con que otro agente diga que aprobó. Los presupuestos por sesión/credencial limitan abuso, aunque también las lecturas autorizadas pueden extraer datos o tener coste.

La conexión HTTPS fija DNS público, valida TLS, rechaza metadatos/privateIP y redirects; no utiliza proxies de entorno. Respuesta máxima 128 KiB y proyección final 4 KiB de campos escalares explícitos. `outputSchema` es obligatorio para cada acción; strings restringidos a enum/patrón anclado simple y longitud acotada, sin texto libre por defecto. Se bloquean ecos literales, base64 y URL-encoded de la credencial; otras codificaciones, fragmentos, datos sensibles de terceros y canales laterales requieren políticas específicas. La lista de campos permitidos importa más que prometer una redacción universal.

El servidor limita a dos clientes concurrentes, frame 16 KiB, lectura 4 s y una petición por conexión. Un peer no autorizado recibe un error constante. Los códigos de error nunca incorporan excepción, petición o respuesta originales. El deadline HTTPS total incluye DNS, handshake, headers y cuerpo; el transporte aborta al vencerlo. DNS usa dos procesos desechables acotados: timeout mata y recoge el hijo para liberar su slot. El coste de crear un proceso se mide en el benchmark; no hay pool de conexiones ni cache DNS. Un timeout no demuestra cancelación de una acción remota.

## Limitaciones verificables

- Laboratorio con dos identidades kernel distintas en namespace efímero aprobado: SO_PEERCRED real y constructor de producción, sin bypass; UID1 autorizado y UID0/2 falsificados rechazados. No se ha desplegado con usuarios persistentes. Las fixtures Unix ordinarias mantienen la excepción privada de constructor, separada de ese laboratorio; no existe bypass remoto/CLI/env.
- GUI Tk renderizada/revisada en Xvfb temporal y probado crear/desbloquear/guardar/bloquear, contraseña incorrecta, tabulación y aprobación/rechazo/caducidad. El display virtual no prueba los permisos o aislamiento del escritorio de producción.
- Hay un launcher Bubblewrap con entorno limpio y namespaces, probado con canarios ficticios, y un segundo laboratorio pasó con dos UID kernel reales dentro de un namespace efímero, pero no se ha desplegado con usuarios persistentes; no configura usuarios, ACL, cgroups o política del escritorio automáticamente. Otro agente con UID del custodio puede leer archivos/procesos y automatizar su escritorio; por ello ese despliegue es inseguro, aunque la API rechace mismo UID.
- Sin auditoría independiente, mlock, hardware-backed keys, OAuth, MFA, rotación de masterpassword, recuperación, attestation o log inalterable. Hay verificación offline contra un checkpoint separado; no instala ni garantiza un testigo externo. Auditoría de escritura fail closed antes de la red y estado incierto si falla después; lecturas best effort. Almacenamiento acotado, sin payloads para replay.
- Root/kernel/proveedor/custodio comprometidos, software malicioso del propio usuario y efectos ya enviados quedan fuera. El guardado cifrado no sustituye separación de cuentas y sandbox.

Las pruebas usan exclusivamente secretos sintéticos. No se inspeccionaron bóvedas locales, contraseñas de usuario ni credenciales de aplicaciones existentes. [Investigación primaria](research.md) explica precedentes y diferencias.

## Separación de la observabilidad

Agent Observer es un proyecto separado, pero separar repositorios no crea una frontera de seguridad. Ejecutarlo con el UID del custodio y darle código arbitrario permitiría leer su memoria/archivos igual que cualquier otro proceso de ese UID. Para exportar auditoría, un componente confiable proyecta exclusivamente el esquema de metadatos hacia un destino de solo recepción; Observer y los agentes deben correr con identidad inferior, sin acceso a la bóveda, código o proceso custodio. No existe tal despliegue automático en esta versión.

## Dependencias verificadas

El 16 de octubre de 2026, la API pública de PyPI no reportó vulnerabilidades para cryptography 50.0.2, cffi 2.1.1 y pycparser 3.11; `pip check` no encontró incompatibilidades. Esto no prueba ausencia de vulnerabilidades desconocidas ni sustituye una auditoría. Solo se instalaron wheels en el venv local. Herramientas de empaquetado y Xvfb de QA no son dependencias runtime del custodio.

[Demostraciones reproducibles y límites](assurance.md) documenta TLS sintético, carreras, crash/restart, corpus con semilla y las hipótesis de cada experimento. El punto final de autorización de salida está después de auditoría; revocar después no recupera datos ya entregados.
