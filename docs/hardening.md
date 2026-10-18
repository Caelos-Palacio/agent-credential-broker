# Gobierno, aislamiento y verificación

## Autoridad por tarea

El servicio de producción exige `TaskGrant` y `QuotaStore`; la excepción de identidad de las fixtures no se expone en CLI ni API. La GUI lee un segundo archivo confiable: **la ruta del catálogo seguida de `.grant.json`**, propietario custodio, 0600 y sin enlaces. Ejemplo deshabilitado: [actions.json.grant.json](../examples/actions.json.grant.json). El custodio configura `expiresAt` como Unix UTC futuro, un `taskId` administrativo, `maxUses` y acciones. Cada acción contiene restricciones de igualdad por campo de entrada, por ejemplo `{"read_document":{"documentId":["documento-aprobado"]}}`. Un objeto vacío permite todos los valores válidos del esquema de esa acción; no lo usar para recursos que deban limitarse.

La identidad sigue siendo UID de kernel; el agente no aporta taskId/modelo/principal. El plan fija concesión, entradas y versión de credencial, y vuelve a comprobarlos antes/después de usarla. Los agentes que comparten UID y socket comparten la concesión: para distinguir trabajadores hacen falta identidades o canales de un supervisor confiable, no etiquetas autodeclaradas. El permiso local tampoco reduce los privilegios de la clave en el proveedor: el custodio debe crear claves de alcance mínimo allí.

`quotas.json` almacena únicamente hashes y contadores/horas, dentro del directorio 0700 del custodio. `flock`, reemplazo atómico y `fsync` de archivo/directorio serializan intentos concurrentes y mantienen cuotas tras reiniciar. Se consume presupuesto antes de acceder a la credencial y no se devuelve ante rechazo posterior, fallo o resultado incierto. Se conservan como máximo 128 concesiones, 64 hashes de credenciales y 4096 marcas horarias activas; almacenamiento lleno o corrupto deniega. No borrar el ledger para liberar espacio sin una revisión administrativa: eso reiniciaría presupuestos. Reemitir una concesión modificada crea un presupuesto de tarea nuevo, pero conserva el límite horario de la credencial.

## Revocación

La API Python confiable `broker.revoke_credential(alias)` invalida planes y elimina la entrada cifrada. No es una operación del agente. `Vault.put/remove` incrementan la versión local: una sustitución directa invalida planes anteriores y el resultado de callbacks que estaban usando la versión anterior. La GUI mantiene su regla de detener antes de guardar.

No se ha añadido revocación individual a la GUI, rotación de contraseña maestra, recuperación, credenciales temporales del proveedor ni revocación remota. Una petición enviada puede haber producido efectos; descartar su resultado no los deshace. No se promete aborto remoto ni borrado completo de bytes en memoria Python.

## Lanzador del agente y laboratorio

`python -m credential_broker.isolation --workspace WORK --socket SOCKET -- COMANDO` se ejecuta bajo el UID del agente, distinto del custodio. Rechaza socket del mismo UID o root y ausencia de Bubblewrap; no degrada a ejecutar sin sandbox. Expone `/usr`, bibliotecas, dispositivos mínimos, `/proc` privado, `/tmp` propio y workspace; monta únicamente el socket como `/run/broker.sock`. Limpia el entorno y aísla namespaces, red, sesión y acceso a buses/escritorio. Deshabilita core dumps y limita descriptores. No monta HOME, D-Bus, X11/Wayland ni sockets auxiliares del custodio.

Esto requiere instalación/configuración confiable: el agente no debe poder editar lanzador, código, catálogo o dependencias, escapar por otro ejecutor ni recibir accesos alternativos. No configura usuarios/grupos/cgroups/AppArmor automáticamente. Tampoco aporta una cuota de RAM/CPU/PIDs: el administrador debe añadirla al entorno del agente. Deben verificarse ACL, montaje del socket entre UIDs, ptrace y políticas de escritorio en el despliegue real.

Prueba reproducible con canarios ficticios: `.venv/bin/python scripts/isolation-lab.py`. En este equipo devolvió PASS para archivo externo inaccesible, red denegada y ausencia de entorno de escritorio/bus de sesión. El primer intento dentro del sandbox exterior devolvió 77; la ejecución de laboratorio autorizada fuera de esa restricción pasó. **`twoUidVerified:false`: no se crearon usuarios ni se demostró el despliegue completo entre dos UIDs reales.** Ese primer laboratorio mantiene su informe acotado. El laboratorio nuevo `scripts/two-uid-lab.py` sí pasó con identidades kernel distintas y constructor de producción, sin excepción de identidad, fresh exec previo a generar claves y grupos suplementarios vacíos. Su `namespaceTwoUidVerified:true` no significa despliegue de producción ni prueba de GUI real. En el laboratorio nuevo, 77 indica entorno no disponible y 1 un control fallido, nunca evidencia aprobada. Véase [assurance](assurance.md).

## Auditoría v2 y checkpoint

`audit-export --schema-version 2` añade `executionId`, `sequence`, `producerId`, `occurredAtUTC` y `observedAtUTC` al DTO v1. El identificador de ejecución enlaza intento/resultado, el contador y origen sobreviven reinicio mediante `audit-state.json` privado. La hora de evento y escritura son lecturas del reloj del host, no tiempo certificado. La secuencia puede tener huecos si un intento de persistencia falla; no se recicla. Exportar v2 con registros antiguos sin esos campos falla para no inventarlos. El formato v1 sigue siendo predeterminado y no añade fechas retroactivas.

Comandos exclusivos del entorno confiable del custodio, sin endpoint para agentes:

```sh
umask 077
.venv/bin/agent-credential-broker audit-export --directory DIR --schema-version 2 > EXPORT.jsonl
.venv/bin/agent-credential-broker audit-checkpoint --file EXPORT.jsonl > CHECKPOINT.json
.venv/bin/agent-credential-broker audit-verify --file EXPORT.jsonl --checkpoint CHECKPOINT.json
```

La referencia debe transferirse y conservarse fuera del control del custodio/agente, por una vía humana confiable. Guardarla junto a la exportación bajo el mismo UID no proporciona esa frontera. La herramienta no instala un testigo independiente ni autentica automáticamente el origen de la referencia.

Especificación `sha256-chain-v1`: digest inicial de 32 bytes cero; para cada evento JSON validado, canonicalizar con claves ordenadas, separadores `,`/`:` y ASCII escapado; digest siguiente = SHA256(digest anterior + longitud de 8 bytes big endian + bytes canónicos). El checkpoint fija algoritmo, cantidad y digest final. Detecta cambios semánticos, orden o truncado frente a una referencia intacta; no considera cambio semántico el espacio o el orden de claves JSON. Lector acotado 2 MiB, archivos regulares, sin enlaces, sin escritura de grupo/otros; todos los DTO se validan. No usa firmas ni nuevas claves. El custodio/root que controla también la referencia puede regenerarla; no es una auditoría inalterable ni cubre eventos nunca registrados.

## Dependencias y rendimiento

`requirements.lock` fija hashes de wheels oficiales de las tres dependencias runtime existentes, sin actualizar versiones. Se verificó descarga con `pip --isolated download --require-hashes --no-deps -r requirements.lock` en Python 3.12 x86_64. El archivo `requirements-build.lock` fija también setuptools, wheel y packaging con hashes de wheels oficiales. Instalar con `pip install --require-hashes -r requirements.lock -r requirements-build.lock`; empaquetar el proyecto local con `pip install --no-deps --no-build-isolation .`, usando las herramientas de build del entorno confiable. Los locks fijan dependencias Python de runtime y build; no fijan intérprete, sistema o compiladores, por lo que no se declara compilación hermética. PyPI no reportó vulnerabilidades para esas versiones el 17-10-2026; no demuestra su ausencia.

DNS usa dos procesos desechables máximos; timeout mata y recoge el proceso, recuperando su slot incluso si libc se atasca. No hereda entorno ni descriptores del custodio. Cada dispatch vuelve a validar todas las IP y fija una para TLS; no hay cache DNS ni pool de conexiones. El contexto TLS se comparte manteniendo validación de certificado/hostname; cambios de CA requieren reiniciar el custodio.

Microbenchmark local reproducible: `.venv/bin/python scripts/benchmark.py`, datos ficticios, sin proveedor. Medianas de esta ejecución: crear contexto TLS 27,38 ms frente a reutilizar 0,00010 ms; resolver `localhost` en proceso 37,81 ms; evento de auditoría durable 14,35 ms; intento de cuota durable 9,43 ms. RSS máximo 34 MiB. El proceso DNS añade coste a cambio de disponibilidad; estas cifras no demuestran mejora global de peticiones HTTPS. Conservar scrypt, pinning, durabilidad y validación, sin rebajarlos para mejorar un benchmark.

## Intérprete y actualización

Elige una instalación compatible de Python ≥3.12; Tk solo es necesario para la GUI. No dependas de un alias del sistema que pueda cambiar de versión tras actualizar. Para reconstruir, detener el broker, preservar o renombrar **solo `.venv`**, crear otro venv con el intérprete elegido, instalar `requirements.lock` y `requirements-build.lock` con `--require-hashes` y el proyecto local con `--no-deps --no-build-isolation`. Mantener bóveda, concesiones, cuotas y auditoría en su directorio privado intacto. Si cambia la ABI de Python, reinstalar los wheels apropiados del lock: no copiar extensiones compiladas entre versiones.

La biblioteca y el protocolo JSON no dependen de Pi, Warp, Codex, un modelo concreto ni Agent Observer. El aislamiento actual usa interfaces del kernel Linux y Bubblewrap; no se afirma soporte de seguridad equivalente en macOS o Windows. `examples/` contiene exclusivamente destinos y credenciales ficticios; adaptar un proveedor no requiere modificar el transporte o conceder URLs arbitrarias al agente.

## Revocación durante entrega

La política vuelve a comprobar generación, concesión, versión de credencial y vigencia del permiso después de red y de auditoría final. El retorno bajo el lock es el punto de autorización; no se mantiene el mutex durante I/O. Un resultado revocado no se entrega; una escritura enviada queda incierta y no se reintenta. Si ya se auditó `ok`, se añade una corrección `denied/uncertain` con el mismo executionId. Consumidores v2 deben interpretar el mayor sequence de cada productor/ejecución, conservando los eventos crudos.
