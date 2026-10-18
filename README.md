# Agent Credential Broker

Custodio local autocontenido para ejecutar acciones autenticadas **sin entregar API keys o contraseñas al agente**. Bóveda cifrada propia, administración nativa Tk y transporte Unix Linux. No usa gestores de contraseñas, perfiles de navegador ni cuentas instaladas. Núcleo independiente del agente, terminal, proveedor y gestor de orquestación. Los ejemplos e integraciones son opcionales.

**Estado: versión experimental implementada, no auditoría de seguridad independiente.** La separación efectiva requiere un agente con UID distinto, sin acceso al escritorio, archivos o procesos del custodio. Las pruebas del proyecto no modifican usuarios del sistema ni usan credenciales reales. La GUI fue renderizada y revisada en un display virtual privado, con datos ficticios; falta validar el aislamiento del escritorio de producción.

## Implementado

- AES-256-GCM con salt/nonce aleatorios y scrypt; archivo propietario 0600, directorio 0700, escritura atómica, rechazo de enlaces y escritores obsoletos.
- GUI propia para crear/desbloquear/bloquear y guardar credenciales en campos ocultos; nunca muestra/exporta sus valores. La contraseña maestra no entra en argumentos, variables de entorno o stdin.
- Catálogo del custodio: acciones, destino HTTPS exacto, esquema estricto, campos de respuesta permitidos con `outputSchema` estricto y presupuestos. El agente no aporta URL, headers, código o comandos.
- Planes de un uso, TTL 60 s, identidad kernel `SO_PEERCRED`, invalidación de sesión. Las escrituras requieren confirmar en la GUI el método, destino y valores reales; máximo 25 s para responder.
- Solo socket Unix 0660, dos solicitudes concurrentes, frame JSON 16 KiB y recepción 4 s. Producción rechaza UID del propio custodio y UID 0 como agente.
- TLS validado, DNS público fijado, sin redirects/proxies ni reintentos de escrituras; errores constantes y resultados proyectados. Credenciales evidentes y ciertos ecos se bloquean; no se promete DLP universal.
- Concesión confiable por tarea: UID kernel, acciones, recursos, caducidad y cuota persistente. Producción requiere archivo de concesión junto al catálogo; véase [hardening](docs/hardening.md).
- Revocación administrativa y versionado de credenciales invalidan planes/resultados obsoletos. Launcher Bubblewrap y laboratorio de controles, sin despliegue de dos UIDs real.
- Auditoría de metadatos, sin solicitudes, respuestas, aliases o secretos; intentos de escritura persistidos antes de usar la credencial, rotación de dos archivos de aproximadamente 256 KiB cada uno. Bloqueo automático 5 minutos; GUI y servidor revocan planes al bloquear.
- Exportación offline de metadatos para Agent Observer, con esquema estricto e identificadores de evento persistentes. No expone la bóveda ni añade operaciones al transporte del agente.

## Preparar y abrir

Necesita Linux y Python ≥3.12. El núcleo y la auditoría funcionan sin escritorio; Tk solo es necesario para la administración humana por GUI. Usa un intérprete compatible elegido por el operador. No requiere una app, terminal o runtime de proveedor específico.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.lock -r requirements-build.lock
.venv/bin/python -m pip install --no-deps --no-build-isolation .
.venv/bin/python -m credential_broker.cli gui
```

La GUI puede crear una bóveda en un directorio nuevo. **No inicies un servicio con secretos reales hasta desplegar la separación descrita en [operaciones](docs/operations.md).** Por diseño, el agente que comparte el UID del custodio no puede usar el servicio. No se crearon usuarios/grupos, servicios ni configuración de sandbox automáticamente.

El catálogo de [ejemplo](examples/actions.json) contiene endpoints ficticios y alias `demo_key`, ningún secreto. Copiarlo a la ubicación confiable, ajustar sus acciones y permisos 0600 es una tarea del custodio, fuera del entorno del agente.

## API del agente

```json
{"op":"capabilities"}
{"op":"plan","request":{"action":"read_account","input":{}}}
{"op":"execute","request":{"planId":"ID_DEVUELTO_POR_PLAN"}}
```

```sh
printf '%s\n' '{"op":"capabilities"}' | .venv/bin/python -m credential_broker.cli call --socket /ruta/confiable/broker.sock
```

El transporte solo expone `status`, `capabilities`, `plan` y `execute`. No tiene `getSecret`, desbloqueo, exportación o almacenamiento remoto. El test privado de transporte permite la identidad de la fixture mediante constructor Python; **no existe flag CLI, variable de entorno ni parámetro del agente que habilite ese bypass**. El código de producción debe ser inaccesible para el UID del agente.

## Validación

```sh
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m compileall -q credential_broker
.venv/bin/python -m pip check
```

78 pruebas disponibles: 76 de núcleo/transporte aprobadas en la última ejecución y 2 de GUI aprobadas en la QA anterior, omitidas en la ejecución actual porque su display virtual temporal ya no existe. Cubren cifrado/manipulación, permisos/enlaces, replay, TTL, revocación durante aprobación, presupuestos, salida con secretos ficticios, DNS/redirects, Unix real, rechazo por identidad kernel y exportación de auditoría. Las pruebas Unix de éxito inyectan identidad sintética en el constructor: **todavía no prueban un despliegue completo con dos usuarios reales**. No se consultó un proveedor real ni una bóveda existente. La QA visual utilizó Xvfb descargado/extractado únicamente en `/tmp`, sin instalarlo en el sistema; `test_gui.py` se omite salvo habilitación explícita de un display virtual privado.

[Gobierno, aislamiento, checkpoints y benchmarks](docs/hardening.md) · [Seguridad y límites](docs/security.md) · [Operaciones](docs/operations.md) · [Investigación y fuentes oficiales](docs/research.md).
