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
- Revocación administrativa y versionado de credenciales invalidan planes/resultados obsoletos. Launcher Bubblewrap y laboratorio con dos identidades kernel reales en un namespace efímero; sin despliegue operativo con usuarios persistentes.
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

102 pruebas disponibles: **100 casos aprobados y 2 de GUI omitidos** en las verificaciones de esta versión. Incluyen TLS real con certificados sintéticos, 133 frames y 136 salidas de proveedor con semilla fija, carreras de revocación y procesos que mueren durante persistencia. La revisión corrigió una ventana que podía devolver resultados después de revocar la sesión, incluida otra durante auditoría final. Las [pruebas semánticas](docs/semantic-assurance.md) contrastan 288 trazas con el Broker real y cubren doce mutaciones tipadas; encontraron y corrigieron consumo de cuota de una concesión nueva por planes antiguos y reactivación de planes al reemitir un permiso idéntico.

El [laboratorio de dos UID](docs/assurance.md) pasó con `SO_PEERCRED` real y constructor de producción, sin bypass de identidad: acceso legítimo, rechazo de UID falsificado, archivos/memoria/código privados y canario IPC. Los clientes parten de fresh exec antes de generar la clave ficticia y sin grupos suplementarios. **No equivale a producción con usuarios persistentes ni verifica GUI/X11/Wayland reales.** La QA visual anterior usó Xvfb privado; no se volvió a ejecutar en esta ronda.

El experimento opcional de [Solidity](docs/solidity-assessment.md) tiene 9 pruebas locales aprobadas de bytecode EVM y control del compilador. No integra blockchain al broker, no despliega contratos ni usa wallets/fondos; no hay prueba formal SMT. Ver [matriz de amenazas, invariantes y reproducciones](docs/assurance.md).

[Gobierno, aislamiento, checkpoints y benchmarks](docs/hardening.md) · [Seguridad y límites](docs/security.md) · [Operaciones](docs/operations.md) · [Investigación y fuentes oficiales](docs/research.md).
