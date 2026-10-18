# Credenciales utilizables por agentes sin entregarles el secreto

Investigación de documentación primaria consultada el 16 de octubre de 2026. Este documento propone un diseño; no instala servicios, inspecciona credenciales locales ni demuestra aislamiento del equipo actual. El broker autocontenido es un proyecto independiente de Enlace y de Agent Observer. Los productos mencionados son antecedentes técnicos, no aplicaciones ni servicios requeridos por el diseño.

## Conclusión

Existe un patrón apropiado: un **broker de acciones autenticadas**, ejecutado fuera del entorno del agente, conserva las credenciales y acepta operaciones concretas previamente autorizadas. El agente recibe resultados filtrados, no tokens. Hay precedentes comerciales y abiertos, pero ocultar un token no impide usar indebidamente los permisos de ese token. La autorización por acción y el aislamiento del broker son requisitos independientes.

No se puede sostener «el agente jamás podrá acceder» si comparte UID, archivos, entorno, depurador, privilegios o control de ejecución con el proceso custodio. La garantía razonable debe describir un modelo de amenaza y una frontera técnica verificable; tampoco cubre compromiso del kernel, administrador, proveedor o broker.

## Qué protegen los sistemas existentes

| Sistema | Función efectiva | ¿Evita entregar credenciales al agente? | Límite relevante |
|---|---|---|---|
| Composio / AgentAuth | Custodia OAuth/API y ejecuta herramientas o peticiones autenticadas | Sí, en la ejecución gestionada; el token del proveedor queda en el servicio | La clave de Composio sigue otorgando poder de ejecución; precisa backend confiable y permisos acotados. [Custodia oficial](https://docs.composio.dev/docs/security/token-custody) |
| CyberArk Secretless Broker | Proxy de protocolo que autentica al servicio de destino | Su diseño mantiene el secreto de conexión en el broker | Un cliente autorizado todavía puede abusar del protocolo o datos permitidos. [Funcionamiento oficial](https://docs.secretless.io/Latest/en/Content/Overview/scl_how_it_works.htm) |
| HashiCorp Vault Proxy | Autenticación automática, caché y proxy de la API de Vault | **No por sí solo**: puede devolver secretos autorizados al cliente | Proxy de un almacén de secretos no equivale a ejecutar una operación de negocio sin revelar el secreto. [Vault Proxy](https://developer.hashicorp.com/vault/docs/agent-and-proxy/proxy) |
| OpenBao Proxy | Patrón equivalente de auto-auth y acceso a la API de OpenBao | **No por sí solo** | Auto-auth también puede escribir tokens en sinks configurados. [Proxy](https://openbao.org/docs/agent-and-proxy/proxy/), [Auto-auth](https://openbao.org/docs/agent-and-proxy/autoauth/) |
| SPIFFE / SPIRE | Identidad y atestación de procesos/cargas, certificados de vida corta | **No es un almacén opaco de credenciales** | La Workload API X.509 entrega una clave privada al workload. [Especificación](https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/) |
| KMS / HSM | Operaciones criptográficas con claves protegidas | Puede impedir exportar la clave criptográfica, según producto/configuración | Desencriptar un token y devolverlo al agente sí revela ese token. [Jerarquía KMS](https://docs.aws.amazon.com/kms/latest/cryptographic-details/key-hierarchy.html), [Decrypt](https://docs.aws.amazon.com/kms/latest/cryptographic-details/decrypt-operation.html) |

### Custodia, claves no exportables y acciones son capas distintas

1. **Custodia del secreto:** Vault/OpenBao pueden almacenar y rotar tokens, claves o credenciales dinámicas. Si el agente tiene permiso para leerlos, recibe los bytes aunque el almacenamiento esté cifrado. Vault Proxy puede adjuntar su token auto-auth a peticiones de la API de Vault; eso simplifica acceso, no impone una política de acciones sobre la API final. [API proxy oficial](https://developer.hashicorp.com/vault/docs/agent-and-proxy/proxy/apiproxy)
2. **Clave no exportable:** el HSM puede firmar o descifrar sin exportar su clave principal. Sin embargo, AWS KMS `Decrypt` devuelve el contenido descifrado al solicitante; `GenerateDataKey` puede devolver una clave de datos en claro. Cifrar una API key bajo KMS no la convierte en una API key que pueda usarse sin existir en claro en el ejecutor. [Decrypt](https://docs.aws.amazon.com/kms/latest/cryptographic-details/decrypt-operation.html), [Jerarquía](https://docs.aws.amazon.com/kms/latest/cryptographic-details/key-hierarchy.html)
3. **Broker de acciones:** solamente el broker puede recuperar el token, preparar la petición y hablar con el proveedor. Su API pública expone `listar_objetos` o `crear_borrador`, no `leer_secreto`, `descifrar`, `firmar_bytes_arbitrarios` ni `HTTP_cualquier_URL`. Esta capa es la propuesta del estudio, no una capacidad demostrada de Agent Observer.

Vault Transit y OpenBao Transit también ofrecen servicios criptográficos. Sus endpoints de descifrado no deben exponerse al agente para material que se pretende ocultarle; un permiso criptográfico excesivo puede convertir la integración en un oráculo. [Vault Transit](https://developer.hashicorp.com/vault/docs/secrets/transit), [OpenBao Transit](https://openbao.org/docs/secrets/transit/)

### Qué aporta Composio y qué revisar

AgentAuth gestiona conexión de cuentas, OAuth, renovación y selección de cuenta. El flujo gestionado evita poner tokens de proveedor en el modelo. [AgentAuth](https://composio.dev/developers), [Autenticación](https://docs.composio.dev/docs/authentication)

La documentación distingue credencial del proveedor, clave del proyecto y custodia del despliegue. La clave del proyecto también debe permanecer fuera del agente no confiable. Proxy Execute amplía operaciones más allá de herramientas predefinidas; su restricción de dominio permite ciertos subdominios hermanos, insuficiente como política de destino exacto. Los logs de ejecución guardan payloads por defecto; Zero Data Retention cubre nuevas llamadas admitidas, no todos los logs propios ni datos ya almacenados. Deben revisarse permisos, retención y custodia antes de elegir el servicio. Estas son declaraciones del proveedor, no una auditoría independiente. [Token custody architecture](https://docs.composio.dev/docs/security/token-custody)

### Qué aporta SPIFFE/SPIRE

SPIRE verifica atributos del nodo y proceso para emitir identidades; resulta útil entre un supervisor confiable y un broker remoto. No certifica que una petición concreta del modelo tenga intención legítima. El perfil X.509 de Workload API contiene una clave privada PKCS#8 sin cifrar para la carga autorizada. Entregar esa identidad al agente solo desplaza el tipo de credencial; no elimina su capacidad de autenticarse. Mantener la identidad más privilegiada exclusivamente en el broker. [Conceptos SPIRE](https://spiffe.io/docs/latest/spire-about/spire-concepts/), [Workload API](https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/)

## Modelo de amenaza propuesto

Se asume que una inyección en webs, documentos, repositorios o resultados puede controlar las decisiones del agente. El atacante puede solicitar herramientas arbitrarias dentro de lo expuesto, manipular argumentos, repetir llamadas y fabricar explicaciones. Incluso puede ejecutar código si el agente dispone de shell. No se confía en que otro LLM detecte siempre el ataque. Las inyecciones indirectas son una clase reconocida por OWASP. [OWASP LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)

Objetivos separados: impedir lectura del secreto, impedir acciones no autorizadas, limitar extracción de datos y consumo, y conservar evidencia operativa mínima. Conocer qué acción ocurrió no basta para impedirla. Un observador externo podría recibir eventos de auditoría proyectados en una integración futura; no constituye la frontera de autorización. Este proyecto no depende de Agent Observer.

Fuera de la garantía inicial: administrador/root, kernel comprometido, malware con privilegios del broker, proveedor malicioso, vulnerabilidad del broker, canales laterales de hardware y acciones ya completadas por el proveedor antes de revocar o cancelar. No se anuncia resistencia absoluta frente a ellos.

## Arquitectura recomendada

```text
Agente no confiable ── solicitud de acción ──> Supervisor / API de capacidades
       │                                           │
       │ sin secretos ni salida libre              ├─ política determinista
       │                                           ├─ aprobación humana externa
       │                                           └─ broker aislado ──> proveedor permitido
       └<── resultado proyectado <── filtro de salida <──┘
                                          │
                              Auditoría propia: solo metadatos
```

El supervisor emite un identificador opaco que referencia un permiso guardado del lado confiable. El permiso liga identidad real de sesión, cuenta, adaptador y versión, acción, recursos permitidos, esquema de entrada, destinos y caducidad. Nunca se acepta un `user_id`, una cuenta, un token o un recibo aportado por el modelo como prueba de autoridad.

### Política dura por petición

- **Destino:** el host define origen, método y rutas autorizados. Validación de todos los DNS, conexión a dirección validada, TLS, bloqueo de metadatos, ausencia de redirects y de proxies controlados por el agente. La salida de red del entorno del agente queda denegada salvo los canales explícitos; un filtro solo dentro de una función no contiene un shell con red libre.
- **Esquema y campos:** operaciones con JSON Schema estricto y reglas por recurso, destinatario, repo, archivo y campo. El broker construye URL y headers. No acepta headers de auth, comandos, SQL, plantillas ejecutables o URLs arbitrarias. Las políticas se aplican a lecturas y escrituras: leer datos privados también requiere autorización.
- **Permiso concreto:** para mutaciones sensibles, aprobación humana fuera del contexto del modelo sobre destinatarios, valores y efecto reales. Hash de la petición normalizada, versión de política, nonce de un solo uso y TTL breve; consumir de forma atómica antes de actuar. Un «sí» generado por el modelo no cuenta. Invalidar al cambiar sesión, cuenta o política.
- **Repetición y resultado incierto:** límite por acción/cuenta/sesión y presupuesto de solicitudes, dinero y bytes. Idempotency key del proveedor cuando exista. Tras timeout de una escritura, registrar resultado incierto y consultar estado autorizado; no repetir ciegamente. Un nonce local evita reutilizar el permiso, no garantiza exactamente una ejecución remota tras un fallo distribuido.
- **Salida:** proyectar solo campos permitidos, limitar tamaño/paginación y bloquear headers/cookies/tokens y mensajes de depuración. DLP heurística como defensa secundaria. Una lista de campos permitidos y límites de datos ofrece una política más auditable que prometer redacción universal; el servidor puede devolver el secreto indirectamente o codificado si se autoriza una superficie demasiado amplia.
- **Auditoría:** ID aleatorio, identidad pseudonimizada, acción, versión de política, decisión, clase de error, duración y coste. Sin body, headers, query, tokens ni respuesta completa. Los hashes de valores de baja entropía pueden revelar información por adivinación; evitar guardarlos o usar HMAC con clave de auditoría separada cuando sean necesarios. Acceso y retención restringidos; cualquier consumidor futuro recibe solo esa proyección. Sin respuestas HTTP crudas, excepciones con valores ni volcados de memoria.

Las reglas anteriores son propuesta de diseño derivada del modelo de amenaza; no se presentan como funciones disponibles automáticamente en los productos comparados.

## Aislamiento mínimo defendible en Linux

Separar broker y agente en identidades del sistema distintas, con archivos y sockets de permisos restrictivos. No exportar secretos al entorno del agente, argumentos de proceso, archivos temporales compartidos ni logs. No montar HOME completo, credenciales, sockets de Docker, SSH/GPG, D-Bus de sesión o perfiles de navegador en el sandbox. El canal de autorización no debe permitir editar la configuración ni el código del broker.

Añadir namespaces de montaje, PID, IPC y red, capabilities eliminadas, seccomp y límites de recursos; broker fuera del sandbox y egress exclusivamente a proveedores configurados. Bubblewrap permite construir esa frontera, pero su protección depende de los argumentos y política del lanzador. Un contenedor con mounts amplios o sockets privilegiados no resuelve la separación. [Seguridad de Bubblewrap](https://github.com/containers/bubblewrap/blob/main/README.md)

Yama y `PR_SET_DUMPABLE` reducen ciertas vías de inspección de procesos; su eficacia depende de configuración y privilegios. No reemplazan identidades distintas, protección de archivos y aislamiento: un agente con el mismo UID y permisos amplios puede encontrar otras vías de acceso. La documentación del kernel detalla cuándo un proceso puede adjuntarse a otro. [Yama](https://docs.kernel.org/admin-guide/LSM/Yama.html)

Para secretos de impacto muy alto, evaluar broker en otra VM/máquina o servicio administrado con identidad propia; HSM/KMS para claves que el protocolo permita usar sin exportar. Un HSM no obliga a una API bearer de terceros a aceptar firmas en lugar de su token. En un esquema bearer, el token normalmente existe en memoria del ejecutor y llega al proveedor por TLS; la meta es excluir al agente de esa frontera, no afirmar que nadie lo ve.

## Entrada humana en una bóveda local: flujo solicitado

El usuario puede abrir la aplicación local por sí mismo, o pedir al agente que solicite su apertura mediante un lanzador fijo del supervisor. **Solo la persona introduce la API key o contraseña, fuera del chat y de la terminal del agente.** No se solicita pegarla en mensajes, parámetros de herramientas, archivos compartidos ni variables del proceso del agente.

Flujo propuesto, todavía no implementado:

1. El agente solicita conectar una cuenta mediante una operación tipada que solo contiene proveedor y propósito. El supervisor valida esa solicitud y abre una UI nativa confiable.
2. El supervisor pone la sesión en modo de entrada sensible y retira las capacidades de captura, screenshots, OCR, DOM/accesibilidad, clipboard, logging de teclas y automatización de esa ventana. El proceso del agente no recibe permisos del sistema para recuperarlas por otra vía. Ocultar caracteres con puntos no constituye esta frontera.
3. La persona desbloquea la bóveda y escribe o selecciona el secreto. Cuando el producto/plataforma lo soporte, se exige presencia del usuario mediante diálogo del sistema, biometría o dispositivo físico; esto autentica a la persona, no demuestra que el modelo tenga una intención legítima. Nunca se habilita aprobación automática mediante clics del agente.
4. La UI propia entrega el secreto únicamente al custodio o ejecutor confiable mediante un canal IPC propio autenticado y acotado, fuera del proceso del agente. El agente recibe un identificador aleatorio opaco y estado, por ejemplo `{ "credentialRef": "cred_random_identifier", "status": "available" }`. No recibe previews, prefijos, sufijos, longitud ni hashes del secreto.
5. El broker liga internamente esa referencia a cuenta, identidad de sesión, acciones, destino y caducidad. **Conocer el alias no concede autoridad:** el broker también verifica identidad y política. El alias no es un token bearer de acceso general ni una referencia que permita `getSecret`.
6. Se cierra la UI sensible antes de restaurar capacidades ordinarias. No se generan capturas de comprobación de la bóveda ni se incorpora al historial el estado visual de entrada. Revocar la referencia o bloquear la bóveda impide futuros usos; no revierte acciones ya completadas.

Pausar voluntariamente las herramientas mientras el mismo agente conserva shell, pantalla o archivos del custodio solo ofrece disciplina operativa. Para la propiedad fuerte solicitada, la retirada de capacidades debe imponerla un supervisor externo y los permisos del sistema. La UI de aprobación y la configuración de esa política deben quedar fuera del alcance del agente.

### Antecedentes de UI y firma; no son dependencias del proyecto

| Opción | Encaje y límite |
|---|---|
| Bitwarden Desktop | Ejemplo de UI para almacenar y editar credenciales con entrada humana. No es por sí sola un broker de acciones. La CLI `bw unlock` genera una clave de sesión que permite operaciones sobre datos de la bóveda: entregar esa sesión o permitir `bw get` al agente incumple el objetivo. [Desktop](https://bitwarden.com/help/getting-started-desktop/), [CLI](https://bitwarden.com/en-gb/help/cli/) |
| KeePassXC | Bóveda local y opciones de hardware. Autofill introduce credenciales en la página; un navegador controlado por el agente puede observarlas. Su integración SSH carga claves en un agente OpenSSH compatible; KeePassXC no implementa ese agente. La protección de screenshot documentada para Windows/macOS no permite asumir equivalente en Linux. [Guía oficial](https://keepassxc.org/docs/KeePassXC_UserGuide), [Integración de navegador](https://keepassxc.org/docs/KeePassXC_GettingStarted) |
| 1Password SSH Agent | Precedente específico de operaciones con una clave sin devolverla al cliente: la app realiza la firma y muestra autorizaciones, con opciones biométricas según plataforma. No convierte API keys arbitrarias en claves criptográficas no exportables ni limita por sí solo las operaciones posteriores del servidor SSH. [Agente oficial](https://www.1password.dev/ssh/agent), [Modelo de seguridad](https://www.1password.dev/ssh/agent/security) |

Para SSH ya existe el patrón de delegar autenticación sin entregar la clave privada. OpenSSH añade confirmación, vida máxima y restricciones de destinos cuando se configuran; por defecto las claves añadidas no están restringidas a destinos. El socket de un agente SSH concede capacidad de uso aunque no revele el material, así que no debe montarse entero en el entorno no confiable. Una conexión SSH autorizada tampoco restringe automáticamente comandos o repositorios remotos: aplicar restricciones también en el broker y servidor. [ssh-add oficial](https://man.openbsd.org/ssh-add), [ssh-agent oficial](https://man.openbsd.org/ssh-agent.1)

El diseño solicitado no reutiliza Bitwarden, KeePassXC, 1Password, Seahorse, Zenity, gestores del escritorio ni servicios comerciales. Los ejemplos anteriores sirven para estudiar límites de UI, custodia y delegación; no se detecta ni configura su instalación. La UI, la bóveda, la política y el ejecutor pertenecerían al propio proyecto, con dependencias de biblioteca declaradas y sin implementar primitivas criptográficas caseras.

## Recorte viable y comprobación antes de usar cuentas

Empezar con un broker de fixture sin credenciales reales y dos operaciones tipadas: lectura de objetos sintéticos y escritura de borrador sintético. Probar agente deliberadamente hostil: `leer_token`, headers adicionales, cuenta ajena, URL maliciosa, DNS mixto, redirect, replay, dos consumos concurrentes, caducidad, cambio de sesión durante aprobación, respuestas con token simulado, logging accidental, presupuestos y fallo de red tras escritura.

Demostrar por separado que el agente no puede leer archivos/procesos del broker ni contactar destinos por fuera del canal. Una prueba unitaria de redacción no demuestra aislamiento operativo. Solo después de revisar ese resultado diseñar la custodia propia: formato cifrado, derivación de claves, desbloqueo humano, recuperación y rotación, apoyados en bibliotecas criptográficas estándar y una revisión específica de sus versiones. Vault, Composio, Secretless, SPIRE y KMS no se despliegan ni se convierten en dependencias del proyecto. La implementación y su auditoría quedan pendientes.

Estado de este trabajo: investigación documental, sin pruebas de productos, sin alta de cuentas, sin instalación de custodios y sin lectura ni uso de secretos del dispositivo.

## Decisión de alcance: autocontenido y todavía sin implementar

El proyecto debe incluir su propia UI sensible, almacén cifrado y API de acciones, junto con un supervisor que el agente no pueda modificar. Autocontenido no significa independiente del kernel o libre de bibliotecas: significa que no requiere otro gestor de contraseñas, aplicación de escritorio, agente proveedor ni servicio comercial instalado. Las dependencias de código se declararían, fijarían y revisarían como parte del artefacto. No se ha escogido aún una biblioteca, formato de bóveda, KDF, política de recuperación o plataforma de aislamiento definitiva.

La experiencia propuesta conserva entrada exclusivamente humana y alias opacos, acciones tipadas, autorización externa, TTL, nonce, presupuestos, allowlists de destino y proyección de salida. Ningún endpoint del agente devuelve secretos ni respuestas crudas del proveedor. Esta es una intención de diseño, no una propiedad ya demostrada.

Inspiración declarada: el patrón Secretless y los brokers de autenticación/acciones explicados en las fuentes; separación de identidad y autorización de SPIFFE; y límites de custodia de Vault/KMS. Para observabilidad, [OpenTelemetry](https://opentelemetry.io/docs/concepts/signals/traces/) y [Langfuse](https://langfuse.com/docs/observability/overview) son referencias conceptuales de eventos y trazas, no componentes integrados. El logger de Agent Observer es JSONL propio, no una integración OTel/Langfuse ni parte de esta bóveda. El broker todavía no tiene logger implementado. No se ha copiado ni auditado una implementación criptográfica externa para construir este proyecto.
