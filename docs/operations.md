# Operar el custodio

Este documento describe una preparación que todavía no se ha aplicado a este computador. No hay usuarios, grupos o servicios creados por el proyecto.

## Separación obligatoria

1. El custodio ejecuta la GUI en su escritorio confiable. El agente corre bajo otro UID no privilegiado; no puede editar el código, venv, catálogo o bóveda del custodio. No debe tener sudo, capabilities de inspección, acceso a ptrace ni grupos amplios.
2. Un administrador configura un grupo dedicado compartido únicamente para IPC y un directorio de socket propiedad del custodio, sin escritura para grupo u otros. Ejemplo de permisos: directorio 0750, grupo dedicado; socket 0660. El agente puede atravesar el directorio y conectar al socket, pero no sustituirlo. El custodio debe pertenecer al GID seleccionado en la GUI.
3. La bóveda permanece en **otro directorio 0700** del custodio, fuera del acceso del agente. No colocar el socket dentro de ese directorio en un despliegue entre UIDs: sus permisos impedirían conectar. El valor inicial de la GUI es una ruta de preparación, que debe cambiarse por el directorio IPC configurado antes de servir.
4. El sandbox del agente no recibe HOME del custodio, DISPLAY, WAYLAND_DISPLAY, XAUTHORITY, bus D-Bus de sesión, sockets de Docker/SSH/GPG, archivos de configuración ni acceso a su proceso. Deshabilitar capturas, accesibilidad y automatización del escritorio desde el agente, además de shell que pudiera recuperarlos. Los puntos del campo de contraseña no hacen esto por sí solos.
5. El agente tampoco puede editar el paquete o usar el test privado de constructor para cambiar identidad. No existe un interruptor remoto que relaje estas restricciones.

Para mayor aislamiento, ejecutar el custodio en otra máquina o VM confiable con un canal limitado; el transporte de esta versión es solo Unix local. No habilitar red/TCP improvisando un proxy: requiere un nuevo modelo de identidad y revisión.

## Entrada humana

Ejecutar `.venv/bin/python -m credential_broker.cli gui` como custodio. Crear una bóveda nueva o desbloquearla escribiendo la contraseña maestra; mínimo 12 bytes UTF-8. Guardar el secreto con un alias aprobado. La interfaz limpia los campos después de usarlos y no incluye copiar/exportar. Se admite entrada manual o pegar desde una fuente humana confiable; el broker no lee el portapapeles.

Preparar fuera del agente un catálogo JSON propio 0600. `examples/actions.json` es ilustrativo y no conecta servicios reales. Cada acción fija método, URL HTTPS443, alias, esquema y campos de respuesta. Cada acción exige `outputSchema` estricto: tipos, campos requeridos, límites; los strings necesitan enum o patrón anclado simple y longitud máxima. Preferir estados/identificadores acotados a texto libre. Los únicos valores variables de URL permitidos son placeholders de query codificados; rutas y hosts permanecen fijos. `auth` es `bearer` o `basic`: en Basic la credencial guardada es `usuario:contraseña`.

Guardar credenciales está bloqueado mientras el servicio está activo: para sustituir una, bloquear/detener, desbloquear, guardar y reiniciar. Esto invalida los planes preparados con la identidad anterior. Una integración Python propia debe conservar esa misma regla; no modificar entradas del objeto Vault mientras exista un ActionBroker activo.

Especificar UID del agente, GID dedicado, ruta de socket y catálogo en la GUI. Iniciar servicio. El agente pide capacidades, prepara un plan y ejecuta su identificador. La GUI muestra el plan real antes de una escritura; la persona autoriza una vez o rechaza. Sin respuesta antes de 25 s, se rechaza. Los planes caducan en 60 s y no pueden repetirse, incluso tras fallos.

## Bloqueo, parada y recuperación

Bloquear y detener revoca planes y cierra la bóveda; cerrar la ventana hace lo mismo. GUI y servidor bloquean tras cinco minutos de inactividad. Una petición HTTPS en curso puede haber llegado al proveedor antes de bloquear; no se deshace una operación ya emitida. Tras timeout de escritura, comprobar el estado por una acción de lectura autorizada: no reintentar a ciegas.

La versión no tiene recuperación de contraseña, rotación automática, OAuth, autenticación de hardware ni revocación de una credencial individual desde la GUI. Bloquear el servicio impide usos posteriores. Para editar/eliminar una entrada se precisa una próxima función administrativa o una migración revisada; no usar acceso a los archivos desde el agente.

Las copias de seguridad deben copiar únicamente la bóveda cifrada, con permisos 0600 y contraseña conservada por una vía humana independiente. No versionar archivos de bóveda, catálogos con datos personales o logs. El formato v1 contiene parámetros criptográficos fijos validados antes de derivar claves.

## Auditoría y Observer

`audit.jsonl` contiene solamente identificador aleatorio de evento, tipo `execute|intent|outcome`, hash truncado del ID de acción, estado `intent|ok|denied|uncertain` y duración acotada. No incluye UID, alias, valores, cuerpos, URLs ni mensajes del proveedor. Rota a `audit.previous.jsonl` al alcanzar 256 KiB; el archivo nuevo puede exceder el umbral en una línea. Antes de una escritura se exige persistir el intento con `fsync` de archivo y directorio, incluida su creación/rotación: ante fallo se devuelve `AUDIT_UNAVAILABLE` sin acceder a la credencial ni a la red. Si falla el registro posterior a enviar la escritura, se devuelve `OUTCOME_UNCERTAIN`, sin respuesta ni reintento. La auditoría de lecturas es best effort.

La bóveda no depende de Observer. Exportar estos metadatos hacia Observer es un paso separado del custodio, nunca darle acceso al directorio de la bóveda. No leerlo desde el UID del agente. Los hashes de IDs facilitan correlación pero no equivalen a anonimato o auditoría inalterable.

El custodio puede ejecutar lo siguiente en su entorno confiable, fuera del agente:

```sh
umask 077
.venv/bin/agent-credential-broker audit-export --directory /ruta/privada/custodio > /ruta/intercambio/broker-audit.jsonl
```

El destino de intercambio debe prepararse con permisos que permitan a Observer leer solamente ese archivo exportado. El comando no configura permisos ni grupos automáticamente. Nunca compartir el directorio privado del custodio.

El exportador abre únicamente `audit.previous.jsonl` y `audit.jsonl`, sin enlaces ni ancestros symlink; verifica propietario, permisos 0600, un enlace, tipo regular y tamaño máximo 262656 bytes por archivo. Proyecta JSONL exacto: `schemaVersion:1`, `source:"agent-credential-broker"`, `eventId`, `event`, `actionIdHash`, `status`, `durationMs`. Valida todo antes de emitir eventos; ante error produce un código fijo y exit 1, que no debe importarse. El transporte del agente no tiene esta operación.

Los nuevos `eventId` permanecen iguales al copiar y rotar, para deduplicación de importaciones. Registros antiguos sin identificador usan un hash de dispositivo, inode, posición y bytes: estable al rotar el mismo archivo, pero no garantizado al copiarlo. No hay fecha original de ejecución; Observer debe distinguir su hora de importación. IDs y hashes no proporcionan integridad criptográfica contra el custodio o root. La ventana de dos archivos no conserva historial indefinido.

Integración opcional con Agent Observer, desde su checkout y bajo su identidad separada:

```sh
node /ruta/agent-observer/src/cli.mjs import-broker-audit --file /ruta/intercambio/broker-audit.jsonl --database /ruta/observer/events.sqlite
node /ruta/agent-observer/src/cli.mjs review --source broker --database /ruta/observer/events.sqlite
```

Se verificó el recorrido completo con tres eventos sintéticos: tres importados, cero duplicados al repetir, dos ejecuciones y una denegada. No se abrió ninguna bóveda real. Importar no demuestra aislamiento entre UIDs ni convierte una auditoría local en prueba inalterable.
