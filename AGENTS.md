# Agent Credential Broker

Hablar español con el usuario. Código y documentación de seguridad deben distinguir implementación, prueba y garantía no demostrada.

- Nunca inspeccionar bóvedas/cuentas reales para pruebas. Usar TemporaryDirectory y credenciales ficticias.
- No aceptar secretos en CLI, variables de entorno, API del agente, logs o errores. La administración ocurre en GUI humana del custodio.
- El servidor de producción rechaza mismo UID y UID0. Identidad únicamente SO_PEERCRED. No añadir bypass remoto/env/CLI; fixtures pueden inyectar identidad en constructor privado.
- Código, catálogo y venv no deben ser editables por UID del agente. No crear usuarios/grupos/servicios ni modificar SO durante pruebas.
- Conservar modelos de límites: esquemas estrictos, destino fijo, TTL/nonce, aprobación exacta, budgets, salida proyectada. No convertirlo en proxy HTTP o ejecutor de código arbitrario.
- Verificar con `.venv/bin/python -m unittest discover -s tests -v`, compileall y pip check; tests Unix necesitan permiso de sockets locales. Nunca declarar GUI validada si no se renderizó.
- `.venv/`, bóvedas, sockets y logs no se versionan. Dependencias criptográficas de PyCA, sin algoritmos caseros.

- Producción exige TaskGrant confiable y cuotas persistentes; taskId/principal/modelo nunca entran en el protocolo del agente. Preservar consumo ante resultado incierto.
- Auditoría v1 sigue predeterminada; v2 opt-in lleva correlación, secuencia y fechas del host. Checkpoints necesitan referencia independiente, no declarar resistencia a custodio/root.
- Sandbox de laboratorio con canarios no demuestra dos UIDs reales. No degradar a ejecución sin aislamiento.
