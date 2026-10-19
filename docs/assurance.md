# Demostraciones de seguridad reproducibles

Este paquete conecta un modelo de amenazas con invariantes y experimentos. Los resultados muestran comportamientos concretos de esta versión, no una prueba formal, certificación ni ausencia de vulnerabilidades. Las pruebas no leen cuentas, bóvedas o datos reales. Los certificados, contraseñas, proveedores y canarios son sintéticos y temporales.

## Modelo de amenazas

Se considera hostil al cliente agente, sus instrucciones y entrada, y los bytes de respuesta del proveedor. El custodio, catálogo, concesión, bibliotecas, reloj y kernel son confiables. Un fallo de red, proceso o almacenamiento puede ocurrir entre validar, reservar cuota, registrar, enviar y entregar una respuesta. El atacante no debe convertir un mensaje, un alias o un checkpoint en autoridad ni obtener una credencial por medio de salidas o errores.

El laboratorio usa identidades kernel distintas dentro de un namespace de usuario efímero y rangos subordinados ya disponibles. No crea usuarios del host. Esto comprueba una frontera más fuerte que inyectar una identidad en el constructor de tests, pero no equivale a un despliegue de producción, una VM, aislamiento contra root/kernel, ni una evaluación de acceso al escritorio real.

## Matriz de evidencia

| Invariante | Demostración | Alcance y límite |
|---|---|---|
| Un cambio de significado no se autoriza por conservar un ID | [Pruebas semánticas](semantic-assurance.md): doce mutaciones tipadas, control autorizado y modelo separado contrastado con 288 trazas del Broker real | Dominio sintético finito; no comprensión de lenguaje natural ni verificación formal. |
| Un plan antiguo no cobra cuota de una concesión nueva ni resucita al reemitirla | Mismas pruebas: reemplazo durante aprobación/reserva y reemisión idéntica | Binding a instancia en memoria; identificador durable conserva el presupuesto. |
| Un nonce produce como máximo un dispatch | `test_assurance_races`: redención concurrente del mismo plan | Dos threads sincronizados; no idempotencia de nuevas peticiones autorizadas. |
| Revocación antes del secreto impide uso y red | `test_assurance_races`: barrera en auditoría previa, revocar concesión | `vault.use=0`, `dispatch=0`, plan consumido. |
| Autoridad vigente hasta entregar el resultado | `test_assurance_races`: invalidación durante upstream y en auditoría final; reemplazo/revocación de concesión y rotación de credencial | Ocho subcasos en auditoría final, lectura denegada y escritura incierta, sin resultado ni replay. |
| Cuota persistente nunca excede el permiso entre procesos | `test_assurance_crash`: ocho procesos, presupuesto de tres | Tres reservas exactas; flock y persistencia reales. |
| Un intento consumido no reaparece tras morir el proceso | `test_assurance_crash`: `os._exit` tras commit y tras rename | No demuestra pérdida eléctrica ni durabilidad de todos los sistemas de archivos. |
| Fallo de persistencia impide publicar una reserva | `test_assurance_crash`: fallo inyectado en fsync | No deja temporales ni ledger publicado; pruebas de política existentes verifican bloqueo antes del secreto/red. |
| Secuencia y origen sobreviven reinicio | `test_assurance_crash`: evento durable y salida abrupta | Solo evento ya persistido; no prueba recuperación de escrituras desgarradas o pérdida eléctrica. |
| Auditoría modificada se detecta contra referencia intacta | `test_audit_checkpoint`: alterar/reordenar/truncar | No autentica una referencia controlada por el propio atacante ni detecta eventos nunca registrados. |
| Frames y salidas hostiles no se vuelven capacidades | `test_assurance_fuzz`: semilla `0xA551`, 133 frames y 136 valores de proveedor | Corpus determinista, no exploración exhaustiva ni DLP universal; no hay dependencias nuevas. |
| La salida contiene únicamente campos/valores autorizados | `test_assurance_tls`: Unix→bóveda cifrada→concesión/cuota→TLS→proyección/auditoría | Credencial ficticia solo llega al proveedor ficticio; transporte Unix de esta prueba usa la excepción privada de fixture, cubierta separadamente por el laboratorio. |
| TLS verifica hostname y CA antes de enviar HTTP autenticado | `test_assurance_tls`: certificados reales generados, confianza incorrecta y hostname incorrecto | Servidor loopback; no evaluación de certificados de un proveedor real. |
| El destino validado se fija conservando Host y SNI | `test_assurance_tls`: IP validada sintética, conexión real, Host/SNI capturados | Se sustituye el resolver por una respuesta pública fija y se enruta IP:443 a un puerto loopback solo en tests. No modifica `_resolve` ni añade excepciones de producción. |
| Redirects no propagan autenticación y límites abortan | `test_assurance_tls`: redirect, cuerpos excesivos y stalls reales de headers/cuerpo | Un dispatch; límite y timer real. No se afirma cancelar efectos ya aceptados por un servidor. |
| IP privada sigue denegada por defecto | `test_assurance_tls`: respuesta DNS privada rechazada antes de conectar | El check de producción se ejecuta sin override; otras pruebas cubren DNS mixto y procesos resolver bloqueados. |
| Solo el UID real autorizado usa el broker | `scripts/two-uid-lab.py`: constructor de producción, `SO_PEERCRED` real | UID1 autorizado; UID0/2 con UID falsificado rechazados; ninguna excepción privada habilitada. |
| El agente no accede al custodio ni modifica su código | Mismo laboratorio: claves generadas después de fresh exec; grupos suplementarios vacíos; archivos privados, canario de código y `/proc/.../mem` denegados | Prueba local con canarios. El proceso cliente no hereda memoria desbloqueada; ejecutables nuevos y entorno mínimo. |
| Errores del laboratorio no se ocultan como plataforma no disponible | `test_assurance_lab`: salida de hijo malformada frente a diagnóstico conocido de unshare | Error/crash devuelve 1; solo una causa de entorno explícita devuelve 77. |
| IPC del escritorio queda fuera de la fixture | Laboratorio: canario Unix privado inaccesible y entorno sin DISPLAY/Wayland/D-Bus | No prueba un servidor X11, compositor Wayland, portal o bus D-Bus real. |
| Contrato de checkpoints aplica reglas locales a evidencia presentada | [Evaluación Solidity](solidity-assessment.md) y `assurance/solidity` | Bytecode EVM local, sin wallet, cadena, fondos ni dependencia runtime del broker; no prueba veracidad o completitud de eventos externos. |

## Reproducir

Instalar las dependencias fijadas de [README](../README.md), luego:

```sh
.venv/bin/python scripts/assurance.py
.venv/bin/python scripts/assurance.py --all --lab
```

La primera orden ejecuta únicamente las demostraciones nuevas. La segunda incluye regresiones y el laboratorio efímero si el SO lo permite. El resumen JSON contiene cantidades, semilla, tiempos y resultado del laboratorio, nunca eventos operativos o secretos. Un laboratorio no disponible devuelve 77 y se registra explícitamente como no demostrado; un control fallido devuelve 1. Los tests TLS y Unix necesitan permiso para sockets locales. No habilitar acceso a secretos reales para hacerlos pasar.

Para el laboratorio aislado: `.venv/bin/python scripts/two-uid-lab.py`. Requiere Linux, `unshare`, helpers/rangos subordinados ya configurados y permiso de user namespaces. Los clientes parten de **fresh exec antes de generar/desbloquear la clave ficticia**, con entorno mínimo y sin grupos suplementarios. La herramienta rechaza ejecución directa fuera del namespace; no altera cuentas, servicios ni archivos del sistema.

## Fallo real encontrado y corregido

Las barreras reprodujeron que `invalidate_session()` durante una petición en curso podía dejar retornar el resultado anterior. Una revisión independiente encontró una segunda ventana durante la auditoría final. La política ahora vuelve a comprobar generación, identidad de concesión, versión de credencial y vigencia del permiso después del upstream y **después de la auditoría final**, y autoriza el retorno bajo el lock del broker. No mantiene el mutex durante red o auditoría lenta.

Ese retorno es el punto de linearización de autorización. Una revocación posterior no puede recuperar bytes ya entregados ni cancelar serialización/red iniciadas después de ese resultado autorizado. Las escrituras que pudieron enviarse quedan `OUTCOME_UNCERTAIN`, sin retry; la cuota sigue consumida. Si un `outcome:ok` se registró antes de revocar, se emite un evento corrector posterior `outcome:denied` o `outcome:uncertain`, con el mismo `executionId` y secuencia mayor. Consumidores v2 deben agrupar por productor/ejecución y tomar el resultado de mayor secuencia; conservar los eventos crudos para revisión.

## Límites pendientes

No se ha demostrado despliegue operativo con usuarios persistentes, aislamiento de GUI real, pérdida eléctrica/torn writes, robustez de kernel/root, cancelación remota, borrado total de memoria, resistencia frente a todo canal lateral ni completitud de auditoría. Las horas dependen del reloj confiable del host; planes usan monotonic y concesiones UTC. Solidity no elimina ninguna de estas fronteras. La verificación SMT disponible no produjo una prueba formal; sus limitaciones figuran en el estudio separado.
