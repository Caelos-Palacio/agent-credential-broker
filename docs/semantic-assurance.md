# Semántica de permisos y ciclo de ejecución

Estas pruebas contrastan contratos tipados con el Broker real. No interpretan instrucciones naturales ni incorporan un clasificador o LLM a la autorización. Catálogo, concesión, aprobación y reloj pertenecen al custodio confiable; los mensajes del agente y proveedor no pueden actualizarlos. Los casos publicados son sintéticos nuevos, sin documentos o configuraciones personales.

## Modelo y observaciones

`tests/lifecycle_spec.py` es una máquina abstracta separada: no importa el Broker, sus validadores ni sus códigos de error. Predice entrega, dispatches, reservas durables e incertidumbre de escrituras. `tests/test_assurance_semantics.py` aplica las secuencias a `ActionBroker`, `TaskGrant` y `QuotaStore` reales. Sustituye bóveda y proveedor por fixtures en memoria y controla ambos relojes y callbacks del custodio. La bóveda cifrada y transporte real tienen otras pruebas en la [matriz de seguridad](assurance.md).

Se enumeran **288 trazas**: lectura/escritura, aprobación concedida/denegada, cuota disponible/agotada, nueve cambios y barreras aplicables. Los cambios son ninguno, invalidación de sesión, revocación de concesión, reemplazo con otro documento, reemisión idéntica, versión de credencial, caducidad de plan, caducidad de concesión y fallo de auditoría. Las barreras son antes de ejecutar, aprobación, auditoría de intención, respuesta del proveedor y auditoría final. Aprobación e intención son exclusivas de escritura.

Además de comparar efectos con el modelo, se comprueban replay rechazado, intención registrada antes del dispatch de escritura, resultado posterior al dispatch y registro final cuando funciona la auditoría. No se fabrica evidencia persistida cuando el callback de auditoría falla. Hay continuaciones autorizadas que deben completar: denegar todo falla las pruebas.

El TTL monotónico del plan limita el inicio de dispatch; caducar durante una petición no cancela sus efectos. Concesión, instancia original, sesión y versión de credencial siguen comprobándose antes de entregar. Una escritura posiblemente enviada queda incierta, sin reintento. Una reserva del permiso original puede persistir si se revoca después de validar y reservar: representa un intento, no ejecución confirmada.

## Contraejemplos y correcciones

La exploración encontró dos problemas en el runtime público anterior:

1. Reemplazar la concesión durante aprobación podía consumir cuota del permiso nuevo para el plan antiguo antes de rechazarlo. Ahora se revalida antes de reservar y se usa la referencia original capturada. Una regresión reemplaza la concesión justo entre validación y persistencia: solo se cobra el permiso original, sin secreto ni dispatch posterior.
2. Revocar y reemitir el mismo documento generaba el mismo identificador y permitía ejecutar un plan antiguo. Ahora cada plan en memoria liga la instancia original además del identificador durable. La reemisión exige un plan nuevo y conserva el presupuesto. `TaskGrant.document` devuelve una copia de inspección: modificarla o modificar el documento de entrada no cambia el permiso efectivo.

El runtime público anterior, cargado solamente en un módulo temporal de prueba, falla el nuevo contrato. No se usó como oráculo ni se cambió el árbol anterior. Las regresiones distinguen plan antiguo rechazado, plan nuevo autorizado y cuota que no se reinicia por reemisión.

## Mutaciones sintéticas

Doce familias conservan el ID de acción e intentan cambiar actor, alias destino, recurso, aprobación, unidad, frontera numérica, condición, negación, excepción, orden de auditoría, recurso con ID conservado o `authority_update`. Cada una bloquea secreto y dispatch. Un control autorizado completa la escritura y recibe solo la salida proyectada aunque el proveedor incluya instrucciones de autoridad y excepciones. Otra prueba modifica solicitud original y copia de revisión humana: destino y cuerpo enviados conservan los valores del plan.

Son diferencias operativas concretas: unidad es un campo tipado restringido por concesión y comparador una frontera numérica del catálogo. No representan comprensión general de unidades, negación o equivalencia de lenguaje natural.

## Reproducir y límites

```sh
.venv/bin/python -m unittest discover -s tests -p test_assurance_semantics.py -v
.venv/bin/python scripts/assurance.py --all
```

Seis métodos contienen los subcasos; no son 288 observaciones independientes de usuarios o modelos. La enumeración es completa únicamente en este producto finito de fixtures y barreras: no explora todos los interleavings, valores, fallos o relojes y no es una prueba formal. Modelo y pruebas pueden compartir errores conceptuales; separación, controles positivos y contraejemplos reducen ese riesgo sin eliminarlo. Código arbitrario del custodio, capaz de modificar atributos privados, queda fuera del modelo. No se afirman aislamiento productivo, cancelación remota ni secreto absoluto.
