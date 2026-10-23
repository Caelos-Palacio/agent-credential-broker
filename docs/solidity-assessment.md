# Solidity como testigo de auditoría: alcance y evaluación

**Un contrato puede reforzar la evidencia de publicación de checkpoints; no demuestra que Agent Credential Broker sea seguro.** Para este proyecto priorizaría un testigo independiente que firme y conserve checkpoints fuera del custodio. Consideraría una cadena pública únicamente si varias partes que no confían entre sí necesitan verificar el mismo orden de publicación y aceptan su coste, exposición y modelo de finalidad. Esta es una conclusión de diseño, no una propiedad implementada del runtime.

## Qué demuestra cada técnica

| Técnica | Aporta | No demuestra | Coste y privacidad |
|---|---|---|---|
| Tests de permisos/esquemas/UID y campañas adversarias | Ejemplos reproducibles de los límites implementados | Ausencia de todos los fallos posibles | Bajo–medio; fixtures locales, sin terceros |
| Verificación formal de una especificación acotada | Propiedades matemáticas del modelo bajo sus hipótesis | Que la especificación cubra la intención, el OS o el software completo | Medio–alto; requiere especificación y solver, no basta compilar |
| Checkpoint guardado por un tercero independiente | Contraste de una copia posterior con una referencia que el custodio no controla | Veracidad o eventos omitidos antes de emitir la referencia | Bajo; almacenamiento y canal confiables |
| Testigo offline con firma | Atribución a una clave testigo y detección de modificación del mensaje firmado | Veracidad, hora confiable o completitud; tampoco independencia si la clave comparte custodio | Bajo–medio; metadatos privados, operación de claves separada |
| Log de transparencia con pruebas de inclusión/consistencia | Evidencia verificable de inclusión y crecimiento; detección de algunas vistas divergentes con monitores/testigos | Que un productor haya enviado todos los eventos ni que todos sean reales | Medio; servicio y monitorización; instancia pública expone metadatos |
| Registro Solidity de compromisos | Reglas del contrato y orden de checkpoints publicados según la cadena/finalidad elegidas | Vault, permisos del SO, aislamiento del agente, captura completa, verdad del digest o ausencia de exfiltración | Alto relativo para una herramienta local; fees, claves, operadores y exposición pública |

La documentación de Solidity distingue pruebas de propiedades especificadas y corrección de la intención: el SMTChecker usa `require` como hipótesis y trata de demostrar `assert`; habilitar el motor y disponer de un solver son requisitos reales. No convierte una compilación exitosa en prueba. [SMTChecker oficial](https://docs.soliditylang.org/en/latest/smtchecker.html).

Foundry permite campañas de secuencias aleatorias e invariantes con dimensiones runs/depth. Una campaña donde todo revierte puede dar una confianza falsa si nunca ejercita estados útiles; por eso nuestra demostración cuenta aceptaciones y rechazos y comprueba efectos. No se instaló ni ejecutó Foundry. [Foundry: invariant testing](https://getfoundry.sh/forge/invariant-testing).

## PoC implementada y comprobada

En [assurance/solidity](../assurance/solidity/README.md) hay un contrato MIT pequeño, sin integración con Python ni cadena real. El compilador oficial solc 0.8.37 se descargó temporalmente desde el repositorio oficial, con versión/hash fijados y comprobados antes de ejecutar. El programa ejecuta bytecode real en una EVM en memoria con direcciones sintéticas; no firma transacciones ni usa claves. Las instrucciones reproducibles están en el README de la PoC.

El contrato fija publisher y producer opaco; liga su domain a etiqueta de protocolo, chainId, dirección del contrato y scope opaco. `append` exige `msg.sender` autorizado, scope/producer correctos, secuencia estrictamente creciente, cabeza anterior exacta y digest no nulo. Guarda el historial y actualiza la cabeza sin llamadas externas. No acepta archivos, secretos o JSON crudo y no autoriza acciones del broker.

Ocho tests EVM pasaron, incluyendo 256 llamadas aleatorias con semilla `0x4123`: 84 aceptadas y 172 rechazadas. Se verificaron estado intacto tras rechazo, secuencia/cabeza tras cada llamada, historial, caller incorrecto, domain/producer incorrectos, predecessor obsoleto, duplicados, retrocesos, digest cero, constructor cero, frontera uint64, ABI incompleta y replay entre despliegues. Otro test acepta deliberadamente un digest inventado por el publisher: evidencia concreta de que el contrato no comprueba los eventos de origen.

Se intentó CHC de verdad. El compilador informó que Z3 no estaba disponible y no pudo iniciar el análisis; se obtuvieron cero aserciones demostradas. `npm run smt` devuelve estado no disponible y exit 2. **No hay prueba formal ni despliegue.** Ningún binario compilado o dato de runtime se versiona.

## Quién observa qué

1. **Productor/custodio:** observa acciones que su propia instrumentación registra. Puede fallar, omitir eventos o fabricar metadatos antes de cualquier hash. Un publisher controlado por el mismo custodio no añade independencia en esa captura.
2. **Testigo externo:** recibe un checkpoint y, preferiblemente, el exportado saneado que lo sustenta. Solo puede validar formato, secuencia y correspondencia entre lo recibido; no ve por sí mismo las operaciones del proveedor. Debe conservar referencias bajo otra frontera de control.
3. **Contrato/validadores:** verifican la transición on-chain, no el archivo off-chain. El digest es opaco. La cadena puede revelar cuándo se publicó, no cuándo ocurrió la acción original.
4. **Revisor:** necesita una referencia de confianza, los parámetros exactos del compromiso y una copia saneada que pueda recomputar. También necesita saber qué intervalos/captura se prometieron. Comparar solo dos valores proporcionados por el custodio no demuestra independencia.

Un exportado modificado o truncado **después** de fijar una referencia independiente puede detectarse al recomputar y comparar con esa referencia. Si se publica solamente una subsecuencia desde el principio, el digest puede coincidir perfectamente: ni contrato, firma ni Merkle tree detectan automáticamente los eventos que nunca recibieron. Huecos de secuencia dentro del intervalo observado son indicios; no certifican cobertura de intervalos anteriores/posteriores. Harían falta fuentes independientes, recibos del proveedor o un protocolo de captura cuya completitud esté especificada y verificada.

La PoC permite saltos de secuencia porque representa lotes. Un `previousDigest` correcto liga cabezas publicadas, pero el contrato no calcula la cadena interna de eventos ni valida el esquema del exportado. Tampoco identifica la persona o agente que ejecutó una acción. Una referencia blockchain no sustituye el `audit-verify` offline existente ni cambia sus garantías.

## Amenazas nuevas al usar una cadena

- **Privacidad:** todas las entradas y variables Solidity son públicas, incluso las marcadas `private`. No publicar contraseñas, claves, cuerpos ni datos personales. Direcciones, secuencias y cadencia siguen siendo correlacionables aunque los digests sean opacos; hashes de datos predecibles permiten ataques de diccionario. Cualquier compromiso con nonce aleatorio exigiría especificación y conservación privada por los verificadores, no ocultaría metadatos de transacción. [Solidity: private information](https://docs.soliditylang.org/en/latest/security-considerations.html#private-information-and-randomness).
- **Custodia de claves:** una clave de publicación robada permite compromisos falsos futuros; perderla congela esta PoC inmutable. Añadir rotación, multisig o guardianes cambia la superficie y requiere revisión. OpenZeppelin ofrece ownership/roles y transferencia en dos pasos para diseños que lo necesiten; aquí no importamos su librería porque no hay administración dinámica. [OpenZeppelin: access control](https://docs.openzeppelin.com/contracts/5.x/access-control).
- **Front-running y orden:** un tercero que copie calldata no pasa `msg.sender`, pero validadores pueden retrasar/reordenar/censurar y dos publicaciones legítimas con el mismo predecessor compiten: una debe revertir y reconciliarse fuera del contrato. La autorización no garantiza inclusión o puntualidad.
- **Reorgs/finalidad:** una transacción incluida todavía puede cambiar de posición o desaparecer antes de alcanzar la finalidad asumida. Un verificador debe fijar cadena, despliegue y política de finalidad, y contemplar fallos críticos de consenso. Ethereum documenta reorgs, retraso de finalidad y censura; no son garantías de una EVM local. [Ethereum: attacks and defense](https://ethereum.org/developers/docs/consensus-mechanisms/pos/attack-and-defense).
- **Gas, disponibilidad y crecimiento:** el trabajo por append está acotado, pero el historial crece y publicar cuesta recursos. Una caída de RPC o presupuesto no debe bloquear guardar auditoría local, aprobar acciones autorizadas ni devolver secretos como alternativa. Esta PoC no tiene RPC ni política de fees.
- **Compilador/modelo:** bytes compilados, bibliotecas y emulador son parte de la base de confianza. Un SHA256 fijado desde HTTPS verifica igualdad del artefacto esperado; no constituye por sí solo una firma del compilador o reconstrucción reproducible independiente. Las aserciones SMT tampoco verifican fuerza criptográfica de keccak ni todo el consenso.

## Alternativa recomendada antes de una chain

Evaluaría un mensaje versionado acotado con dominio de protocolo, ID opaco de productor, rango/contador de eventos, digest, referencia previa y timestamp de recepción del testigo. El testigo valida únicamente datos saneados y firma ese mensaje; el revisor recibe la clave pública por un canal de confianza distinto del custodio. La clave privada y estado de secuencia pertenecen a otro proceso/UID o dispositivo bajo control independiente; una clave en otro archivo del mismo custodio no establece esa separación.

PyCA implementa Ed25519 con API de firma/verificación; emplear una implementación revisada evita construir firmas propias. Una firma acredita el control de la clave sobre el mensaje, no la verdad de un log ni una hora confiable. Generación, custodia, rotación, revocación y registro de claves públicas tendrían que especificarse. **Este testigo no está implementado ni se generaron claves reales.** [PyCA Ed25519](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/).

Si hace falta una vista compartida, Rekor permite registrar metadatos firmados y comprobar inclusión; sus monitores comprueban consistencia append-only. También requiere confianza operativa y detección de vistas divergentes, y una instancia pública puede exponer identidades/metadatos. No se subieron datos a Rekor ni se instaló un servicio. [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/), [verifiable data structures](https://transparency.dev/verifiable-data-structures/).

Para elegir mediría bytes revelados, retraso máximo de evidencia, quién puede alterar cada referencia, recuperación ante pérdida/compromiso de clave, tiempo de verificación offline, coste operativo y comportamiento ante testigo ausente. La siguiente inversión más útil para el broker es validar su aislamiento real y sus invariantes de permisos/consumo, más una frontera de testigo demostrable. Publicar un contrato sería una capa adicional de evidencia con un propósito concreto, nunca un sello universal de seguridad.
