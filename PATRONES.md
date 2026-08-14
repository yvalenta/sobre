# Patrones de integración

> 🇬🇧 **English:** integration patterns for mounting the envelope on systems
> that already exist — on-chain anchors, marketplace envelopes, one-click
> verification. The normative spec is [`SPEC.en.md`](SPEC.en.md); this file is
> guidance, not new rules.

La spec define el formato. Esto documenta **cómo se monta el sobre en sistemas
que ya existen**, sin cambiarle un byte a la spec ni al sistema anfitrión. Cada
patrón salió de una necesidad real; ninguno agrega reglas nuevas — solo dice
dónde encaja lo que ya hay.

---

## Patrón 1 — El anclaje externo

**Contexto.** Muchos sistemas anclan `hash(documento)` en un lugar que no
pueden falsificar: una cadena de bloques, un log transparente, un servidor de
timestamps. ERC-8004, por ejemplo, ancla feedbacks entre agentes como un hash
on-chain, y el documento se sirve aparte por una URI.

**Lo que el ancla sola no resuelve.** Un hash anclado prueba que un documento
con esos bytes **existía** en cierto momento y que nadie lo cambió después. No
dice **quién** lo escribió, y no permite **leerlo** si la entrega falla. Si el
documento anclado no lleva firma, toda la propiedad depende de que el servidor
lo sirva: el día que la URI deja de resolver, el ancla apunta al vacío y la
integridad que prometía queda **vacía** — sigue siendo verdad que "existe un
documento con ese hash", y nadie en el mundo puede ya decir cuál era.

**El patrón: el documento anclado ES un sobre.** El sistema anfitrión no
cambia — sigue anclando un hash, con la función que use (keccak-256 en EVM,
sha-256 donde sea). Lo que cambia es qué se hashea: los **bytes canónicos
(§3 de la spec)** del sobre completo, ya firmado. Cada propiedad la aporta una
capa distinta, y ninguna depende de la otra:

| Propiedad | La aporta |
|---|---|
| Existencia e inmutabilidad desde el momento T | el ancla |
| Autoría — quién lo emitió | la firma del sobre |
| Legibilidad y verificación sin el emisor ni su servidor | el sobre, offline, en manos de cualquiera que tenga una copia |
| Procedencia del cálculo — contra qué reglas y de cuándo | `reglasHash` + `reglasVerificadasAl` |

La consecuencia que importa: **la entrega deja de ser un punto único de
falla.** Con el ancla sola, perder el servidor pierde la propiedad entera. Con
un sobre anclado, cualquier copia del documento —un mirror, un cache, el disco
del que lo descargó a tiempo— se verifica sola contra el ancla y contra la
firma. Y la autoría deja de ser una columna en una base de datos que alguien
puede escribir mal: es criptográfica o no es.

**Las reglas del patrón:**

1. **El hash externo se calcula sobre los bytes canónicos del sobre completo**
   (con `signature` incluida): es la única representación estable ante
   re-serializaciones. Un hash sobre el JSON "bonito" no re-verifica nunca.
   Producir esos bytes es una línea:

   ```bash
   ruby -r ./sobre -e 'STDOUT.write Sobre.bytes_canonicos(Sobre.cargar(ARGV[0]))' sobre.json | openssl dgst -sha256
   ```

   (En EVM el hash del ancla es keccak-256, **no** sha-256 — usar la función
   del sistema anfitrión. Confundirlas es el primer falso negativo clásico.)

   **Ejemplo con el vector del repo.** Correr el comando de arriba sobre
   [`vectores/sobre.json`](vectores/sobre.json) da, hoy y mientras el vector
   no cambie:

   ```
   e636c7bd0fc91fc418239124b0ec365a9083efdb3704840dd5a47437ee59918d
   ```

   Ese es el número que un sistema externo anclaría (con SU función de hash).
   Cualquiera con una copia del archivo lo re-deriva sin preguntarle nada a
   nadie — que es la propiedad entera del patrón en una línea.
   [`patrones_test.rb`](patrones_test.rb) fija que este número y el documento
   sigan coincidiendo: si el vector cambia, el test truena antes de que esta
   prosa mienta.

2. **Al comparar contra el ancla, normalizar antes de comparar**: prefijo `0x`
   presente o ausente, mayúsculas contra minúsculas. El segundo falso negativo
   clásico es un hash correcto que "no coincide" por el prefijo.

3. **Publicar la llave del emisor (§5).** El ancla no identifica a nadie; la
   firma sí, pero solo si un tercero puede descubrir la llave y cruzar el
   `publicKeyId`.

4. **Lo que el patrón NO da (§6.1 aplica entero):** ancla + firma prueban
   existencia y autoría, **no** que el contenido sea correcto. Un documento
   falso anclado y firmado es un documento falso con fecha cierta y autor
   conocido.

---

## Patrón 2 — El sobre viaja VERBATIM dentro de envelopes ajenos

**Contexto.** Las plataformas de entrega envuelven: un marketplace pide la
entrega dentro de un campo (`json_response`, `result`, `payload`) junto a
reportes legibles, metadata, timestamps.

**El patrón:** el sobre viaja **tal cual, como valor de un campo del envelope
ajeno — ni una clave más, ni una menos** — y todo lo presentacional (resúmenes,
tablas, HTML) vive en los OTROS campos del envelope, nunca adentro del sobre.

**Por qué es regla y no estilo:** la firma cubre **todos** los campos del
documento (§3 descarta `null`, no campos). Agregarle al sobre una clave
`"metadata"` — aunque sea vacía, aunque sea "solo informativa" — produce otros
bytes canónicos y la firma **deja de verificar**. El error se comete siempre
con buena intención y se detecta tarde, porque el JSON se ve bien. La prueba de
que se hizo bien es barata: extraer el campo y pasarlo por `verificar` tiene
que dar el mismo veredicto que el documento original.

---

## Patrón 3 — Verificación de un clic

**Contexto.** La demostración más corta del formato es una URL que descarga un
sobre y lo verifica en el navegador del que mira, sin instalar nada:

```
https://<verificador>/?url=https://<emisor>/ruta/al/sobre.json
```

**Lo que tiene que hacer el que SIRVE el documento** (esto es para el operador
del servidor, no para el usuario):

1. **CORS abierto para ese recurso**: `Access-Control-Allow-Origin: *`. Un
   sobre es un documento público firmado — restringir quién puede *leerlo para
   verificarlo* no protege nada y rompe la verificación de un clic. Sin ese
   encabezado, el navegador del verificador no puede descargarlo y el usuario
   queda relegado a bajar el archivo y arrastrarlo a mano.
2. **Servir los bytes estables**: mismo documento, mismos bytes, sin
   re-serializar por el camino (un proxy que "embellece" JSON rompe el patrón 1
   si además hay un ancla).
3. **`Content-Type: application/json`** — hay navegadores y proxies que
   reescriben lo que creen texto.

---

**Enlaces:** [`SPEC.md`](SPEC.md) · [`IMPLEMENTAR.md`](IMPLEMENTAR.md) ·
[`README.md`](README.md)
