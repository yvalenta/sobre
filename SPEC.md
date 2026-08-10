# El sobre — especificación v1

**Un formato mínimo para que la salida de un agente se pueda comprobar ante un
tercero, sin confiar en quien la emitió y sin conexión a su servidor.**

Libre y abierto a propósito. Ver §9.

> 🇬🇧 **English translation:** [`SPEC.en.md`](SPEC.en.md) traduce las partes
> normativas —§2 a §8— para que nadie tenga que leer español para implementar
> esto. **Este documento sigue siendo la fuente normativa**; el inglés deja
> afuera las secciones de fundamentación por decisión, no por descuido.
>
> Las dos se mantienen sincronizadas por una guarda que compara **las cifras de
> cada una contra `vectores/`**, no una contra la otra: dos textos en idiomas
> distintos no se pueden diffear, pero sus afirmaciones sí se pueden medir.

---

## 1. El problema que resuelve

Execution Market decide si un trabajo entregado estuvo bien así — verificado
contra su propia documentación el 2026-07-26:

```
POST /arbiter/verify      503, deshabilitado desde la auditoría del 2026-04-07
Ring 2 (anillo LLM)       stub, sin reimplementar
arbiter_mode=auto         hard-disabled: guarda el veredicto, NO mueve fondos
disputas                  self-claim, sin auto-asignación, SIN paga al árbitro
sin revisar               auto-liquida al worker a las 72 h
```

Y el mercado cobra en micro-montos: `min_bounty_usd` es **$0,01** y las tareas
abiertas pagan entre **$0,01 y $0,08**.

A ese precio nadie revisa nunca — revisar cuesta más que el bounty por dos
órdenes de magnitud. **En la práctica todo se liquida por temporizador.** La
capa de verificación del mercado es un reloj de 72 horas.

Un sobre elimina la necesidad de árbitro: el comprador corre un comando y
obtiene sí o no.

---

## 2. Qué es un sobre

Un JSON con cuatro piezas además del resultado:

| Campo | Qué aporta | Sin él |
|---|---|---|
| *(la salida)* | el resultado | — |
| `reglasHash` | sha256 del catálogo/método que lo produjo | no se sabe **contra qué** comprobar |
| `reglasVerificadasAl` | fecha en que se comprobó ese catálogo | no se sabe si el método está vigente |
| `habeasData` | constancia de tratamiento de datos | no se sabe qué pasó con el insumo |
| `signature` | Ed25519 sobre el JSON canónico | cualquiera pudo escribirlo |

**La distinción que justifica todo esto:** una firma válida **no alcanza**. Un
documento firmado sin `reglasHash` prueba *quién lo dijo*, no que sea correcto.
Es una opinión firmada. El verificador los separa con veredictos distintos
(§6), porque tratarlos igual es lo que vuelve inútil a la firma.

### Ejemplo mínimo completo

```json
{
  "version": "1",
  "reglasHash": "ca49edf08c164c80a1a178a0ef12feb93e6418b2a73da9809546eb7bacce229f",
  "reglasVerificadasAl": "2026-07-16",
  "habeasData": { "persistidoEnBd": false, "procesadoPorLlmExterno": false },
  "resultados": [{ "externalId": "T-1", "valor": 1234567 }],
  "signature": {
    "algo": "ed25519",
    "valor": "<base64>",
    "publicKeyId": "<sha256(pem)[0,32]>",
    "cubreCampos": "todos_menos_signature",
    "canonical": "sorted_keys_utf8_json"
  }
}
```

---

## 3. Forma canónica

Aquí es donde divergen las implementaciones, así que va exacto. Antes de firmar
o verificar, el documento se transforma:

1. **Descartar la clave `signature`** en la raíz. Una firma no se cubre a sí
   misma.
2. **Descartar toda clave cuyo valor sea `null`**, recursivamente. Un campo
   ausente y un campo en `null` deben producir los mismos bytes; si no, agregar
   un campo opcional vacío rompería firmas viejas.
3. **Ordenar las claves de cada objeto** lexicográficamente por su nombre
   UTF-8, recursivamente.
4. **Los arreglos conservan su orden.** Es información.
5. **Serializar sin espacios** — sin espacio tras `:` ni tras `,`.
6. **UTF-8 sin escapar.** No convertir a `\uXXXX`.

El resultado son los bytes que se firman y sobre los que se verifica.

> **Recomendación fuerte: emitir en ASCII puro.** No es obligatorio, pero evita
> de raíz el mojibake de gateways que sirven sin `charset`, y vuelve
> irrelevante si tu serializador escapa o no los no-ASCII.

### 3.1 En qué difiere de JCS (RFC 8785), y por qué

**JCS es el estándar de canonicalización JSON y esto no lo es.** Si venís de
JCS, estas son las diferencias exactas — importan porque **producen bytes
distintos, y por lo tanto firmas distintas**.

| | JCS (RFC 8785) | El sobre §3 |
|---|---|---|
| Orden de claves | por unidades de código **UTF-16** | por bytes **UTF-8** |
| Claves con valor `null` | **se conservan** | **se descartan**, recursivamente |
| Escapado no-ASCII | literal UTF-8 | igual (literal), con ASCII recomendado |
| Números | serialización de ECMAScript, muy especificada | se emiten tal cual |
| `signature` en la raíz | no aplica | **se descarta** |

**Las dos que de verdad importan:**

**1. El orden.** JCS ordena por unidades UTF-16; acá se ordena comparando los
**bytes UTF-8**. Para claves ASCII —que es el 99% de los casos— dan el mismo
resultado. Divergen a partir de U+10000 (emoji, planos suplementarios): en UTF-16
un par suplente empieza por `0xD800`, que ordena **antes** que un carácter alto
del BMP como `Ａ` (U+FF21); en UTF-8 ordena **después**, porque `0xF0` es mayor
que `0xEF`. Un sobre con una clave emoji firmado por un emisor JCS no
verificaría acá, y al revés.

Ese par exacto —`Ａ` contra `🐦`— es el que lleva el vector unicode del
[§7](#el-vector-que-sí-prueba-lo-difícil), para que la divergencia no quede solo
descrita sino **ejercitada**.

**2. Descartar los `null`.** JCS los conserva. Acá se descartan a propósito, y el
motivo está en el §3.2: **un campo ausente y un campo en `null` deben producir
los mismos bytes**, o agregar un campo opcional vacío rompería todas las firmas
viejas. Es una decisión de compatibilidad hacia adelante, no un descuido.

> **Por qué no se adoptó JCS y no se va a adoptar.** Cambiar de canonicalización
> **invalida todas las firmas ya emitidas**, y este formato existe para que una
> salida siga siendo comprobable dentro de diez años. Romper eso para ganar
> conformidad con un RFC sería exactamente la promesa que el sobre dice no
> romper.
>
> Lo que sí corresponde es **decirlo**, que es lo que hace esta sección: un
> implementador que ya tiene JCS necesita saber en qué difiere antes de escribir
> su verificador, y hasta el 2026-07-28 no podía saberlo.

---

## 4. Firma

- **Algoritmo:** Ed25519 (`algo: "ed25519"`).
- **Mensaje:** los bytes canónicos del §3, tal cual, sin pre-hash.
- **`valor`:** la firma de 64 bytes en base64 estándar.
- **`publicKeyId`:** `sha256(pem_normalizado)` truncado a **32 hex**.

`publicKeyId` no es decorativo: permite comprobar que verificaste contra **la
llave que el documento dice**. Sin ese cruce, verificar correctamente contra la
llave equivocada se ve idéntico a verificar de verdad.

### Normalización del PEM — obligatoria antes de hashear

1. Descartar las líneas `-----BEGIN/END ... -----`.
2. Quitar **todo** espacio en blanco del cuerpo base64.
3. Reconstruir: `-----BEGIN PUBLIC KEY-----\n`, el base64 en líneas de **64**
   caracteres, `\n-----END PUBLIC KEY-----\n`.

> **Por qué es obligatoria.** El id se deriva del *texto* del PEM, que es una
> serialización, no la llave. Sin normalizar, la misma llave da ids distintos
> según quién la guardó. Medido el 2026-07-26: un `curl > llave.pem` agregó un
> solo `\n` y el id pasó de `9958654482741c98f4b6caaffcdf8acc` a
> `13a3c8d9352984f7a1c3a90b376b375c`. La firma verificaba —era la misma llave—
> pero la comprobación de procedencia fallaba. Con CRLF de Windows o con otro
> ancho de línea pasa lo mismo.
>
> **Deuda conocida de v1:** lo correcto sería derivar el id de los **32 bytes
> crudos** de la llave Ed25519 (dentro del SPKI DER), que no tienen
> serialización ambigua. No se hizo así porque producción ya publica el id
> basado en PEM y no se puede cambiar unilateralmente. La normalización cierra
> el agujero; el derivado de bytes crudos queda para v2.

---

## 5. Publicación de la llave

El emisor sirve su llave pública en un endpoint estable:

```json
{ "algo": "ed25519", "publicKeyId": "...", "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n..." }
```

La llave debe ser **estable en el tiempo**. Rotarla invalida la verificación de
todo lo firmado antes — que es precisamente lo que el sobre promete evitar.

---

## 6. Los tres veredictos

| Veredicto | Significa | Exit |
|---|---|---|
| `verificable` | Firma válida **y** procedencia completa. Se sostiene ante un tercero. | **0** |
| `firmado_sin_procedencia` | La firma es auténtica, pero falta contra qué comprobarla. Prueba quién lo dijo, no que sea correcto. | **2** |
| `invalido` | La firma no verifica, falta, o es de otra llave. No confiar. | **1** |

Que `firmado_sin_procedencia` sea un estado propio y no un fallo es
deliberado: es el estado más común en la práctica y el que más se confunde con
"verificado".

### 6.1 Qué NO afirma un sobre

**Un `verificable` es una afirmación estrecha, y decir cuál es su borde vale
tanto como decir qué prueba.** Sin esto, el veredicto se lee como un sello de
calidad y no lo es.

> **Esta lista tuvo seis entradas y le faltaba una.** El 2026-07-29 se agregó la
> de "qué programa recorrió el catálogo", que no estaba ni acá ni en el §10 de
> pendientes — o sea que el hueco era invisible incluso para la propia lista de
> deudas de esta spec. Una enumeración de bordes es lo que un lector cuidadoso
> confía que sea **exhaustiva**; que le falte una la vuelve peor que no tenerla,
> porque el que la lee deja de buscar.

Un sobre `verificable` afirma exactamente tres cosas:

1. Que **estos bytes** los firmó quien controla **esta llave**.
2. Que el emisor **declaró** contra qué catálogo de reglas se comprueba
   (`reglasHash`) y en qué fecha verificó esa normativa
   (`reglasVerificadasAl`).
3. Que dejó constancia de cómo trató los datos (`habeasData`).

**Y no afirma ninguna de estas, aunque se le parezcan:**

- **No afirma que el cálculo sea correcto.** Afirma que es *derivable del
  catálogo declarado*. Si ese catálogo está mal, el sobre es válido y el número
  es incorrecto — y el sobre te da exactamente lo que hace falta para
  demostrarlo, que es el punto.
- **No afirma qué programa recorrió el catálogo.** Dice contra qué catálogo se
  comprueba (`reglasHash`), no qué código lo aplicó. Dos motores —uno correcto y
  uno sutilmente equivocado— producen sobres **indistinguibles en procedencia**
  mientras citen el mismo catálogo: la firma verifica, el `reglasHash` coincide, y
  el número está mal. Es el borde más filoso de esta lista porque **el punto
  anterior lo presupone**: "derivable del catálogo declarado" da por hecho que
  algún programa lo derivó fielmente, y el sobre no le da al verificador ninguna
  forma de comprobar cuál. Diseñado en [§10.1](#101-identidad-del-programa-que-firmó-diseño),
  sin implementar.
- **No afirma que el catálogo declarado sea el vigente.** `reglasVerificadasAl`
  es la fecha en que el emisor *dijo* haberlo comprobado. Un sobre firmado hoy
  contra normativa de hace dos años verifica igual. **La antigüedad es dato del
  verificador, no del emisor.**
- **No afirma nada sobre líneas de origen extralegal.** Bonos, comisiones y
  conceptos pactados no se derivan de una norma, así que no se verifican: quedan
  marcados como no verificables en vez de adivinarse. Un sobre `verificable`
  puede contener líneas que nadie comprobó, **y lo dice**.
- **No es dictamen contable ni asesoría legal.** En Colombia eso está reservado
  (Ley 43/1990).
- **No afirma nada sobre la infraestructura del emisor**: ni que su servidor sea
  seguro, ni que sus datos estén bien custodiados, ni que la organización exista.
  Ese es el terreno de las atestaciones de cumplimiento, y es **otro problema**.
- **No afirma que el emisor sea confiable.** Una firma válida de un mentiroso es
  una firma válida. Lo que cambia es que ahora **su mentira es reproducible por
  un tercero**.

> **Por qué esto va en la spec y no en un descargo legal.** Es la misma
> distinción que sostiene los tres veredictos: `firmado_sin_procedencia` existe
> porque "está firmado" y "es correcto" son cosas distintas, y **el estado más
> peligroso de un sistema de verificación es el que se lee como más de lo que
> es.** Un formato que no declara su borde invita a que un registry lo convierta
> en insignia.
>
> La idea de exigir *non-claims* explícitos no es nuestra: apareció en la
> discusión de la spec de descubrimiento ARD, en las mismas semanas y por el
> mismo motivo. Convergencia independiente, que es la mejor señal de que la
> distinción es real.

---

## 7. Vectores de prueba

Para comprobar una implementación nueva sin adivinar. **Llave de prueba
publicada a propósito — jamás usarla en producción.**

```
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICUO2yvJkTeGWwrDFspYvRdm52KG7qiHKBtVokf3rpwJ
-----END PRIVATE KEY-----
```

```
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA83wZm2o4kOhrC/2IRk2rD0H+cP0Ut58pReGXFcl7WOA=
-----END PUBLIC KEY-----
```

`publicKeyId` esperado:

```
b6b3aa455b1826e2e04402d4a695e40f
```

Documento de entrada:

```json
{"version":"1","reglasHash":"ca49edf08c164c80a1a178a0ef12feb93e6418b2a73da9809546eb7bacce229f","reglasVerificadasAl":"2026-07-16","habeasData":{"persistidoEnBd":false,"procesadoPorLlmExterno":false},"resultados":[{"externalId":"T-1","valor":1234567}]}
```

Bytes canónicos esperados — **251 bytes**, nótese el reordenamiento:

```
{"habeasData":{"persistidoEnBd":false,"procesadoPorLlmExterno":false},"reglasHash":"ca49edf08c164c80a1a178a0ef12feb93e6418b2a73da9809546eb7bacce229f","reglasVerificadasAl":"2026-07-16","resultados":[{"externalId":"T-1","valor":1234567}],"version":"1"}
```

Firma esperada:

```
/evR5PJMg6b/n29bBeWpDAfllT7/a26y+A9Nt5lpmmu423zC7lWHGf1gECoLWDM7GoZHA8osiF/7PP77tAi7Aw==
```

Si tus bytes canónicos coinciden pero tu firma no, el problema es el manejo de
la llave. Si los bytes no coinciden, el problema es el §3 — y esa es la falla
que hace que dos implementaciones "correctas" no se entiendan.

### El vector que sí prueba lo difícil

**El vector de arriba es ASCII puro, así que no atrapa nada.** Si tu
implementación lo pasa, todavía no sabés si funciona: las dos trampas de abajo
lo cruzan sin despeinarse.

Por eso hay un segundo vector, **construido para disparar las dos divergencias
reales**, y se entrega como archivo — no como transcripción:

```
vectores/sobre-unicode.json      el sobre firmado, listo para verificar
vectores/canonico-unicode.txt    los bytes canónicos exactos que debe producir
```

```bash
ruby sobre.rb verificar vectores/sobre-unicode.json --llave vectores/llave-publica.pem
```

Lo que tu implementación tiene que reproducir:

```
bytes canónicos   525
publicKeyId       b6b3aa455b1826e2e04402d4a695e40f
orden de claves   ["-nota", "0", "descripción", "habeasData", "montos",
                   "reglasHash", "reglasVerificadasAl", "señal", "version",
                   "Ａmpliación", "🐦canal"]
```

**Los dos pares que importan, y por qué son esos:**

| Par | Qué pasa si lo hacés como JavaScript |
|---|---|
| `"-nota"` antes de `"0"` | `-` es `0x2D` y `0` es `0x30`, así que por bytes va primero `-nota`. Pero en JavaScript las claves **tipo entero se reordenan solas al frente** de un objeto: si reconstruís el objeto y dejás que el motor decida, `"0"` salta al principio. Hay que **serializar a mano** |
| `"Ａmpliación"` antes de `"🐦canal"` | `Ａ` es U+FF21 (`0xEF…` en UTF-8) y `🐦` es U+1F426 (`0xF0…`). Por bytes va primero la `Ａ`; **por unidades UTF-16 va primero el emoji**, porque es un par suplente que empieza en `0xD800`. Es exactamente el punto donde el [§3.1](#31-en-qué-difiere-de-jcs-rfc-8785-y-por-qué) se separa de JCS |

> **Cómo se llegó a este vector, porque la lección es la que vale.** Hasta el
> 2026-08-09 esta sección describía en prosa un documento que **nunca estuvo en
> `vectores/`**. Al entregarlo por fin como archivo, tenía `ñ`, `—`, `€` y un
> emoji —y **una implementación ingenua de JavaScript lo pasaba entera**: los
> caracteres raros estaban en posiciones donde la primera letra ya decidía el
> orden, así que nunca se comparaban. Lo descubrió `conformidad.rb` corriendo
> contra un canonicalizador roto a propósito.
>
> **Un vector con caracteres raros no es un vector que pruebe algo.** Tiene que
> contener los pares donde los dos órdenes *discrepan*, y eso hay que buscarlo
> a mano. Es la diferencia entre parecer exhaustivo y serlo.

El verificador web (`web/index.html`, el que se sirve en `ynt.codes/verificar`)
resuelve las dos: serializa a mano en vez de reconstruir el objeto, y ordena con
un comparador de bytes UTF-8 propio en lugar de `.sort()`. **Comprobado con este
vector, no afirmado** — sus dos funciones, extraídas tal como se sirven, pasan
`conformidad.rb`.

> Vale la pena el matiz: esa implementación estaba correcta desde que se
> escribió. Lo que faltaba era un vector capaz de **ponerla a prueba**. Durante
> semanas la afirmación "ambas están resueltas" fue cierta por suerte y no por
> evidencia, que desde afuera se ve igual.

---

## 8. Implementación de referencia

`sobre.rb`. Sin dependencias fuera de la stdlib de Ruby.

```bash
ruby sobre.rb verificar <sobre.json> --llave-url https://host/publickey
```

```bash
ruby sobre.rb verificar <sobre.json> --llave llave.pem --json
```

**Emitir** un sobre, que es lo que hace falta para adoptarlo. Escribe en la
salida estándar, así que se encadena:

```bash
ruby sobre.rb firmar documento.json --llave-privada llave.pem | ruby sobre.rb verificar -
```

Si al documento le falta `reglasHash`, `reglasVerificadasAl` o `habeasData`, el
firmador **avisa por `stderr`** que el sobre va a salir como
`firmado_sin_procedencia` y no como `verificable`. Firma igual —es un estado
legal del formato, [§6](#6-los-tres-veredictos)— pero emitirlo sin darse cuenta
es el error más fácil de cometer y el más difícil de ver después.

```bash
ruby sobre_test.rb
```

**La mayoría de las pruebas son NEGATIVAS, y la proporción es intencional:** un
verificador que siempre dice OK se ve idéntico a uno que funciona, hasta que
alguien lo ataca. Comprueban que rechaza documentos alterados, con campos
agregados, con campos borrados, firmados por otra llave, y firmados de verdad
pero declarando una llave ajena. Otras blindan la normalización del PEM contra
saltos de línea, CRLF y anchos de línea distintos, y las últimas afirman que los
vectores entregados **siguen disparando** las divergencias del §7.

> El conteo exacto no se escribe acá a propósito: lo dice la corrida. Este mismo
> párrafo decía «23 pruebas» —cierto para la copia vendorizada de `nomicheck_ops`
> y falso para este repo, que no trae los mismos archivos—, y una cifra que
> depende de dónde se lea es una cifra que va a estar mal en algún lado siempre.

**Rendimiento medido** sobre el documento real de 2.258 bytes: **101 µs por
verificación**, ~9.900 por segundo. De eso, 83 µs son Ed25519 puro y 18 µs la
canonicalización. No hay caso de rendimiento para reescribir esto en un
lenguaje compilado — ver §10.

`probe.rb` **delega** su canonicalización a `sobre.rb`. Dos copias de la regla
que decide qué bytes se firman es la clase de deriva que nadie nota hasta que
un comprador audita.

### 8.1 Comprobar una implementación nueva

`conformidad.rb` corre **tu** implementación contra los vectores. No hace falta
escribirle a nadie ni pedir permiso:

```bash
ruby conformidad.rb --canonicalizador "node canon.js"
ruby conformidad.rb --verificador     "python3 verify.py"
ruby conformidad.rb --firmador        "go run sign.go"
```

El contrato con tu comando es deliberadamente mínimo —`stdin`, `stdout`, código
de salida— para que se pueda cumplir en cualquier lenguaje sin adoptar ninguna
convención nuestra:

| Modo | Recibe por `stdin` | Debe responder |
|---|---|---|
| `--canonicalizador` | un documento JSON | los bytes canónicos del [§3](#3-forma-canónica) por `stdout` |
| `--verificador` | un sobre JSON | salir con `0` **solo** si es `verificable` |
| `--firmador` | un documento JSON | el sobre firmado por `stdout`, con la llave de `vectores/` |

**Empezá por `--canonicalizador`.** Es donde divergen las implementaciones de
verdad: un verificador roto se nota, pero una canonicalización distinta produce
firmas que *parecen* válidas del lado de quien firma y no verifican del otro.

Cuando falla no dice «no coincide»: nombra el byte exacto de la primera
divergencia y, si es una de las dos causas conocidas, **cuál es**:

```
[FALLA ] vector unicode: produce los bytes canónicos exactos
          primera divergencia en el byte 2
            esperado: …"{\"-nota\":\"ordena antes de 0 por bytes…
            obtenido: …"{\"0\":\"clave tipo entero: JavaScript…
            → subiste la clave "0" al frente. En JavaScript las claves tipo
              entero se reordenan solas: hay que SERIALIZAR a mano, no
              reconstruir el objeto y dejar que el motor decida el orden (§7)
```

El verificador se comprueba sobre todo con casos **negativos** —un sobre
alterado, uno sin firma, uno con una firma auténtica de otra llave, y uno
firmado pero sin `reglasHash`—, porque aceptar los dos vectores buenos lo hace
también un programa que responde que sí a todo.

> **Los casos negativos se saltan si tu verificador no acepta un sobre válido**,
> y no es una comodidad. El contrato es un código de salida, así que *"rechacé
> el sobre"* y *"no pude ejecutarme"* son indistinguibles: un comando que no
> existe rechaza todo y pasaba las cuatro pruebas de rechazo — un verificador
> roto sacaba 4 de 6 y quien lo leyera creía estar casi listo.
>
> Lo encontró alguien copiando estos comandos con los nombres de archivo de
> ejemplo tal cual, o sea el primer intento de cualquiera. **Si no sabés aceptar
> un sobre bueno, tu rechazo no prueba nada**, y decirlo es más honesto que
> contarlo como acierto.

---

## 9. Por qué es libre

Un formato de verificación que usa un solo vendedor no vale nada. El valor
aparece cuando el comprador puede verificar **a cualquiera** — y eso solo pasa
si el formato es estándar. Cobrar por él garantiza que nunca lo sea.

El foso no es el formato: es el catálogo de reglas y el motor legal detrás.
Regalar el sobre nos vuelve la implementación de referencia del riel donde
además vendemos.

Encaja en lo que Execution Market ya expone — `evidence_schema` (18 tipos) y
`evidence_content_hash` (SHA-256 por artefacto y raíz) — así que entra como un
tipo de evidencia más, sin pedirle permiso a nadie.

---

## 10. Qué falta

| Qué | Por qué importa |
|---|---|
| ~~**Publicar la spec fuera del repo**~~ | **Hecho.** Vive en `github.com/yvalenta/sobre`, público y CC0 |
| ~~**Verificador web sin instalación**~~ | **Hecho.** `ynt.codes/verificar` — se le suelta el JSON o una URL y devuelve el veredicto, bilingüe, sin instalar ni registrarse. El código es `web/index.html`, sin dependencias |
| ~~**Firmar con la implementación de referencia**~~ | **Hecho.** `ruby sobre.rb firmar doc.json --llave-privada k.pem`. El `publicKeyId` lo **deriva** de la llave privada en vez de aceptarlo como parámetro: así el emisor no puede declarar un id que no corresponde a la llave con la que firmó, que es justo el ataque que `llave_declarada` caza del otro lado |
| ~~**Suite de conformidad**~~ | **Hecho.** `conformidad.rb` — ver [§8.1](#81-comprobar-una-implementación-nueva) |
| ~~Implementación en TypeScript~~ | **Hecha, en JavaScript plano.** `sobre.mjs` — Node 18+, cero dependencias, sin paso de compilación. Verifica, firma y canonicaliza; sirve como librería y como CLI. Pasa `conformidad.rb` en los tres modos y **produce firmas byte a byte idénticas** a las de Ruby. Se eligió `.mjs` sobre TypeScript a propósito: un estándar que para comprobarse pide `npm install`, un `tsconfig` y un build pone una barrera justo donde no debe — igual se type-checkea con `tsc --checkJs --noEmit` |
| Derivar `publicKeyId` de los bytes crudos (v2) | Elimina la ambigüedad de serialización que la normalización hoy tapa |
| **Identidad del programa que firmó** ([§10.1](#101-identidad-del-programa-que-firmó-diseño)) | El sobre ata los bytes, la llave y el catálogo — **no el código**. Dos motores que citen el mismo `reglasHash` son indistinguibles en procedencia. Diseñado; no implementado, y el porqué está abajo |

### 10.1 Identidad del programa que firmó (diseño)

El hueco está en [§6.1](#61-qué-no-afirma-un-sobre): el sobre ata **tres** cosas
—los bytes, la llave, y el catálogo declarado— y ninguna es el código. Dos
binarios que citen el mismo `reglasHash` producen sobres indistinguibles en
procedencia, uno con el número bien y el otro mal.

Esto queda diseñado y **no implementado**. Se escribe entero porque la decisión ya
está tomada y no conviene volver a tomarla desde cero cuando aparezca el primer
comprador que la pida.

#### Los campos

Dos strings planos de nivel raíz, al estilo de `reglasHash` /
`reglasVerificadasAl` y no un objeto anidado:

| Campo | Qué es |
|---|---|
| `motorHash` | sha256 hex de un **hash de árbol** del motor de reglas publicado |
| `motorUri` | dónde se publica el manifiesto que ese hash cubre |

`motorHash` **no** es un SHA de git —irresoluble para un tercero, y el repo del
producto es privado— ni un digest de contenedor, que no es reproducible. Es
sha256 sobre la lista ordenada de líneas `ruta\0sha256(contenido)` de la salida de
build del motor, emitida en tiempo de build y publicada como manifiesto en
`motorUri`.

Da **dos** propiedades y conviene no confundirlas, porque solo una es
incondicional:

- **Enlazabilidad**, siempre: dos sobres con el mismo `motorHash` salieron del
  mismo motor. Vale aunque el manifiesto no exista.
- **Resolubilidad**, condicionada: bajás el manifiesto, recomputás, y confirmás
  qué código fue. Depende de que el manifiesto esté publicado y siga estándolo.

La primera es la garantía real; la segunda es una promesa sobre publicación, y una
spec que las presente como una sola cosa está prometiendo de más.

#### Aditivo puro, y esta parte no se puede errar

[§3.1](#31-en-qué-difiere-de-jcs-rfc-8785-y-por-qué) es explícita en que la
canonicalización está **congelada**, porque cambiarla invalida toda firma ya
emitida. Una clave extra de nivel raíz es segura en las dos direcciones:
`canonicalizar` es genérico y ordena las claves que encuentre, así que un sobre
nuevo verifica bajo un verificador viejo, y un verificador nuevo sobre un sobre
viejo simplemente no encuentra el campo.

#### El check, y el único mecanismo nuevo que hace falta

`sobre.motor_declarado`, **no crítico** y —a diferencia de todos los demás de
`analizar`— **condicionado a presencia**:

```ruby
if doc.key?("motorHash")
  add.call("sobre.motor_declarado", false, valido, ...)
end
```

La condición no es una comodidad, la fuerza [§6](#6-los-tres-veredictos):
`veredicto` devuelve `verificable` solo si **todos** los checks están en ok, así
que un check no crítico incondicional volvería `firmado_sin_procedencia` a cada
sobre ya emitido. La regla, en una línea:

> **La ausencia no puede costar veredicto.**

Y presente-pero-malformado da `firmado_sin_procedencia`, nunca `invalido`: una
afirmación de procedencia mala no puede invalidar una entrega real.

#### Orden de propagación

Hay **cinco** lugares que implementan o documentan esta spec, y el orden no es
preferencia de estilo: dos de ellos son copias vendorizadas con una guarda de
igualdad contra su origen, así que hacerlo al revés deja el auditor en rojo entre
paso y paso.

1. **La implementación de referencia**, en su repo de origen → y en la misma
   sesión, su copia vendorizada.
2. **Los vectores y las pruebas nuevas**, también en el origen primero. No entran
   en la asimetría registrada de los que leen `vectores/`, así que propagan a la
   copia, y los conteos de pruebas se mueven en los dos lados.
3. **La implementación JavaScript** del verificador web, en su origen → la copia
   servida → despliegue. No está terminado hasta que la comparación byte a byte de
   lo **servido** esté verde: un verificador viejo publicado verifica distinto que
   el nuevo, y el que importa es el que abre un tercero.
4. **Esta spec**: §2, §6.1, §7 y §10.
5. **El producto, que es quien firma.** El motor emite el manifiesto durante el
   build y la API agrega el campo al payload firmado.

El paso 5 es el único que **no se puede hacer donde vive esta spec**: el hash solo
se puede *computar* donde se construye el motor. Y esa asimetría es en sí misma un
argumento para no emitir el campo todavía — un verificador que sabe comprobar un
campo que nadie emite es una feature sin productor.

#### Por qué no se implementa todavía

- **Cero consumidores.** Un campo que nadie emite y nadie comprueba es una
  afirmación que nadie verifica.
- **El radio de explosión son cinco artefactos y una spec pública**, con dos
  copias bajo guarda estricta y un deploy en el medio.
- **El hash es irresoluble hasta que el manifiesto se publique**, y eso es trabajo
  en otro repo. Emitir el campo primero es emitir la mitad débil.
- **La lógica de §3.1 argumenta por esperar**: la canonicalización es para
  siempre, y la misma disciplina que produjo esa sección dice diseñar el campo con
  cuidado bajo presión real en vez de v1 de él bajo ninguna.

Lo que sí valía cerrar hoy es el **borde**: que §6.1 no mintiera por omisión.

**Binario en Rust: no, por ahora.** No hay caso de rendimiento (101 µs, ~9.900
verificaciones/s en Ruby, y 83 µs de eso es la criptografía misma, que Rust
tampoco acelera). Y para *longevidad* un binario es **peor** que un script: uno
compilado para x86_64 en 2026 no corre en una máquina ARM de 2036 sin emulación,
mientras que el script corre donde haya Ruby. Lo más duradero de todo es esta
especificación con sus vectores de prueba — sobrevive a cualquier
implementación. Rust se justificaría si un comprador verificara a volumen en CI
o en un entorno que prohíba intérpretes. Nadie pidió eso todavía.
