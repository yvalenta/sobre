# El sobre — especificación v1

**Un formato mínimo para que la salida de un agente se pueda comprobar ante un
tercero, sin confiar en quien la emitió y sin conexión a su servidor.**

Libre y abierto a propósito. Ver §9.

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

### Validación cruzada Ruby ↔ JavaScript (2026-07-26)

El vector de arriba es ASCII puro, así que no prueba lo difícil. Se firmó en
Ruby un segundo documento con **tildes, ñ, `—`, `€`, un emoji y una clave
`"0"`**, y se verificó en JavaScript:

```
bytes canónicos   Ruby 366  ·  JS 366     idénticos
orden de claves   ["0", "descripción", "habeasData", "montos",
                   "reglasHash", "reglasVerificadasAl", "señal"]
cambiar 🐦 por 🐧  → invalido
```

Dos trampas que hacen fallar a JavaScript si se implementa el §3 con
`JSON.stringify` sobre un objeto reconstruido:

1. **Claves que parecen enteros.** En JS, `"0"` se reordena sola al frente de
   un objeto sin importar en qué orden la insertaste. Por eso hay que
   **serializar a mano**, no reconstruir el objeto y dejar que el motor decida.
2. **Orden de las claves no-ASCII.** JS ordena por unidades UTF-16; el §3 exige
   bytes UTF-8. `"señal"` va **al final** (la ñ es `0xC3 0xB1`, mayor que `r`),
   pero un `.sort()` a secas puede ponerla en otro lado. Hace falta un
   comparador que ordene por bytes UTF-8.

Ambas están resueltas en `web/index.html`.

---

## 8. Implementación de referencia

`sobre.rb`. Sin dependencias fuera de la stdlib de Ruby.

```bash
ruby sobre.rb verificar <sobre.json> --llave-url https://host/publickey
```

```bash
ruby sobre.rb verificar <sobre.json> --llave llave.pem --json
```

```bash
ruby sobre_test.rb
```

**23 pruebas, 12 de ellas negativas.** La proporción es intencional: un
verificador que siempre dice OK se ve idéntico a uno que funciona, hasta que
alguien lo ataca. Las pruebas comprueban que rechaza documentos alterados, con
campos agregados, con campos borrados, firmados por otra llave, y firmados de
verdad pero declarando una llave ajena. Cinco más blindan la normalización del
PEM contra saltos de línea, CRLF y anchos de línea distintos.

**Rendimiento medido** sobre el documento real de 2.258 bytes: **101 µs por
verificación**, ~9.900 por segundo. De eso, 83 µs son Ed25519 puro y 18 µs la
canonicalización. No hay caso de rendimiento para reescribir esto en un
lenguaje compilado — ver §10.

`probe.rb` **delega** su canonicalización a `sobre.rb`. Dos copias de la regla
que decide qué bytes se firman es la clase de deriva que nadie nota hasta que
un comprador audita.

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
| **Publicar la spec fuera del repo** | Un estándar que vive en un repo privado no es un estándar. Máxima palanca, costo casi cero |
| **Verificador web sin instalación** | Soltás el JSON en una página y te dice el veredicto. Ed25519 ya está en WebCrypto en los tres motores, así que son ~100 líneas sin dependencias, servibles desde el Worker que ya sirve el agent card — sin tocar el VPS. Es el UX real de "un tercero verifica sin confiar en vos": un abogado o un inspector no instalan nada, pero abren un enlace |
| Implementación en TypeScript | Cerraría el círculo: quien firma podría auto-verificarse con código que no es el suyo |
| Derivar `publicKeyId` de los bytes crudos (v2) | Elimina la ambigüedad de serialización que la normalización hoy tapa |

**Binario en Rust: no, por ahora.** No hay caso de rendimiento (101 µs, ~9.900
verificaciones/s en Ruby, y 83 µs de eso es la criptografía misma, que Rust
tampoco acelera). Y para *longevidad* un binario es **peor** que un script: uno
compilado para x86_64 en 2026 no corre en una máquina ARM de 2036 sin emulación,
mientras que el script corre donde haya Ruby. Lo más duradero de todo es esta
especificación con sus vectores de prueba — sobrevive a cualquier
implementación. Rust se justificaría si un comprador verificara a volumen en CI
o en un entorno que prohíba intérpretes. Nadie pidió eso todavía.
