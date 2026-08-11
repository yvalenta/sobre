# Implementar el sobre en tu lenguaje

Guía para escribir una implementación nueva —verificador, firmador o ambas—
partiendo solo de este repo. No hay que coordinar con nadie: la suite de
conformidad decide, y corre contra cualquier binario por
`stdin`/`stdout`/código de salida.

Hoy hay tres implementaciones que producen **bytes idénticos**: la referencia
en Ruby ([`sobre.rb`](sobre.rb)), una en Node sin dependencias
([`sobre.mjs`](sobre.mjs)) y la del navegador ([`web/`](web/)). Que una cuarta
llegue a los mismos bytes leyendo solo la spec es la evidencia de que el
formato es implementable — **si no llega, el defecto es de la spec y queremos
saberlo**: reportalo tal cual, sin pulir.

## Insumos

| Qué | Dónde |
|---|---|
| Spec normativa | [`SPEC.md`](SPEC.md) (español) · [`SPEC.en.md`](SPEC.en.md) (inglés) |
| Vectores | [`vectores/`](vectores/) — sobre ASCII, sobre unicode, canónicos, llave de prueba |
| Suite de conformidad | [`conformidad.rb`](conformidad.rb) — Ruby stdlib, sin gemas |

## El contrato de proceso

Tres comandos. Sin librerías nuestras, sin red.

```
canonicalizador  stdin: JSON           stdout: bytes canónicos   exit 0
                                       exit != 0 = rechazado a propósito
verificador      stdin: sobre          exit 0 verificable
                                             1 inválido
                                             2 firmado_sin_procedencia
firmador         stdin: doc sin firma  stdout: sobre firmado     exit 0
```

Se somete así (ejemplo con una implementación en Node):

```bash
ruby conformidad.rb \
  --canonicalizador "node tu-sobre.js canonicalizar -" \
  --verificador     "node tu-sobre.js verificar - --llave vectores/llave-publica.pem" \
  --firmador        "node tu-sobre.js firmar - --llave-privada vectores/llave-privada-SOLO-PRUEBAS.pem"
```

**Verde = interoperable.** No hay revisión humana de por medio. Podés empezar
solo con `--canonicalizador`: la suite corre lo que le des.

## Los lugares donde se rompe

No están acá porque suenen difíciles: cada uno ya rompió algo real. (El
título no lleva conteo a propósito: la lista crece cuando un implementador
nuevo paga un peaje nuevo.)

**1. El orden de claves es por bytes UTF-8, no por unidades UTF-16.**
`Array.prototype.sort()` de JavaScript ordena por UTF-16 y **da otro orden**
para claves fuera del BMP. Hay que comparar los bytes codificados. El vector
unicode lo dispara a propósito con `"Ａmpliación"` contra `"🐦canal"`.

**2. Una clave que parece número no se ordena como número.** `Object.keys()`
de JavaScript sube las claves de índice entero al frente, antes que cualquier
string. El vector trae `"0"` y `"-nota"` para cazarlo.

**3. Los números.** La regla completa está en el §3.2 de la spec: lo integral
se emite como entero, un decimal se emite con los dígitos **más cortos que
round-trippean** en notación plana, y se rechazan los enteros sobre 2^53−1 y
los decimales bajo 1e-6. Si tu serializador JSON no emite la forma más corta
(el de Ruby no la emite), buscá la precisión más chica que vuelve al mismo
double con un bucle de 1 a 17 — no dependas de tu librería.

**4. La normalización del PEM.** `publicKeyId` es `sha256(pem normalizado)`
truncado a 32 hex, y el PEM se normaliza a base64 en líneas de 64 con salto
final. **Un solo `\n` de diferencia cambia el id** — ya pasó.

**5. stdin son bytes, no texto.** El contrato de proceso entrega **bytes
UTF-8** por stdin; si tu runtime los decodifica con la codificación de la
consola, el documento entra corrupto y el error revienta lejos del culpable.
El caso real (reportado por el primer implementador externo, 2026-08-11):
`sys.stdin.read()` en Python bajo Windows decodifica con cp1252 y el fallo
aparece recién al canonicalizar, como `UnicodeEncodeError: surrogates not
allowed` — señalando al lugar equivocado. Leé los bytes y decodificá vos:
`sys.stdin.buffer.read().decode("utf-8")`. Y lo simétrico al emitir: escribí
bytes UTF-8 a stdout (`sys.stdout.buffer.write(...)`), no texto en la
codificación por defecto.

## Los tres veredictos, y por qué no son dos

- **`verificable`** — la firma es válida **y** el documento declara contra qué
  comprobarse (`reglasHash`, `reglasVerificadasAl`, `habeasData`).
- **`firmado_sin_procedencia`** — la firma es auténtica pero no hay contra qué
  comprobarla. Prueba **quién lo dijo**, no que sea correcto.
- **`invalido`** — no verifica. No confiar en la salida.

Colapsar `firmado_sin_procedencia` en cualquiera de los otros dos es el error
que vuelve inútil a la firma: un documento firmado sin `reglasHash` es una
opinión firmada.

## Definición de terminado

1. `conformidad.rb` en verde con los modos que implementes.
2. Firma cruzada, si implementás firmador: lo que firma tu implementación lo
   verifica la referencia, y al revés.
3. Un sobre alterado en un byte da exit 1 — exigí el fallo, no lo observes.
4. Los dos vectores publicados verifican con la llave publicada.

## Lo que NO hay que hacer

- **No adaptar los vectores.** Si se ajustan para que pasen, se está probando
  la adaptación.
- **No agregar dependencias** para canonicalizar o hashear. Un estándar que
  necesita un gestor de paquetes para comprobarse pone la barrera justo donde
  no debe.
- **No tocar la canonicalización** para que encaje: está congelada (§3.1), y
  cambiarla invalida todas las firmas ya emitidas sin que nadie se entere
  hasta que alguien verifica un documento viejo.
