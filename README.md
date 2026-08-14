# sobre

**Un formato mínimo para que la salida de un agente se pueda comprobar ante un
tercero, sin confiar en quien la emitió y sin conexión a su servidor.**

Libre y de dominio público. Ver [por qué](#por-qué-es-libre).

> 🇬🇧 **English:** the normative parts of the spec are translated in
> [`SPEC.en.md`](SPEC.en.md) — everything you need to implement, without reading
> Spanish. Run `ruby conformidad.rb --canonicalizador "<your command>"` to check
> your implementation against the test vectors.

---

## El problema

Una salida de agente en un archivo de texto la escribe cualquiera. No vale nada
ante un inspector, un auditor o un comprador.

Firmarla tampoco alcanza. Un documento firmado prueba **quién lo dijo**, no que
sea correcto — sin saber contra qué reglas se calculó y de cuándo son, una firma
válida es una opinión con sello.

Un sobre agrega las tres cosas que faltan:

```json
{
  "resultados": [ ... ],
  "reglasHash": "ca49edf0…",          // sha256 del catálogo/método que lo produjo
  "reglasVerificadasAl": "2026-07-16", // cuándo se comprobó ese catálogo
  "habeasData": { "persistidoEnBd": false, "procesadoPorLlmExterno": false },
  "signature": { "algo": "ed25519", "valor": "…", "publicKeyId": "…" }
}
```

## Verificar uno

```bash
ruby sobre.rb verificar salida.json --llave-url https://host/publickey
```

```bash
ruby sobre.rb verificar salida.json --llave llave.pem --json
```

Sin instalar nada, en el navegador: abrí [`web/index.html`](web/index.html).
Corre entero del lado del cliente, sin una sola petición de red.

### Los tres veredictos

| Veredicto | Significa | Exit |
|---|---|---|
| `verificable` | Firma válida **y** procedencia completa. Se sostiene ante un tercero. | **0** |
| `firmado_sin_procedencia` | La firma es auténtica, pero falta contra qué comprobarla. | **2** |
| `invalido` | No verifica, falta, o es de otra llave. | **1** |

Que `firmado_sin_procedencia` tenga estado propio y no sea un fallo es
deliberado: es el más común en la práctica y el que más se confunde con
«verificado».

## Emitir uno

No hay nada que instalar ni registrar: una llave, un comando, y publicar la
llave pública.

```bash
# 1. La llave, una sola vez (la privada no sale nunca de tu máquina)
openssl genpkey -algorithm ed25519 -out privada.pem
openssl pkey -in privada.pem -pubout -out publica.pem

# 2. Firmar tu salida
ruby sobre.rb firmar salida.json --llave-privada privada.pem > sobre.json

# 3. Publicar la llave pública en un endpoint estable (§5 de la spec):
#    { "algo": "ed25519", "publicKeyId": "…", "publicKeyPem": "…" }
ruby sobre.rb llave-id publica.pem   # el id que declara ese endpoint

# 4. Desde acá, cualquiera verifica sin hablar con vos:
ruby sobre.rb verificar sobre.json --llave publica.pem
```

Si `firmar` avisa `firmado_sin_procedencia`, tu salida aún no lleva
`reglasHash`, `reglasVerificadasAl` o `habeasData` — firma auténtica,
procedencia incompleta (§6). En Node es la misma superficie: `firmar`, `analizar` y `veredicto` en
[`sobre.mjs`](sobre.mjs).

**Para montarlo en sistemas que ya existen** —un hash anclado on-chain, el
envelope de un marketplace, verificación de un clic— ver
[`PATRONES.md`](PATRONES.md).

## Implementarlo en otro lenguaje

**La guía completa está en [`IMPLEMENTAR.md`](IMPLEMENTAR.md)** — el contrato
de proceso de la conformidad, los cuatro lugares donde se rompe de verdad y la
definición de terminado. Lo de abajo es el resumen.

Leé [`SPEC.md`](SPEC.md) — son seis reglas de canonicalización y una firma
Ed25519. Después comprobá tu implementación contra
[`vectores/`](vectores/), que trae la llave, el sobre, los bytes canónicos
esperados y la firma:

```
vectores/llave-publica.pem              la llave del vector
vectores/llave-privada-SOLO-PRUEBAS.pem publicada a propósito, jamás en producción
vectores/sobre.json                     un sobre completo y bien firmado
vectores/canonico.txt                   los 251 bytes exactos que hay que producir
```

Si tus bytes canónicos coinciden pero tu firma no, el problema es el manejo de
la llave. Si los bytes no coinciden, el problema es la canonicalización — y esa
es la falla que hace que dos implementaciones «correctas» no se entiendan.

## Estado

Tres implementaciones independientes que producen bytes idénticos:

| Lenguaje | Dónde | Rol |
|---|---|---|
| Ruby | [`sobre.rb`](sobre.rb) | referencia |
| JavaScript | [`web/index.html`](web/index.html) | verificador sin instalación |
| TypeScript | privado (NomiCheck) | emisor |

**28 pruebas, 12 de ellas negativas.** La proporción es intencional: un
verificador que siempre dice OK se ve idéntico a uno que funciona, hasta que
alguien lo ataca.

```bash
ruby sobre_test.rb
```

Rendimiento medido sobre un documento real de 2.258 bytes: **101 µs por
verificación**, ~9.900 por segundo. De eso, 83 µs son Ed25519 puro.

## Por qué es libre

Un formato de verificación que usa un solo emisor no vale nada. El valor
aparece cuando el comprador puede verificar **a cualquiera**, y eso solo pasa si
el formato es estándar. Cobrar por él garantiza que nunca lo sea.

El foso de quien lo usa no es el formato: es el catálogo de reglas que hay
detrás.

## Licencia

**Dominio público** ([CC0 1.0](LICENSE)). Sin atribución requerida, sin
condiciones. Un estándar con fricción de licencia no se adopta.
