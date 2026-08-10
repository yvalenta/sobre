# The envelope (*el sobre*) — specification v1

**A minimal format that lets an agent's output be checked by a third party,
without trusting whoever issued it and without reaching its server.**

Free and open on purpose. See [§9](#9-why-its-free).

> **About this document.** The normative source is
> [`SPEC.md`](SPEC.md), in Spanish. This is a **full translation of the
> normative parts** — §2 through §8 — written so an implementer never has to
> read Spanish. It deliberately leaves out the long rationale sections (the
> history behind each decision, the design notes for unreleased fields); those
> live in the Spanish document and are commentary, not requirements.
>
> **Every concrete figure below is checked against the shipped test vectors in
> CI**, in both documents. If a number here disagrees with `vectores/`, the
> build fails. That is the only sync guarantee worth making: prose can drift,
> but the facts cannot.

---

## 1. The problem

Marketplaces settle agent work by timer, not by review. When a task pays cents,
reviewing it costs more than the bounty by two orders of magnitude, so nothing
gets reviewed and everything auto-settles.

An envelope removes the need for an arbiter: the buyer runs one command and gets
yes or no.

---

## 2. What an envelope is

JSON with four pieces besides the result:

| Field | What it adds | Without it |
|---|---|---|
| *(the output)* | the result | — |
| `reglasHash` | sha256 of the rule catalogue/method that produced it | you don't know **against what** to check |
| `reglasVerificadasAl` | date the issuer checked that catalogue | you don't know whether the method is current |
| `habeasData` | record of how the input data was handled | you don't know what happened to the input |
| `signature` | Ed25519 over the canonical JSON | anyone could have written it |

**The distinction that justifies the whole format:** a valid signature is **not
enough**. A document signed without `reglasHash` proves *who said it*, not that
it is correct. It is a signed opinion. The verifier keeps them apart with
separate verdicts ([§6](#6-the-three-verdicts)), because conflating them is what
makes signatures useless.

Field names stay in Spanish on purpose: they are part of the wire format, and
translating them would produce a second, incompatible format.

### Minimal complete example

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

## 3. Canonical form

This is where implementations diverge, so it is given exactly. Before signing or
verifying, transform the document:

1. **Drop the `signature` key** at the root. A signature does not cover itself.
2. **Drop every key whose value is `null`**, recursively. An absent field and a
   `null` field must produce the same bytes; otherwise adding an empty optional
   field would break old signatures.
3. **Sort each object's keys** lexicographically **by their UTF-8 bytes**,
   recursively.
4. **Arrays keep their order.** It is information.
5. **Serialize without whitespace** — no space after `:` or `,`.
6. **UTF-8, unescaped.** Do not convert to `\uXXXX`.

The result is the byte string that gets signed and verified.

> **Strong recommendation: emit pure ASCII.** Not required, but it avoids
> mojibake from gateways that serve without `charset`, and makes it irrelevant
> whether your serializer escapes non-ASCII.

### 3.1 How it differs from JCS (RFC 8785), and why

**JCS is the JSON canonicalization standard and this is not it.** If you are
coming from JCS, these are the exact differences — they matter because they
**produce different bytes, and therefore different signatures**.

| | JCS (RFC 8785) | This spec §3 |
|---|---|---|
| Key ordering | by **UTF-16** code units | by **UTF-8** bytes |
| Keys with `null` values | **kept** | **dropped**, recursively |
| Non-ASCII escaping | literal UTF-8 | same (literal), ASCII recommended |
| Numbers | ECMAScript serialization, tightly specified | emitted as-is |
| `signature` at the root | n/a | **dropped** |

**The two that actually matter:**

**1. Ordering.** JCS sorts by UTF-16 code units; here you compare **UTF-8
bytes**. For ASCII keys — 99% of cases — they agree. They diverge from U+10000
onward (emoji, supplementary planes): in UTF-16 a surrogate pair starts at
`0xD800`, which sorts **before** a high BMP character such as `Ａ` (U+FF21); in
UTF-8 it sorts **after**, because `0xF0` is greater than `0xEF`. An envelope with
an emoji key signed by a JCS emitter would not verify here, and vice versa.

That exact pair — `Ａ` against `🐦` — is in the unicode test vector of
[§7](#7-test-vectors), so the divergence is exercised and not merely described.

**2. Dropping `null`s.** JCS keeps them. Here they are dropped on purpose: an
absent field and a `null` field must produce the same bytes, or adding an empty
optional field would break every existing signature. It is forward-compatibility,
not an oversight.

> **Why JCS was not adopted, and will not be.** Changing canonicalization
> **invalidates every signature already issued**, and this format exists so that
> an output stays checkable ten years from now. Breaking that to gain conformance
> with an RFC would be exactly the promise the envelope claims not to break.
>
> What is owed is **saying so**, which is what this section does: an implementer
> who already has JCS needs to know how it differs before writing a verifier.

---

## 4. Signature

- **Algorithm:** Ed25519 (`algo: "ed25519"`).
- **Message:** the canonical bytes from §3, as-is, no pre-hash.
- **`valor`:** the 64-byte signature, standard base64.
- **`publicKeyId`:** `sha256(normalized_pem)` truncated to **32 hex chars**.

`publicKeyId` is not decorative: it lets a verifier confirm it checked against
**the key the document names**. Without that cross-check, correctly verifying
against the wrong key looks identical to verifying for real.

### PEM normalization — required before hashing

1. Drop the `-----BEGIN/END ... -----` lines.
2. Strip **all** whitespace from the base64 body.
3. Rebuild: `-----BEGIN PUBLIC KEY-----\n`, the base64 in **64**-character lines,
   `\n-----END PUBLIC KEY-----\n`.

> **Why it is required.** The id derives from the PEM *text*, which is a
> serialization, not the key. Unnormalized, the same key yields different ids
> depending on who saved it. Measured: a `curl > key.pem` added a single `\n` and
> the id changed completely. The signature still verified — same key — but the
> provenance check failed. Windows CRLF or a different line width do the same.
>
> **Known v1 debt:** the right thing is deriving the id from the **32 raw bytes**
> of the Ed25519 key inside the SPKI DER, which have no ambiguous serialization.
> That was not done because production already publishes the PEM-based id and it
> cannot be changed unilaterally. Normalization closes the hole; raw-byte
> derivation is v2.

---

## 5. Publishing the key

The issuer serves its public key at a stable endpoint:

```json
{ "algo": "ed25519", "publicKeyId": "...", "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n..." }
```

The key must be **stable over time**. Rotating it invalidates verification of
everything signed before — precisely what the envelope exists to prevent.

---

## 6. The three verdicts

| Verdict | Meaning | Exit |
|---|---|---|
| `verificable` | Valid signature **and** complete provenance. Holds up to a third party. | **0** |
| `firmado_sin_procedencia` | The signature is authentic, but there is nothing to check it against. Proves who said it, not that it is right. | **2** |
| `invalido` | The signature does not verify, is missing, or belongs to another key. Do not trust. | **1** |

`firmado_sin_procedencia` being its own state rather than a failure is
deliberate: it is the most common state in practice and the one most often
mistaken for "verified".

### 6.1 What an envelope does NOT assert

**A `verificable` is a narrow claim, and stating its boundary is worth as much as
stating what it proves.** Without this, the verdict reads as a quality seal, and
it is not one.

A `verificable` envelope asserts exactly three things:

1. That **these bytes** were signed by whoever controls **this key**.
2. That the issuer **declared** which rule catalogue it checks against
   (`reglasHash`) and on what date it verified that regulation
   (`reglasVerificadasAl`).
3. That it recorded how it handled the data (`habeasData`).

**And it asserts none of these, however similar they look:**

- **Not that the calculation is correct.** It asserts the result is *derivable
  from the declared catalogue*. If that catalogue is wrong, the envelope is valid
  and the number is wrong — and the envelope hands you exactly what you need to
  prove it, which is the point.
- **Not which program walked the catalogue.** It names the catalogue
  (`reglasHash`), not the code that applied it. Two engines — one correct, one
  subtly wrong — produce envelopes **indistinguishable in provenance** as long as
  they cite the same catalogue. This is the sharpest edge on the list because
  **the previous point presupposes it**. Designed but not implemented; see §10.1
  of the Spanish spec.
- **Not that the declared catalogue is current.** `reglasVerificadasAl` is the
  date the issuer *said* it checked. An envelope signed today against two-year-old
  regulation verifies just the same. **Staleness is the verifier's call, not the
  issuer's.**
- **Nothing about line items of extra-legal origin.** Bonuses, commissions and
  negotiated items do not derive from a rule, so they are not verified: they are
  marked unverifiable rather than guessed. A `verificable` envelope may contain
  lines nobody checked, **and it says so**.
- **Not an accounting opinion or legal advice.**
- **Nothing about the issuer's infrastructure**: not that its server is secure,
  its data well kept, or the organization real. That is the territory of
  compliance attestations, and it is **a different problem**.
- **Not that the issuer is trustworthy.** A valid signature from a liar is a
  valid signature. What changes is that **their lie is now reproducible by a
  third party**.

> **Why this belongs in the spec and not in a legal disclaimer.** It is the same
> distinction that holds up the three verdicts: `firmado_sin_procedencia` exists
> because "it is signed" and "it is correct" are different things, and **the most
> dangerous state for a verification system is one that reads as more than it
> is.** A format that does not declare its boundary invites a registry to turn it
> into a badge.

---

## 7. Test vectors

For checking a new implementation without guessing. **The test key is published
on purpose — never use it in production.**

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

Expected `publicKeyId`: `b6b3aa455b1826e2e04402d4a695e40f`

### 7.1 The ASCII vector — necessary, not sufficient

Files: `vectores/sobre.json`, `vectores/canonico.txt`.

Canonical bytes: **251**. Note the reordering:

```
{"habeasData":{"persistidoEnBd":false,"procesadoPorLlmExterno":false},"reglasHash":"ca49edf08c164c80a1a178a0ef12feb93e6418b2a73da9809546eb7bacce229f","reglasVerificadasAl":"2026-07-16","resultados":[{"externalId":"T-1","valor":1234567}],"version":"1"}
```

Expected signature:

```
/evR5PJMg6b/n29bBeWpDAfllT7/a26y+A9Nt5lpmmu423zC7lWHGf1gECoLWDM7GoZHA8osiF/7PP77tAi7Aw==
```

If your canonical bytes match but your signature does not, the problem is key
handling. If the bytes do not match, the problem is §3 — and that is the failure
that makes two "correct" implementations unable to understand each other.

### 7.2 The unicode vector — the one that actually catches things

**The ASCII vector catches nothing.** If your implementation passes it you still
do not know whether it works: both traps below sail straight through.

Files: `vectores/sobre-unicode.json`, `vectores/canonico-unicode.txt`.

```
canonical bytes   525
key order         ["-nota", "0", "descripción", "habeasData", "montos",
                   "reglasHash", "reglasVerificadasAl", "señal", "version",
                   "Ａmpliación", "🐦canal"]
```

**The two pairs that matter, and why they are those:**

| Pair | What happens if you do it the JavaScript way |
|---|---|
| `"-nota"` before `"0"` | `-` is `0x2D` and `0` is `0x30`, so by bytes `-nota` comes first. But in JavaScript **integer-like keys hoist themselves to the front** of an object: if you rebuild the object and let the engine decide, `"0"` jumps to the start. You must **serialize by hand** |
| `"Ａmpliación"` before `"🐦canal"` | `Ａ` is U+FF21 (`0xEF…` in UTF-8) and `🐦` is U+1F426 (`0xF0…`). By bytes `Ａ` comes first; **by UTF-16 code units the emoji comes first**, because it is a surrogate pair starting at `0xD800`. This is exactly where [§3.1](#31-how-it-differs-from-jcs-rfc-8785-and-why) parts ways with JCS |

> **How this vector came to be, because the lesson is the valuable part.** It
> first shipped containing `ñ`, `—`, `€` and an emoji — and **a naive JavaScript
> implementation passed it whole**: the non-ASCII characters sat in positions
> where the first letter already decided the ordering, so they were never
> compared. A deliberately broken canonicalizer run through the conformance
> harness caught it.
>
> **A vector with exotic characters is not a vector that proves anything.** It
> has to contain the pairs where the two orderings *disagree*, and finding those
> takes deliberate work. That is the difference between looking thorough and
> being thorough.

---

## 8. Reference implementation

`sobre.rb`. No dependencies outside the Ruby standard library.

```bash
ruby sobre.rb verificar <envelope.json> --llave-url https://host/publickey
ruby sobre.rb verificar <envelope.json> --llave key.pem --json
```

**Signing** — what you need to adopt the format. It writes to stdout, so it
chains:

```bash
ruby sobre.rb firmar document.json --llave-privada key.pem | ruby sobre.rb verificar -
```

If the document is missing `reglasHash`, `reglasVerificadasAl` or `habeasData`,
the signer **warns on `stderr`** that the envelope will come out as
`firmado_sin_procedencia` rather than `verificable`. It signs anyway — that is a
legal state of the format ([§6](#6-the-three-verdicts)) — but emitting one
unknowingly is the easiest mistake to make and the hardest to notice later.

`publicKeyId` is **derived** from the private key rather than taken as an
argument, so an emitter cannot declare an id that does not match the key it
signed with. That is precisely the attack the verifier's key-declaration check
exists to catch; making it unrepresentable beats detecting it.

### 8.1 Checking a new implementation

`conformidad.rb` runs **your** implementation against the vectors. No need to
contact anyone or ask permission:

```bash
ruby conformidad.rb --canonicalizador "node canon.js"
ruby conformidad.rb --verificador     "python3 verify.py"
ruby conformidad.rb --firmador        "go run sign.go"
```

The contract with your command is deliberately minimal — `stdin`, `stdout`, exit
code — so it can be met in any language without adopting any convention of ours:

| Mode | Receives on `stdin` | Must respond |
|---|---|---|
| `--canonicalizador` | a JSON document | the canonical bytes of [§3](#3-canonical-form) on `stdout` |
| `--verificador` | a JSON envelope | exit `0` **only** if the verdict is `verificable` |
| `--firmador` | a JSON document | the signed envelope on `stdout`, using the key in `vectores/` |

**Start with `--canonicalizador`.** That is where implementations really diverge:
a broken verifier is noticeable, but a different canonicalization produces
signatures that *look* valid to whoever signs and fail for everyone else.

When it fails it does not say "mismatch": it names the exact byte of the first
divergence and, if it is one of the two known causes, **which one**:

```
[FALLA ] vector unicode: produce los bytes canónicos exactos
          primera divergencia en el byte 2
            esperado: …"{\"-nota\":\"ordena antes de 0 por bytes…
            obtenido: …"{\"0\":\"clave tipo entero: JavaScript…
            → you hoisted the "0" key to the front. In JavaScript integer-like
              keys reorder themselves: you must SERIALIZE by hand …
```

The verifier is checked mostly with **negative** cases — a tampered envelope, an
unsigned one, one carrying an authentic signature from a different key, and one
signed but missing `reglasHash` — because accepting the two good vectors is also
something a program that says yes to everything does.

> **The negative cases are skipped if your verifier cannot accept a valid
> envelope**, and that is not a convenience. The contract is an exit code, so
> *"I rejected it"* and *"I failed to run"* are indistinguishable: a command that
> does not exist rejects everything, and used to pass all four rejection checks —
> a broken verifier scored 4 out of 6 and whoever read that believed they were
> nearly done.
>
> It was found by someone copying these commands with the example filenames
> as-is, which is anyone's first attempt. **If you cannot accept a good envelope,
> your rejection proves nothing**, and saying so beats counting it as a pass.

---

## 9. Why it's free

A verification format used by a single vendor is worth nothing. The value appears
when a buyer can verify **anyone** — and that only happens if the format is a
standard. Charging for it guarantees it never becomes one.

The moat is not the format: it is the rule catalogue and the legal engine behind
it. Giving the envelope away makes us the reference implementation of the rail we
also sell on.

Released under CC0. No attribution required, no conditions. A standard with
licence friction does not get adopted.

---

## 10. What's missing

| What | Why it matters |
|---|---|
| ~~TypeScript implementation~~ | **Done, as plain JavaScript.** `sobre.mjs` — Node 18+, zero dependencies, no build step. Verifies, signs and canonicalizes; usable as a library and as a CLI. It passes `conformidad.rb` in all three modes and **produces byte-identical signatures** to the Ruby reference. Plain `.mjs` was chosen over TypeScript deliberately: a standard that needs `npm install`, a `tsconfig` and a build to be checked puts a barrier exactly where it shouldn't — it still type-checks with `tsc --checkJs --noEmit` |
| Derive `publicKeyId` from raw key bytes (v2) | Removes the serialization ambiguity that normalization currently papers over |
| **Identity of the program that signed** | The envelope binds the bytes, the key and the catalogue — **not the code**. Two engines citing the same `reglasHash` are indistinguishable in provenance. Designed, not implemented; the full design and the argument for waiting are in §10.1 of the Spanish spec |
