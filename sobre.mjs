#!/usr/bin/env node
// Implementación del sobre en JavaScript, para Node 18+.
//
//     node sobre.mjs verificar <sobre.json> --llave <llave.pem>
//     node sobre.mjs firmar <documento.json> --llave-privada <llave.pem>
//     node sobre.mjs llave-id <llave.pem>
//     node sobre.mjs canonicalizar <documento.json>
//
// `-` en vez del archivo lee de la entrada estándar, así que encadena:
//
//     node sobre.mjs firmar doc.json --llave-privada k.pem | node sobre.mjs verificar -
//
// ── Por qué existe ─────────────────────────────────────────────────────────
//
// Un formato con una sola implementación es un formato de un solo vendedor.
// Que dos programas independientes produzcan los MISMOS bytes es la evidencia
// —la única— de que la especificación se puede implementar leyéndola. Ruby es
// la referencia; esto es la contraparte en el lenguaje que usa quien escribe
// agentes, que es de donde va a venir cualquier adoptante.
//
// No reemplaza a `web/index.html`: aquél corre en el navegador con WebCrypto,
// no puede firmar y no se puede importar. Éste sirve como librería y como CLI.
//
// ── Cero dependencias, y sin paso de compilación ───────────────────────────
//
// JavaScript plano en un solo archivo, con `node:crypto` de la stdlib. Un
// estándar que para comprobarse pide `npm install`, un `tsconfig` y un build
// pone una barrera justo donde no debe. Se puede type-checkear con
// `tsc --checkJs --noEmit sobre.mjs` sin instalar nada del proyecto.
//
// ── Las dos trampas de JavaScript, que este archivo existe para no pisar ────
//
// Están documentadas en el §7 de la spec y las dos las cazó el vector unicode:
//
//   1. Las claves tipo entero ("0", "1") se reordenan solas al frente de un
//      objeto. Por eso se SERIALIZA A MANO en vez de reconstruir el objeto y
//      dejar que `JSON.stringify` decida.
//   2. `.sort()` ordena por unidades UTF-16, y el §3 exige bytes UTF-8.
//      Divergen a partir de U+10000. Por eso hay un comparador propio.

import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";

const enc = new TextEncoder();

// ── §3 Forma canónica ──────────────────────────────────────────────────────

/** Compara dos claves por sus bytes UTF-8, no por unidades UTF-16. */
export function compararUtf8(a, b) {
  const A = enc.encode(a);
  const B = enc.encode(b);
  const n = Math.min(A.length, B.length);
  for (let i = 0; i < n; i++) if (A[i] !== B[i]) return A[i] - B[i];
  return A.length - B.length;
}

/**
 * Un documento que no se puede canonicalizar de forma interoperable. Mismo
 * criterio que la referencia en Ruby: se lanza al firmar y al verificar.
 */
export class ErrorDeCanonicalizacion extends Error {
  constructor(mensaje) {
    super(mensaje);
    this.name = "ErrorDeCanonicalizacion";
  }
}

// Techo de los enteros: 2^53 - 1. Arriba de eso JavaScript ya no puede leer el
// número sin redondearlo —`JSON.parse("9007199254740993")` devuelve ...992— así
// que la firma dejaría de coincidir con la de Ruby SIN QUE NADA AVISE.
const ENTERO_MAXIMO = Number.MAX_SAFE_INTEGER;

// Los decimales se rechazan en vez de especificarse. Cada lenguaje serializa
// los flotantes distinto: medido entre estas dos implementaciones, `1.0` sale
// `1.0` en Ruby y `1` en JS, y `-0.0` sale `-0.0` y `0`. Bytes distintos =
// firmas distintas. Ver el comentario largo en `sobre.rb` para el porqué de
// rechazar en vez de adoptar la serialización de ECMAScript.
function numeroSeguro(n) {
  if (!Number.isInteger(n)) {
    throw new ErrorDeCanonicalizacion(
      `los decimales no son representables de forma interoperable (${n}). ` +
        "Codificá en la unidad mínima (centavos) o como string.",
    );
  }
  if (Math.abs(n) > ENTERO_MAXIMO) {
    throw new ErrorDeCanonicalizacion(
      `entero fuera del rango seguro (|n| > 2^53-1): ${n}. JavaScript no puede ` +
        "leerlo sin redondear, así que la firma no sería interoperable.",
    );
  }
  return n;
}

/** Los bytes canónicos del §3: sin `signature`, sin nulos, claves ordenadas. */
export function bytesCanonicos(v) {
  if (v === null || v === undefined) return "null";
  if (typeof v === "number") return JSON.stringify(numeroSeguro(v));
  if (Array.isArray(v)) return "[" + v.map(bytesCanonicos).join(",") + "]";
  if (typeof v === "object") {
    const claves = Object.keys(v)
      .filter((k) => k !== "signature" && v[k] !== null && v[k] !== undefined)
      .sort(compararUtf8);
    return "{" + claves.map((k) => JSON.stringify(k) + ":" + bytesCanonicos(v[k])).join(",") + "}";
  }
  return JSON.stringify(v);
}

// ── §4 Llave y firma ───────────────────────────────────────────────────────

/** §4: base64 en líneas de 64, sin espacios sueltos. El id sale de ESTE texto. */
export function normalizarPem(pem) {
  const cuerpo = pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "");
  return (
    "-----BEGIN PUBLIC KEY-----\n" +
    (cuerpo.match(/.{1,64}/g) || []).join("\n") +
    "\n-----END PUBLIC KEY-----\n"
  );
}

export function idDeLlave(pem) {
  return createHash("sha256").update(normalizarPem(pem), "utf8").digest("hex").slice(0, 32);
}

/**
 * Firma un documento. El `publicKeyId` se DERIVA de la llave privada en vez de
 * aceptarse como parámetro: así el emisor no puede declarar un id que no
 * corresponde a la llave con la que firmó, que es el ataque que la
 * comprobación de procedencia caza del otro lado.
 */
export function firmar(doc, pemPrivado) {
  const sk = createPrivateKey(pemPrivado);
  const pub = createPublicKey(sk).export({ type: "spki", format: "pem" });
  const bytes = bytesCanonicos(doc);
  const { signature, ...resto } = doc;
  return {
    ...resto,
    signature: {
      algo: "ed25519",
      valor: sign(null, Buffer.from(bytes, "utf8"), sk).toString("base64"),
      publicKeyId: idDeLlave(pub),
      cubreCampos: "todos_menos_signature",
      canonical: "sorted_keys_utf8_json",
    },
  };
}

/** Lo que le falta al documento para llegar a `verificable` (§6). */
export function faltantesParaProcedencia(doc) {
  return ["reglasHash", "reglasVerificadasAl", "habeasData"].filter((c) => !(c in doc));
}

// ── §6 Veredicto ───────────────────────────────────────────────────────────

export function analizar(doc, pem) {
  const checks = [];
  const add = (id, critico, ok, detalle) => checks.push({ id, critico, ok, detalle });

  const firma = doc?.signature?.valor;
  add("sobre.firma_presente", true, Boolean(firma), `algo=${doc?.signature?.algo ?? "—"}`);

  let firmaOk = false;
  if (firma && pem) {
    try {
      firmaOk = verify(
        null,
        Buffer.from(bytesCanonicos(doc), "utf8"),
        createPublicKey(pem),
        Buffer.from(firma, "base64"),
      );
    } catch {
      firmaOk = false;
    }
  }
  add("sobre.firma_verifica", true, firmaOk, "Ed25519 sobre el JSON canónico");

  if (pem) {
    const id = idDeLlave(pem);
    add("sobre.llave_declarada", true, doc?.signature?.publicKeyId === id,
        `publicKeyId ${doc?.signature?.publicKeyId ?? "—"} vs ${id}`);
  }

  // No críticos: su ausencia no invalida la firma, baja el veredicto a
  // `firmado_sin_procedencia`. Es la distinción del §6.
  for (const campo of ["reglasHash", "reglasVerificadasAl", "habeasData"]) {
    add(`sobre.${campo}`, false, campo in doc, campo in doc ? "presente" : `falta ${campo}`);
  }
  return checks;
}

export function veredicto(checks) {
  if (checks.some((c) => c.critico && !c.ok)) return "invalido";
  return checks.every((c) => c.ok) ? "verificable" : "firmado_sin_procedencia";
}

export const SALIDA = { verificable: 0, invalido: 1, firmado_sin_procedencia: 2 };

// ── CLI ────────────────────────────────────────────────────────────────────

function leer(ruta) {
  const crudo = ruta === "-" ? readFileSync(0, "utf8") : readFileSync(ruta, "utf8");
  return JSON.parse(crudo);
}

function uso() {
  process.stderr.write(
    [
      "sobre — implementacion en JavaScript (Node 18+, sin dependencias)",
      "",
      "  node sobre.mjs verificar <sobre.json> [--llave a.pem]",
      "  node sobre.mjs firmar <documento.json> --llave-privada k.pem",
      "  node sobre.mjs llave-id <llave.pem>",
      "  node sobre.mjs canonicalizar <documento.json>",
      "",
      "`-` lee de la entrada estandar. Salida de verificar:",
      "  0 verificable · 1 firma invalida · 2 firmado sin procedencia",
      "",
    ].join("\n"),
  );
  process.exit(64);
}

function opcion(nombre) {
  const i = process.argv.indexOf(nombre);
  return i === -1 ? null : process.argv[i + 1];
}

// Solo cuando se ejecuta directo: importarlo como librería no debe correr nada.
if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split("/").pop())) {
  const cmd = process.argv[2];
  const archivo = process.argv[3];

  if (cmd === "canonicalizar") {
    if (!archivo) uso();
    process.stdout.write(bytesCanonicos(leer(archivo)));
  } else if (cmd === "llave-id") {
    if (!archivo) uso();
    process.stdout.write(idDeLlave(readFileSync(archivo, "utf8")) + "\n");
  } else if (cmd === "firmar") {
    const priv = opcion("--llave-privada");
    if (!archivo || !priv) uso();
    const doc = leer(archivo);
    const faltan = faltantesParaProcedencia(doc);
    if (faltan.length) {
      // A stderr, para no contaminar el JSON de la tubería.
      process.stderr.write(
        `  aviso: firmado, pero le falta ${faltan.join(", ")} — va a verificar\n` +
          "         como `firmado_sin_procedencia`, no como `verificable` (§6).\n",
      );
    }
    process.stdout.write(JSON.stringify(firmar(doc, readFileSync(priv, "utf8"))) + "\n");
  } else if (cmd === "verificar") {
    if (!archivo) uso();
    const rutaLlave = opcion("--llave");
    const pem = rutaLlave ? readFileSync(rutaLlave, "utf8") : null;
    const checks = analizar(leer(archivo), pem);
    const v = veredicto(checks);
    for (const c of checks) {
      process.stderr.write(`  [${c.ok ? "OK    " : "FALLA "}] ${c.id.padEnd(28)} ${c.detalle}\n`);
    }
    process.stderr.write(`\n${v.toUpperCase()}\n`);
    process.exit(SALIDA[v]);
  } else {
    uso();
  }
}
