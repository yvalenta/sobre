#!/usr/bin/env ruby
# frozen_string_literal: true

# Pruebas de `sobre.rb`. Existen por una razon: un verificador que siempre
# dice OK se ve identico a uno que funciona, hasta que alguien lo ataca. Estas
# pruebas son casi todas NEGATIVAS — comprueban que sabe rechazar.
#
#   ruby scripts/sobre_test.rb

require "json"
require "openssl"
require "base64"
require_relative "sobre"

@fallos = 0
@corridas = 0

def prueba(nombre)
  @corridas += 1
  ok = yield
  @fallos += 1 unless ok
  puts "  [#{ok ? "OK    " : "FALLA "}] #{nombre}"
end

def firmar(doc, sk, pem)
  bytes = Sobre.bytes_canonicos(doc)
  doc.merge("signature" => {
              "algo" => "ed25519",
              "valor" => Base64.strict_encode64(sk.sign(nil, bytes)),
              "publicKeyId" => Sobre.id_de_llave(pem),
              "cubreCampos" => "todos_menos_signature",
              "canonical" => "sorted_keys_utf8_json"
            })
end

sk = OpenSSL::PKey.generate_key("ED25519")
pem = sk.public_to_pem
pk = OpenSSL::PKey.read(pem)

otra = OpenSSL::PKey.generate_key("ED25519")
pk_otra = OpenSSL::PKey.read(otra.public_to_pem)

COMPLETO = {
  "version" => "1",
  "reglasHash" => "ca49edf08c164c80a1a178a0ef12feb93e6418b2a73da9809546eb7bacce229f",
  "reglasVerificadasAl" => "2026-07-16",
  "habeasData" => { "persistidoEnBd" => false, "procesadoPorLlmExterno" => false },
  "resultados" => [{ "externalId" => "T-1", "valor" => 1_234_567 }]
}.freeze

MINIMO = { "version" => "1", "resultados" => [{ "valor" => 42 }] }.freeze

puts "Pruebas de sobre.rb\n\n"

puts "positivas"
completo = firmar(COMPLETO.dup, sk, pem)
prueba("un sobre completo y bien firmado es VERIFICABLE") do
  Sobre.veredicto(Sobre.analizar(completo, pk, pem)) == "verificable"
end

puts "\nnegativas — la firma"
prueba("alterar un numero invalida la firma") do
  roto = JSON.parse(JSON.generate(completo))
  roto["resultados"][0]["valor"] += 1
  Sobre.veredicto(Sobre.analizar(roto, pk, pem)) == "invalido"
end

prueba("alterar un texto invalida la firma") do
  roto = JSON.parse(JSON.generate(completo))
  roto["reglasHash"] = roto["reglasHash"].sub(/.$/, "0")
  Sobre.veredicto(Sobre.analizar(roto, pk, pem)) == "invalido"
end

prueba("AGREGAR un campo invalida la firma") do
  roto = JSON.parse(JSON.generate(completo))
  roto["montoExtra"] = 999
  Sobre.veredicto(Sobre.analizar(roto, pk, pem)) == "invalido"
end

prueba("BORRAR un campo invalida la firma") do
  roto = JSON.parse(JSON.generate(completo))
  roto.delete("reglasVerificadasAl")
  Sobre.veredicto(Sobre.analizar(roto, pk, pem)) == "invalido"
end

prueba("verificar con OTRA llave falla") do
  Sobre.veredicto(Sobre.analizar(completo, pk_otra, otra.public_to_pem)) == "invalido"
end

prueba("una firma valida de OTRA llave no pasa por la declarada") do
  # El ataque real: firmo de verdad, pero con una llave que no es la que el
  # documento dice. La firma verifica; lo que falla es la procedencia.
  suplantado = firmar(COMPLETO.dup, otra, otra.public_to_pem)
  suplantado["signature"]["publicKeyId"] = Sobre.id_de_llave(pem)
  checks = Sobre.analizar(suplantado, pk_otra, otra.public_to_pem)
  checks.find { |c| c[:id] == "sobre.llave_declarada" }&.fetch(:ok) == false
end

prueba("un documento sin firma es invalido") do
  Sobre.veredicto(Sobre.analizar(COMPLETO.dup, pk, pem)) == "invalido"
end

puts "\nnegativas — la procedencia (firma valida, sobre incompleto)"
minimo = firmar(MINIMO.dup, sk, pem)
prueba("firmado sin reglasHash NO es verificable") do
  Sobre.veredicto(Sobre.analizar(minimo, pk, pem)) == "firmado_sin_procedencia"
end

prueba("...y el motivo se nombra: falta reglasHash") do
  c = Sobre.analizar(minimo, pk, pem).find { |x| x[:id] == "sobre.reglas_hash" }
  c[:ok] == false && c[:detalle].include?("reglasHash")
end

prueba("...pero su firma SI verifica — no se confunde con invalido") do
  Sobre.analizar(minimo, pk, pem).find { |x| x[:id] == "sobre.firma_verifica" }[:ok] == true
end

sin_habeas = firmar(COMPLETO.reject { |k, _| k == "habeasData" }, sk, pem)
prueba("firmado sin habeasData tampoco es verificable") do
  Sobre.veredicto(Sobre.analizar(sin_habeas, pk, pem)) == "firmado_sin_procedencia"
end

puts "\ncanonicalizacion"
prueba("el orden de las claves no cambia los bytes") do
  a = { "b" => 1, "a" => { "z" => 2, "y" => 3 } }
  b = { "a" => { "y" => 3, "z" => 2 }, "b" => 1 }
  Sobre.bytes_canonicos(a) == Sobre.bytes_canonicos(b)
end

prueba("un campo en null pesa igual que uno ausente") do
  Sobre.bytes_canonicos({ "a" => 1, "b" => nil }) == Sobre.bytes_canonicos({ "a" => 1 })
end

prueba("la firma nunca se cubre a si misma") do
  Sobre.bytes_canonicos({ "a" => 1, "signature" => { "valor" => "x" } }) ==
    Sobre.bytes_canonicos({ "a" => 1 })
end

prueba("firmar es estable: los mismos datos dan los mismos bytes") do
  Sobre.bytes_canonicos(COMPLETO) == Sobre.bytes_canonicos(JSON.parse(JSON.generate(COMPLETO)))
end

puts "\nid de llave"
prueba("el id de llave es sha256(pem)[0,32]") do
  Sobre.id_de_llave(pem) == Digest::SHA256.hexdigest(pem)[0, 32]
end

prueba("dos llaves distintas dan ids distintos") do
  Sobre.id_de_llave(pem) != Sobre.id_de_llave(otra.public_to_pem)
end

# El id se deriva del TEXTO del PEM, que es una serializacion. Sin normalizar,
# la misma llave guardada por otra herramienta da otro id y la verificacion
# falla aunque todo este bien. Encontrado el 2026-07-26 con un `curl >` que
# agrego un solo \n.
prueba("un salto de linea de mas no cambia el id") do
  Sobre.id_de_llave(pem) == Sobre.id_de_llave("#{pem}\n")
end

prueba("sin salto final tampoco lo cambia") do
  Sobre.id_de_llave(pem) == Sobre.id_de_llave(pem.strip)
end

prueba("CRLF de Windows tampoco lo cambia") do
  Sobre.id_de_llave(pem) == Sobre.id_de_llave(pem.gsub("\n", "\r\n"))
end

prueba("otro ancho de linea tampoco lo cambia") do
  b64 = pem.gsub(/-----[A-Z ]+-----/, "").gsub(/\s+/, "")
  suelto = "-----BEGIN PUBLIC KEY-----\n#{b64.scan(/.{1,40}/).join("\n")}\n-----END PUBLIC KEY-----\n"
  Sobre.id_de_llave(pem) == Sobre.id_de_llave(suelto)
end

prueba("normalizar es idempotente") do
  n = Sobre.normalizar_pem(pem)
  Sobre.normalizar_pem(n) == n
end

puts "\nvectores publicados (vectores/)"
# Los vectores del SPEC viven tambien como archivos, y esta seccion los lee de
# ahi. Sin esto la implementacion puede cambiar y los vectores quedar viejos sin
# que nada avise — y un vector viejo es peor que ninguno: manda a quien
# implementa a cazar un bug que no existe.
VEC = File.expand_path("vectores", __dir__)

prueba("el canonico publicado es el que produce la implementacion") do
  Sobre.bytes_canonicos(Sobre.cargar(File.join(VEC, "sobre.json"))) ==
    File.read(File.join(VEC, "canonico.txt"), encoding: "UTF-8")
end

prueba("el canonico publicado mide 251 bytes") do
  File.size(File.join(VEC, "canonico.txt")) == 251
end

prueba("el id de la llave publicada es b6b3aa45...") do
  Sobre.id_de_llave(File.read(File.join(VEC, "llave-publica.pem"))) ==
    "b6b3aa455b1826e2e04402d4a695e40f"
end

prueba("el sobre publicado verifica con la llave publicada") do
  doc = Sobre.cargar(File.join(VEC, "sobre.json"))
  pem = File.read(File.join(VEC, "llave-publica.pem"))
  Sobre.veredicto(Sobre.analizar(doc, OpenSSL::PKey.read(pem), pem)) == "verificable"
end

prueba("la llave privada de pruebas reproduce esa firma exacta") do
  sk = OpenSSL::PKey.read(File.read(File.join(VEC, "llave-privada-SOLO-PRUEBAS.pem")))
  bytes = File.read(File.join(VEC, "canonico.txt"), encoding: "UTF-8")
  doc = Sobre.cargar(File.join(VEC, "sobre.json"))
  Base64.strict_encode64(sk.sign(nil, bytes)) == doc["signature"]["valor"]
end

# ── El vector unicode, que es el unico que atrapa algo ──────────────────────
#
# Todo lo de arriba usa el vector ASCII, y el propio §7 dice que ese "no prueba
# lo dificil": una implementacion con las dos trampas de JavaScript lo pasa
# entero. Hasta el 2026-08-09 el vector dificil existia SOLO como prosa en la
# spec — quien implementaba bajaba los vectores, le pasaban todos, y se llevaba
# los dos bugs que la spec dedica media seccion a advertir.
UNI = File.join(VEC, "sobre-unicode.json")

prueba("el sobre unicode publicado verifica con la llave publicada") do
  doc = Sobre.cargar(UNI)
  pem = File.read(File.join(VEC, "llave-publica.pem"))
  Sobre.veredicto(Sobre.analizar(doc, OpenSSL::PKey.read(pem), pem)) == "verificable"
end

prueba("el canonico unicode publicado es el que produce la implementacion") do
  # Rojo aca significa una de dos, y las dos son noticia: o cambio la
  # canonicalizacion —y entonces se invalidaron todas las firmas ya emitidas,
  # ver §3.1— o el .txt quedo viejo.
  Sobre.bytes_canonicos(Sobre.cargar(UNI)) ==
    File.read(File.join(VEC, "canonico-unicode.txt"), encoding: "UTF-8")
end

prueba("el canonico unicode mide 525 bytes") do
  File.size(File.join(VEC, "canonico-unicode.txt")) == 525
end

# Las dos pruebas de abajo afirman que el vector SIGUE DISPARANDO las trampas.
# No son paranoia: la primera version de este vector tenia ñ, €, — y un emoji, y
# aun asi una implementacion ingenua de JavaScript la pasaba entera — los
# caracteres raros estaban en posiciones donde la primera letra ya decidia el
# orden. Lo descubrio `conformidad.rb` corriendo contra un canonicalizador roto
# a proposito, no una relectura.
#
# Un vector que no dispara nada es peor que no tener vector: da confianza.

prueba("el vector dispara la trampa de la clave tipo entero") do
  # JavaScript sube "0" al frente de un objeto sin importar el orden de
  # insercion. Para que eso DIVERGA hace falta una clave que ordene antes que
  # "0" por bytes: "-" es 0x2D y "0" es 0x30.
  claves = Sobre.canonicalizar(Sobre.cargar(UNI)).keys
  claves[0] == "-nota" && claves[1] == "0"
end

prueba("el vector dispara la trampa del orden UTF-16") do
  # U+FF21 (BMP alto) contra U+1F426 (sobre U+10000, par suplente en UTF-16).
  # Por bytes UTF-8 va primero la Ａ (0xEF < 0xF0); por unidades UTF-16 va
  # primero el emoji (0xD83D < 0xFF21). Es el punto exacto del §3.1.
  claves = Sobre.canonicalizar(Sobre.cargar(UNI)).keys
  claves.index("Ａmpliación") < claves.index("🐦canal")
end

# ── Entrada estandar: verificar en una tuberia, sin tocar el disco ───────────

prueba("`-` lee de la entrada estandar y da el mismo documento que el archivo") do
  ruta = File.join(VEC, "sobre.json")
  esperado = Sobre.cargar(ruta)
  leido = nil
  IO.pipe do |r, w|
    w.write(File.read(ruta, encoding: "UTF-8"))
    w.close
    original = $stdin
    $stdin = r
    begin
      leido = Sobre.cargar("-")
    ensure
      $stdin = original
    end
  end
  leido == esperado
end

prueba("un sobre con tildes sobrevive a la tuberia sin romper la firma") do
  # El locale de la maquina puede dar US-ASCII, y entonces `$stdin.read` marca
  # los bytes con esa codificacion. Un JSON con tildes canonicaliza distinto y
  # la firma deja de verificar — sin error visible, solo un veredicto falso.
  ruta = File.join(VEC, "sobre.json")
  pem = File.read(File.join(VEC, "llave-publica.pem"))
  leido = nil
  IO.pipe do |r, w|
    w.write(File.read(ruta, encoding: "UTF-8"))
    w.close
    r.set_encoding("US-ASCII")
    original = $stdin
    $stdin = r
    begin
      leido = Sobre.cargar("-")
    ensure
      $stdin = original
    end
  end
  Sobre.veredicto(Sobre.analizar(leido, OpenSSL::PKey.read(pem), pem)) == "verificable"
end

# ── Las specs no pueden mentir sobre los vectores ───────────────────────────
#
# Hay DOS documentos normativos —SPEC.md en español y SPEC.en.md en inglés— y
# los dos citan cifras concretas: cuántos bytes mide cada canónico, el
# publicKeyId, la firma esperada, el orden de claves.
#
# La tentación es guardar "que digan lo mismo entre sí". Es inmantenible: son
# textos distintos en idiomas distintos y cualquier reescritura de una frase
# daría rojo. Lo que sí se puede vigilar —y es lo único que importa— es que
# **las dos coincidan con los archivos de `vectores/`**, que son la fuente real.
#
# Traducir una spec agrega un segundo lugar donde desincronizarse; esto es la
# guarda que esa decisión exigía.
# ── Numeros: el bug de interoperabilidad del 2026-08-10 ────────────────────
#
# Ruby conserva la distincion entero/decimal y JavaScript no: despues del parse,
# en JS `1.0` y `1` son el mismo valor. Antes de esto, Ruby emitia `1.0` donde JS
# emitia `1` — bytes distintos, firmas distintas, y un sobre emitido en Ruby NO
# verificaba contra un verificador en JS. Estaba escondido porque todos los
# vectores usaban enteros.
#
# La regla: si el numero VALE un entero se emite como entero; un decimal de
# verdad se rechaza. Es lo unico que las dos implementaciones pueden cumplir.
puts "\nnumeros interoperables"

prueba("un entero disfrazado de decimal se normaliza") do
  # 1.0, 1e3 y -0.0 son lo que JS ya produce; Ruby tiene que llegar al mismo lado.
  Sobre.bytes_canonicos({ "v" => 1.0 }) == '{"v":1}' &&
    Sobre.bytes_canonicos({ "v" => 1e3 }) == '{"v":1000}' &&
    Sobre.bytes_canonicos({ "v" => -0.0 }) == '{"v":0}'
end

prueba("un decimal de verdad se emite, no se rechaza") do
  # Esta prueba afirmaba lo CONTRARIO hasta el 2026-08-10, y la version que
  # rechazaba rompio produccion: la entrega real trae `baseGravableUvt: 105.4`.
  Sobre.bytes_canonicos({ "v" => 0.1 }) == '{"v":0.1}' &&
    Sobre.bytes_canonicos({ "v" => 105.4 }) == '{"v":105.4}' &&
    Sobre.bytes_canonicos({ "v" => 127.96 }) == '{"v":127.96}' &&
    Sobre.bytes_canonicos({ "v" => 3.14159 }) == '{"v":3.14159}'
end

prueba("se emiten los digitos MAS CORTOS que round-trippean") do
  # El caso que delato el diagnostico: con la gema `json` 2.21.1 este double sale
  # `26331.157329999998` de `JSON.generate` y `26331.15733` de JavaScript. Mismo
  # numero, distinto texto, distinta firma.
  #
  # La prueba NO afirma lo que hace `JSON.generate`, a proposito: se escribio asi
  # primero y se puso roja en CI, donde una version distinta de la gema no tiene
  # el defecto. Afirmar el defecto de una dependencia hace que la guarda mida la
  # version instalada en vez de la propiedad. Lo que se exige es la propiedad, que
  # es cierta en toda version y en todo lenguaje: los digitos emitidos vuelven al
  # mismo double, y ninguno mas corto lo hace.
  v = JSON.parse("[2.633115733e4]")[0]
  emitido = Sobre.bytes_canonicos({ "v" => v })[/:(.*)\}/, 1]

  vuelve = emitido.to_f == v
  digitos = emitido.delete("-.").sub(/\A0+/, "").length
  ninguno_mas_corto = (1...digitos).none? { |p| format("%.#{p}g", v).to_f == v }

  emitido == "26331.15733" && vuelve && ninguno_mas_corto
end

prueba("un decimal abajo de 1e-6 se RECHAZA") do
  # Unica banda irreconciliable: JS pasa a exponencial (`1e-7`) y Ruby imprime
  # plano (`0.0000001`). Firmar algo que el otro lado no reproduce es peor que
  # no firmar.
  [1e-7, 5e-9, -1e-7].all? do |f|
    Sobre.bytes_canonicos({ "v" => f })
    false
  rescue Sobre::ErrorDeCanonicalizacion
    true
  end
end

prueba("1e-6 justo en el borde SI se emite") do
  # El borde se afirma en los dos sentidos: una guarda que solo prueba el lado
  # que rechaza no distingue "corta donde debe" de "corta de mas".
  Sobre.bytes_canonicos({ "v" => 1e-6 }) == '{"v":0.000001}'
end

prueba("un entero sobre 2^53-1 se RECHAZA") do
  # JavaScript no puede leerlo sin redondear: JSON.parse("9007199254740993")
  # devuelve ...992. La firma dejaria de coincidir sin que nada avise.
  Sobre.bytes_canonicos({ "v" => 9_007_199_254_740_993 })
  false
rescue Sobre::ErrorDeCanonicalizacion
  true
end

prueba("el ultimo entero seguro SI pasa") do
  # El borde exacto importa: uno menos y estariamos rechazando cosas validas.
  Sobre.bytes_canonicos({ "v" => 9_007_199_254_740_991 }) == '{"v":9007199254740991}'
end

prueba("la regla se aplica anidada, no solo en la raiz") do
  # Un numero escondido en un array adentro de un objeto se canonicaliza igual
  # —y uno de la banda prohibida tiene que doler igual de hondo—.
  emitido = Sobre.bytes_canonicos({ "a" => { "b" => [1, { "c" => 0.5 }] } }) ==
            '{"a":{"b":[1,{"c":0.5}]}}'
  rechazado = begin
    Sobre.bytes_canonicos({ "a" => { "b" => [1, { "c" => 1e-9 }] } })
    false
  rescue Sobre::ErrorDeCanonicalizacion
    true
  end
  emitido && rechazado
end

puts "\nlas specs contra los vectores"

CANONICO = File.read(File.join(VEC, "canonico.txt"), encoding: "UTF-8")
FIRMA_ASCII = Sobre.cargar(File.join(VEC, "sobre.json")).dig("signature", "valor")
KEY_ID = Sobre.id_de_llave(File.read(File.join(VEC, "llave-publica.pem")))
ORDEN_UNICODE = Sobre.canonicalizar(Sobre.cargar(UNI)).keys

%w[SPEC.md SPEC.en.md].each do |archivo|
  ruta = File.join(__dir__, archivo)
  texto = File.read(ruta, encoding: "UTF-8")

  prueba("#{archivo}: trae los bytes canónicos ASCII exactos") do
    texto.include?(CANONICO)
  end

  prueba("#{archivo}: trae la firma ASCII esperada") do
    texto.include?(FIRMA_ASCII)
  end

  prueba("#{archivo}: declara el publicKeyId de la llave entregada") do
    texto.include?(KEY_ID)
  end

  prueba("#{archivo}: los dos tamaños que afirma son los reales") do
    # Se buscan como palabra suelta para no enganchar un 251 dentro de otra cifra.
    [CANONICO.bytesize, File.size(File.join(VEC, "canonico-unicode.txt"))]
      .all? { |n| texto.match?(/\b#{n}\b/) }
  end

  prueba("#{archivo}: el orden de claves que publica es el real") do
    # El listado va partido en varias líneas dentro de un bloque; se compara la
    # secuencia de nombres, no el formato.
    bloque = texto[/(?:orden de claves|key order)\s+\[(.*?)\]/m, 1]
    next false if bloque.nil?

    bloque.scan(/"([^"]*)"/).flatten == ORDEN_UNICODE
  end
end

puts
if @fallos.zero?
  puts "#{@corridas} pruebas, todas verdes."
  exit 0
else
  puts "#{@fallos} de #{@corridas} fallaron."
  exit 1
end
