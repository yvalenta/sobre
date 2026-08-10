#!/usr/bin/env ruby
# frozen_string_literal: true

# Comprueba una implementación AJENA del sobre contra los vectores.
#
#     ruby conformidad.rb --canonicalizador "node canon.js"
#     ruby conformidad.rb --verificador     "python3 verify.py"
#     ruby conformidad.rb --firmador        "go run sign.go"
#
# Se pueden combinar. Exit 0 si todo pasa, 1 si algo falla.
#
# ── Por qué existe ──────────────────────────────────────────────────────────
#
# El sobre solo sirve si dos implementaciones independientes producen los MISMOS
# bytes. Hasta el 2026-08-09, comprobar eso pedía escribirle a quien mantiene
# esto — o sea que la interoperabilidad dependía de una conversación. Un formato
# que necesita hablar con su autor para adoptarse no es un estándar.
#
# Esto invierte la carga: bajás el repo, corrés tu comando contra los vectores, y
# el resultado no lo interpreta nadie.
#
# ── El contrato con el comando externo ──────────────────────────────────────
#
# Deliberadamente mínimo — stdin/stdout/exit — para que se pueda cumplir en
# cualquier lenguaje sin librerías ni convenciones nuestras:
#
#   canonicalizador  stdin: un documento JSON   → stdout: los bytes canónicos (§3)
#   verificador      stdin: un sobre JSON       → exit 0 si es `verificable`
#   firmador         stdin: un documento JSON   → stdout: el sobre firmado (§4)
#                    con la llave de pruebas en vectores/
#
# ── Por qué el canonicalizador es el que más importa ────────────────────────
#
# Es donde divergen las implementaciones de verdad. Un verificador que falla se
# nota; una canonicalización distinta produce firmas que *parecen* válidas del
# lado de quien firma y no verifican del otro. El §3.1 y la validación cruzada
# del §7 existen por eso.

require "json"
require "open3"
require "base64"
require "openssl"
require_relative "sobre"

VEC = File.expand_path("vectores", __dir__)
PUB = File.read(File.join(VEC, "llave-publica.pem"))

@fallos = 0
@corridas = 0

def prueba(nombre)
  @corridas += 1
  ok, detalle = yield
  @fallos += 1 unless ok
  puts "  [#{ok ? "OK    " : "FALLA "}] #{nombre}#{detalle ? "\n              #{detalle}" : ""}"
end

# Corre el comando externo con `entrada` por stdin. Devuelve [stdout, exito?].
#
# `force_encoding` no es cosmetico y este runner es el peor lugar para
# olvidarlo: `capture3` devuelve la salida con la codificacion del locale, y sin
# LANG eso es US-ASCII. El primer byte del vector unicode revienta cualquier
# comparacion con "invalid byte sequence" — o sea que la herramienta escrita
# para probar unicode se cae con unicode, en la maquina de un tercero, y el
# error apunta a nuestro codigo y no al suyo.
def correr(cmd, entrada)
  salida, _err, estado = Open3.capture3(cmd, stdin_data: entrada)
  [salida.dup.force_encoding("UTF-8"), estado.success?]
rescue StandardError => e
  ["", false, e.message]
end

def vector(nombre) = File.read(File.join(VEC, nombre), encoding: "UTF-8")

def sin_firma(json)
  d = JSON.parse(json)
  d.delete("signature")
  JSON.generate(d)
end

# ── canonicalizador ─────────────────────────────────────────────────────────

def probar_canonicalizador(cmd)
  puts "\ncanonicalizador — `#{cmd}`"

  { "ASCII" => %w[sobre.json canonico.txt],
    "unicode" => %w[sobre-unicode.json canonico-unicode.txt] }.each do |etiqueta, (js, txt)|
    esperado = vector(txt)
    prueba("vector #{etiqueta}: produce los bytes canónicos exactos") do
      obtenido, ok = correr(cmd, sin_firma(vector(js)))
      obtenido = obtenido.sub(/\n\z/, "") # un \n final de `puts` no es divergencia
      next [false, "el comando falló"] unless ok
      next [true, nil] if obtenido == esperado

      # El diagnóstico es la mitad del valor: decir "no coincide" manda a
      # alguien a mirar 365 bytes a ojo.
      [false, diagnostico(obtenido, esperado)]
    end
  end
end

# Las dos causas que aparecen SIEMPRE, y las dos son de JavaScript. Nombrarlas
# es la diferencia entre "no coincide" —que manda a alguien a mirar 525 bytes a
# ojo— y "arreglá esto".
#
# El vector está construido para dispararlas: `"0"` contra `"-nota"`, y una
# clave sobre U+10000 contra una del BMP alto. Ver el §7.
def pista_conocida(obtenido, esperado)
  primera = ->(s) { s[/\{"([^"]*)"/, 1] }

  if primera.call(obtenido) == "0" && primera.call(esperado) != "0"
    "subiste la clave \"0\" al frente. En JavaScript las claves tipo entero se " \
      "reordenan solas: hay que SERIALIZAR a mano, no reconstruir el objeto y " \
      "dejar que el motor decida el orden (§7)"
  elsif [obtenido, esperado].all? { |s| s.include?("canal") && s.include?("mpliaci") } &&
        (obtenido.index("canal") <=> obtenido.index("mpliaci")) !=
        (esperado.index("canal") <=> esperado.index("mpliaci"))
    "ordenaste por unidades UTF-16 en vez de bytes UTF-8. Divergen a partir de " \
      "U+10000: el emoji es un par suplente (0xD83D) y queda antes que U+FF21 " \
      "en UTF-16, pero después en bytes (0xF0 > 0xEF). Es el §3.1"
  end
end

# Nombra la PRIMERA divergencia y, cuando puede, la causa conocida.
def diagnostico(obtenido, esperado)
  return "longitud #{obtenido.bytesize} vs #{esperado.bytesize} esperados" if obtenido.empty?

  i = (0...[obtenido.bytesize, esperado.bytesize].min).find { |n| obtenido.b[n] != esperado.b[n] }
  return "prefijo correcto pero longitud #{obtenido.bytesize} vs #{esperado.bytesize}" if i.nil?

  pista = pista_conocida(obtenido, esperado)
  ["primera divergencia en el byte #{i}",
   "  esperado: …#{esperado.b[[0, i - 20].max, 40].inspect}",
   "  obtenido: …#{obtenido.b[[0, i - 20].max, 40].inspect}",
   pista && "  → #{pista}"].compact.join("\n              ")
end

# ── verificador ─────────────────────────────────────────────────────────────

def probar_verificador(cmd)
  puts "\nverificador — `#{cmd}`"

  prueba("acepta el vector ASCII") { [correr(cmd, vector("sobre.json"))[1], nil] }
  prueba("acepta el vector unicode") { [correr(cmd, vector("sobre-unicode.json"))[1], nil] }

  # Las negativas son las que valen: un verificador que dice OK a todo pasa
  # las dos de arriba y no sirve para nada.
  prueba("RECHAZA un sobre con un valor alterado") do
    roto = vector("sobre-unicode.json").sub("1234567", "1234568")
    [!correr(cmd, roto)[1], nil]
  end

  prueba("RECHAZA un sobre sin firma") do
    [!correr(cmd, sin_firma(vector("sobre.json")))[1], nil]
  end

  prueba("RECHAZA una firma auténtica de OTRA llave") do
    # El ataque real: la firma verifica, pero no es de quien el documento dice.
    otra = OpenSSL::PKey.generate_key("ED25519")
    doc = JSON.parse(sin_firma(vector("sobre.json")))
    falso = Sobre.firmar(doc, otra.private_to_pem)
    falso["signature"]["publicKeyId"] = Sobre.id_de_llave(PUB)
    [!correr(cmd, JSON.generate(falso))[1], nil]
  end

  prueba("RECHAZA (o no llama verificable a) uno sin reglasHash") do
    doc = { "version" => "1", "resultados" => [{ "valor" => 42 }] }
    firmado = Sobre.firmar(doc, File.read(File.join(VEC, "llave-privada-SOLO-PRUEBAS.pem")))
    [!correr(cmd, JSON.generate(firmado))[1],
     "firma válida sin procedencia: no es `verificable` (§6)"]
  end
end

# ── firmador ────────────────────────────────────────────────────────────────

def probar_firmador(cmd)
  puts "\nfirmador — `#{cmd}`"

  prueba("firma el vector ASCII igual que la implementación de referencia") do
    salida, ok = correr(cmd, sin_firma(vector("sobre.json")))
    next [false, "el comando falló"] unless ok

    begin
      producido = JSON.parse(salida)
    rescue JSON::ParserError
      next [false, "la salida no es JSON"]
    end
    esperada = JSON.parse(vector("sobre.json"))["signature"]["valor"]
    if producido.dig("signature", "valor") == esperada
      [true, nil]
    else
      # Ed25519 es determinista, así que dos firmas del mismo mensaje con la
      # misma llave DEBEN coincidir. Si no, el mensaje firmado es otro.
      [false, "la firma difiere. Ed25519 es determinista, así que los bytes " \
              "que firmaste no son los canónicos — probá con --canonicalizador"]
    end
  end

  prueba("lo que firma lo acepta el verificador de referencia") do
    salida, ok = correr(cmd, sin_firma(vector("sobre-unicode.json")))
    next [false, "el comando falló"] unless ok

    doc = JSON.parse(salida)
    [Sobre.veredicto(Sobre.analizar(doc, OpenSSL::PKey.read(PUB), PUB)) == "verificable", nil]
  end
end

# ── CLI ─────────────────────────────────────────────────────────────────────

def opcion(nombre)
  i = ARGV.index(nombre)
  i && ARGV[i + 1]
end

modos = { "--canonicalizador" => method(:probar_canonicalizador),
          "--verificador" => method(:probar_verificador),
          "--firmador" => method(:probar_firmador) }

pedidos = modos.filter_map { |bandera, fn| [fn, opcion(bandera)] if opcion(bandera) }

if pedidos.empty?
  warn <<~TXT
    conformidad — comprueba una implementación ajena del sobre contra los vectores

      ruby conformidad.rb --canonicalizador "node canon.js"
      ruby conformidad.rb --verificador     "python3 verify.py"
      ruby conformidad.rb --firmador        "go run sign.go"

    Contrato del comando (stdin/stdout/exit, nada más):

      canonicalizador  stdin: documento JSON  → stdout: bytes canónicos (§3)
      verificador      stdin: sobre JSON      → exit 0 si es `verificable`
      firmador         stdin: documento JSON  → stdout: sobre firmado, con la
                                                llave de vectores/ (§4)
  TXT
  exit 64
end

puts "Conformidad con los vectores de sobre v1"
pedidos.each { |fn, cmd| fn.call(cmd) }

puts
if @fallos.zero?
  puts "#{@corridas} comprobaciones, todas verdes. Tu implementación es interoperable."
  exit 0
else
  puts "#{@fallos} de #{@corridas} fallaron."
  exit 1
end
