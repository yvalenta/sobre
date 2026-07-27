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

puts
if @fallos.zero?
  puts "#{@corridas} pruebas, todas verdes."
  exit 0
else
  puts "#{@fallos} de #{@corridas} fallaron."
  exit 1
end
