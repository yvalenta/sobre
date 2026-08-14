#!/usr/bin/env ruby
# frozen_string_literal: true

# Pruebas de PATRONES.md. SIN RED.
#
# El patrón del anclaje externo publica un digest del vector como ejemplo. Un
# número escrito en prosa es una copia más donde desincronizarse: si alguien
# regenera el vector y no relee el documento, la prosa queda mintiendo con los
# tests en verde. Esto fija los dos lados a la vez.
#
#   ruby patrones_test.rb

require "digest"
require_relative "sobre"

@fallos = 0
@corridas = 0

def prueba(nombre)
  @corridas += 1
  ok = yield
  @fallos += 1 unless ok
  puts "  [#{ok ? "OK    " : "FALLA "}] #{nombre}"
end

DIGEST_EJEMPLO = "e636c7bd0fc91fc418239124b0ec365a9083efdb3704840dd5a47437ee59918d"

prueba "el digest del ejemplo es el sha-256 real de los bytes canonicos del vector" do
  bytes = Sobre.bytes_canonicos(Sobre.cargar(File.expand_path("vectores/sobre.json", __dir__)))
  Digest::SHA256.hexdigest(bytes) == DIGEST_EJEMPLO
end

prueba "PATRONES.md publica exactamente ese digest" do
  File.read(File.expand_path("PATRONES.md", __dir__), encoding: "UTF-8")
      .include?(DIGEST_EJEMPLO)
end

prueba "el digest se calcula sobre el sobre COMPLETO, firma incluida (la regla 1 del patron)" do
  doc = Sobre.cargar(File.expand_path("vectores/sobre.json", __dir__))
  doc.key?("signature")
end

if @fallos.zero?
  puts "\n#{@corridas} pruebas, todas verdes\n\n"
else
  puts "\n#{@fallos} de #{@corridas} fallaron\n\n"
end
exit(@fallos.zero? ? 0 : 1)
