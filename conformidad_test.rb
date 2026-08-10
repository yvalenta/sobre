#!/usr/bin/env ruby
# frozen_string_literal: true

# Pruebas de `conformidad.rb` — la herramienta que certifica a otros, que hasta
# el 2026-08-10 no estaba certificada ella misma.
#
# El modo de falla que importa no es que se caiga: es que **apruebe a quien no
# debe**. Alguien que corre esto sobre su implementación y ve verdes concluye
# que es interoperable, y si esa conclusión está mal, el formato entero deja de
# significar algo.
#
#     ruby conformidad_test.rb

require "open3"
require "tmpdir"

RAIZ = __dir__
LLAVE = File.join(RAIZ, "vectores/llave-publica.pem")
PRIVADA = File.join(RAIZ, "vectores/llave-privada-SOLO-PRUEBAS.pem")

@fallos = 0
@corridas = 0

def prueba(nombre)
  @corridas += 1
  ok = yield
  @fallos += 1 unless ok
  puts "  [#{ok ? "OK    " : "FALLA " }] #{nombre}"
end

def conformidad(*args)
  salida, estado = Open3.capture2e(RbConfig.ruby, File.join(RAIZ, "conformidad.rb"), *args, chdir: RAIZ)
  [salida, estado.success?]
end

puts "\nconformidad.rb"

prueba("aprueba a la implementación de referencia en los tres modos") do
  _s, ok = conformidad(
    "--canonicalizador", "ruby -r./sobre -rjson -e 'puts Sobre.bytes_canonicos(JSON.parse($stdin.read.force_encoding(%q{UTF-8})))'",
    "--verificador", "ruby sobre.rb verificar - --llave #{LLAVE}",
    "--firmador", "ruby sobre.rb firmar - --llave-privada #{PRIVADA}",
  )
  ok
end

prueba("aprueba a la implementación de JavaScript") do
  # La segunda implementación independiente. Si esta prueba se cae, o se rompió
  # `sobre.mjs` o se rompió la conformidad — las dos son noticia.
  _s, ok = conformidad(
    "--canonicalizador", "node sobre.mjs canonicalizar -",
    "--verificador", "node sobre.mjs verificar - --llave #{LLAVE}",
    "--firmador", "node sobre.mjs firmar - --llave-privada #{PRIVADA}",
  )
  ok
end

# ── El defecto que motivó este archivo ──────────────────────────────────────
#
# El contrato del verificador es un codigo de salida, y eso vuelve
# indistinguible "rechace el sobre" de "no pude ejecutarme". Un comando que no
# existe rechaza todo, asi que pasaba las CUATRO pruebas de rechazo: un
# verificador roto sacaba 4 de 6 y quien lo leyera creia estar casi listo.
#
# Lo encontro alguien copiando los comandos de ejemplo del README con los
# nombres de archivo tal cual — el primer intento de cualquiera.

prueba("un verificador que NO EXISTE no aprueba ningún caso de rechazo") do
  salida, ok = conformidad("--verificador", "ruby /ruta/que/no/existe.rb")
  !ok && !salida.include?("[OK    ] RECHAZA")
end

prueba("...y lo dice, en vez de callarse") do
  salida, _ok = conformidad("--verificador", "ruby /ruta/que/no/existe.rb")
  salida.include?("NO se evaluaron")
end

prueba("un verificador que dice OK A TODO es rechazado") do
  # El otro extremo, y el mas peligroso en produccion: acepta los dos vectores
  # buenos —o sea pasa las positivas— y tambien acepta un sobre alterado.
  Dir.mktmpdir do |dir|
    si = File.join(dir, "si.rb")
    File.write(si, "$stdin.read\nexit 0\n")
    salida, ok = conformidad("--verificador", "ruby #{si}")
    !ok && salida.include?("acepta el vector ASCII") && salida.include?("[FALLA ] RECHAZA")
  end
end

prueba("un canonicalizador que devuelve basura es rechazado, con el byte exacto") do
  Dir.mktmpdir do |dir|
    basura = File.join(dir, "basura.rb")
    File.write(basura, "$stdin.read\nputs '{}'\n")
    salida, ok = conformidad("--canonicalizador", "ruby #{basura}")
    !ok && salida.include?("primera divergencia en el byte")
  end
end

prueba("sin argumentos explica el contrato y sale 64") do
  salida, _e, estado = Open3.capture3(RbConfig.ruby, File.join(RAIZ, "conformidad.rb"), chdir: RAIZ)
  estado.exitstatus == 64 && salida.include?("stdin") == false || _e.include?("canonicalizador")
end

if @fallos.zero?
  puts "\n#{@corridas} pruebas, todas verdes.\n\n"
  exit 0
else
  puts "\n#{@fallos} de #{@corridas} fallaron.\n\n"
  exit 1
end
