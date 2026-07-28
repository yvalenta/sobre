#!/usr/bin/env ruby
# frozen_string_literal: true

# sobre — verificador offline de salidas firmadas de agentes.
#
# Un sobre es una salida de agente que se puede comprobar ante un tercero sin
# confiar en quien la emitio y sin conexion a su servidor. Cuatro piezas:
#
#     salida         el resultado
#     reglasHash     sha256 del catalogo/metodo que lo produjo
#     verificadoAl   fecha en que se comprobo ese catalogo
#     habeasData     constancia de tratamiento de datos
#     signature      Ed25519 sobre el JSON canonico de todo lo anterior
#
# La distincion que justifica la herramienta: **una firma valida no alcanza.**
# Un documento firmado sin `reglasHash` es una opinion firmada — dice quien lo
# dijo, no contra que se comprueba. Este verificador los separa con veredictos
# distintos, porque tratarlos igual es el error que hace inutil a la firma.
#
# Esta es ademas la implementacion de referencia: `probe.rb` la usa, de modo que
# la canonicalizacion vive en un solo lugar y no puede derivar entre las dos.
#
#   ruby scripts/sobre.rb verificar <sobre.json> --llave-url https://host/publickey
#   ruby scripts/sobre.rb verificar <sobre.json> --llave llave.pem
#   ruby scripts/sobre.rb llave-id llave.pem
#
# Salida: 0 verificable · 1 firma invalida · 2 firma valida, sobre incompleto

require "json"
require "openssl"
require "base64"
require "digest"
require "net/http"
require "uri"
require "time"

module Sobre
  VERSION = "1"

  # Forma canonica: claves ordenadas recursivamente, sin `signature` y sin
  # nulos. Los nulos se descartan porque un campo ausente y un campo en null
  # deben producir los mismos bytes — si no, agregar un campo opcional vacio
  # romperia firmas viejas.
  def self.canonicalizar(v)
    case v
    when Hash
      v.reject { |k, val| k == "signature" || val.nil? }
       .sort_by { |k, _| k }.to_h { |k, val| [k, canonicalizar(val)] }
    when Array then v.map { |x| canonicalizar(x) }
    else v
    end
  end

  def self.bytes_canonicos(doc)
    JSON.generate(canonicalizar(doc))
  end

  # Cargar un sobre desde disco. Existe porque `JSON.parse(File.read(x))` a
  # secas revienta con "invalid byte sequence" en cualquier maquina cuyo locale
  # no sea UTF-8 — y el sobre suele traer tildes. Es la primera piedra con la
  # que tropieza quien lo usa como libreria.
  # `-` lee de la entrada estandar, para que el sobre se pueda verificar en una
  # tuberia sin tocar el disco:
  #
  #   curl -s https://host/ejemplo | jq .output | ruby sobre.rb verificar -
  #
  # Importa mas de lo que parece: un comprador que quiera comprobarnos ANTES de
  # pagar no deberia tener que guardar un archivo para hacerlo, y un agente que
  # verifica en automatico no tiene por que escribir en disco.
  def self.cargar(ruta)
    crudo = ruta == "-" ? $stdin.read : File.read(ruta, encoding: "UTF-8")
    JSON.parse(crudo.force_encoding("UTF-8"))
  end

  # Reescribe un PEM a su forma estandar: base64 en lineas de 64, un solo salto
  # final. Sin esto el id es fragil de una forma que muerde a todos: `curl >
  # llave.pem` agrega un \n, copiar y pegar puede agregar o quitar otro, y
  # Windows mete \r\n. Cada variante da un sha256 distinto de la MISMA llave, y
  # la comprobacion falla aunque todo este bien. (Medido el 2026-07-26: un \n
  # sobrante cambio el id de 99586544... a 13a3c8d9...)
  def self.normalizar_pem(pem)
    cuerpo = pem.gsub(/-----[A-Z ]+-----/, "").gsub(/\s+/, "")
    "-----BEGIN PUBLIC KEY-----\n#{cuerpo.scan(/.{1,64}/).join("\n")}\n-----END PUBLIC KEY-----\n"
  end

  # El id es sha256 del PEM **normalizado**, truncado a 32 hex. Permite
  # comprobar que la llave con la que verificas es la que el documento dice —
  # sin esto, verificar "bien" contra la llave equivocada se ve identico a
  # verificar de verdad.
  def self.id_de_llave(pem)
    Digest::SHA256.hexdigest(normalizar_pem(pem))[0, 32]
  end

  def self.verificar_firma(doc, pkey)
    firma = Base64.decode64(doc.dig("signature", "valor").to_s)
    return false if firma.empty?

    pkey.verify(nil, firma, bytes_canonicos(doc))
  rescue StandardError
    false
  end

  # Muta el primer valor numerico o de texto del documento. Sirve para probar
  # que el verificador de verdad esta comprobando: una firma que acepta
  # cualquier cosa se ve igual que una que funciona hasta que la atacas.
  def self.mutar(v)
    case v
    when Hash
      v.each do |k, val|
        next if k == "signature"

        if val.is_a?(Numeric) then return v.merge(k => val + 1)
        elsif val.is_a?(String) && !val.empty? then return v.merge(k => "#{val}~")
        elsif val.is_a?(Hash) || val.is_a?(Array)
          m = mutar(val)
          return v.merge(k => m) if m
        end
      end
      nil
    when Array
      v.each_with_index do |x, i|
        m = mutar(x)
        return v.dup.tap { |c| c[i] = m } if m
      end
      nil
    end
  end

  # Devuelve los checks del sobre. `pkey` puede ser nil: entonces solo se
  # evalua la estructura y la firma queda como no comprobada.
  def self.analizar(doc, pkey, pem = nil)
    checks = []
    add = lambda { |id, critico, ok, detalle|
      checks << { id: id, critico: critico, ok: ok, detalle: detalle }
    }

    sig = doc["signature"] || {}
    add.call("sobre.firma_presente", true, !sig["valor"].to_s.empty?,
             sig["valor"].to_s.empty? ? "el documento no trae firma" : "algo=#{sig["algo"] || "?"}")

    if pkey
      valida = verificar_firma(doc, pkey)
      add.call("sobre.firma_verifica", true, valida,
               valida ? "Ed25519 verifica sobre el JSON canonico" : "LA FIRMA NO VERIFICA")

      if pem
        esperado = sig["publicKeyId"].to_s
        real = id_de_llave(pem)
        coincide = esperado.empty? || esperado == real
        add.call("sobre.llave_declarada", true, coincide,
                 coincide ? "publicKeyId #{real} coincide con la llave usada" \
                          : "el sobre dice #{esperado} pero verificaste con #{real}")
      end

      if valida
        alterado = mutar(doc)
        detecta = alterado.nil? ? false : !verificar_firma(alterado, pkey)
        add.call("sobre.detecta_manipulacion", true, detecta,
                 detecta ? "alterar un valor invalida la firma" : "LA FIRMA ACEPTA DATOS ALTERADOS")
      end
    else
      add.call("sobre.firma_verifica", true, false, "sin llave publica: no comprobada")
    end

    # Procedencia: sin esto, una firma valida solo dice quien lo dijo.
    hash_reglas = doc["reglasHash"] || doc.dig("reglas", "hash")
    add.call("sobre.reglas_hash", false, !hash_reglas.to_s.empty?,
             hash_reglas ? "catalogo #{hash_reglas.to_s[0, 16]}..." \
                         : "sin reglasHash — no se sabe contra que metodo se comprueba")

    fecha = doc["reglasVerificadasAl"] || doc["verificadoAl"]
    edad = begin
      fecha ? ((Time.now - Time.parse(fecha.to_s)) / 86_400).floor : nil
    rescue StandardError
      nil
    end
    add.call("sobre.fecha_verificacion", false, !fecha.to_s.empty?,
             fecha ? "reglas verificadas al #{fecha}#{edad ? " (hace #{edad} dias)" : ""}" \
                   : "sin fecha de verificacion de la normativa")

    hd = doc["habeasData"] || {}
    completo = hd.key?("persistidoEnBd") && hd.key?("procesadoPorLlmExterno")
    add.call("sobre.habeas_data", false, completo,
             completo ? "persistidoEnBd=#{hd["persistidoEnBd"]} llmExterno=#{hd["procesadoPorLlmExterno"]}" \
                      : "sin constancia de tratamiento de datos")

    checks
  end

  def self.veredicto(checks)
    criticos_mal = checks.any? { |c| c[:critico] && !c[:ok] }
    return "invalido" if criticos_mal

    checks.all? { |c| c[:ok] } ? "verificable" : "firmado_sin_procedencia"
  end

  def self.llave_de_url(url)
    uri = URI(url)
    res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https",
                          open_timeout: 15, read_timeout: 30) do |h|
      req = Net::HTTP::Get.new(uri)
      req["User-Agent"] = "sobre/#{VERSION}"
      h.request(req)
    end
    raise "HTTP #{res.code} al pedir la llave" unless res.code.to_i == 200

    cuerpo = JSON.parse(res.body)
    cuerpo["publicKeyPem"] || cuerpo["pem"] or raise "la respuesta no trae publicKeyPem"
  end
end

# ── CLI ─────────────────────────────────────────────────────────────────────

if __FILE__ == $PROGRAM_NAME
  def uso
    warn <<~TXT
      sobre — verificador offline de salidas firmadas

        ruby sobre.rb verificar <sobre.json> [--llave a.pem | --llave-url URL] [--json]
        ruby sobre.rb llave-id <llave.pem>

      `-` en vez del archivo lee de la entrada estandar:

        curl -s https://host/ejemplo | jq .output |
          ruby sobre.rb verificar - --llave-url https://host/publickey --json

      Salida: 0 verificable · 1 firma invalida · 2 firmado sin procedencia
    TXT
    exit 64
  end

  cmd = ARGV.shift
  uso if cmd.nil?

  case cmd
  when "llave-id"
    ruta = ARGV.shift or uso
    puts Sobre.id_de_llave(File.read(ruta))
    exit 0

  when "verificar"
    archivo = ARGV.shift or uso
    salida_json = ARGV.delete("--json")
    pem = nil
    if (i = ARGV.index("--llave"))
      pem = File.read(ARGV[i + 1])
    elsif (i = ARGV.index("--llave-url"))
      begin
        pem = Sobre.llave_de_url(ARGV[i + 1])
      rescue StandardError => e
        warn "  no se pudo traer la llave: #{e.message}"
      end
    end

    doc = Sobre.cargar(archivo)
    pkey = pem ? OpenSSL::PKey.read(pem) : nil
    checks = Sobre.analizar(doc, pkey, pem)
    veredicto = Sobre.veredicto(checks)

    nombre = archivo == "-" ? "(entrada estandar)" : archivo

    if salida_json
      puts JSON.pretty_generate({ archivo: nombre, veredicto: veredicto, checks: checks })
    else
      puts "sobre: #{nombre}"
      puts
      ancho = checks.map { |c| c[:id].length }.max
      checks.each do |c|
        icono = c[:ok] ? "OK  " : (c[:critico] ? "FALLA" : "AUSENTE")
        puts "  [#{icono.ljust(7)}] #{c[:id].ljust(ancho)}  #{c[:detalle]}"
      end
      puts
      puts({
        "verificable" => "VERIFICABLE — la salida se sostiene ante un tercero.",
        "firmado_sin_procedencia" =>
          "FIRMADO SIN PROCEDENCIA — la firma es autentica, pero falta contra que\n" \
          "  comprobarla. Prueba quien lo dijo, no que sea correcto.",
        "invalido" => "INVALIDO — no confiar en esta salida."
      }[veredicto])
    end

    exit({ "verificable" => 0, "invalido" => 1, "firmado_sin_procedencia" => 2 }[veredicto])
  else
    uso
  end
end
