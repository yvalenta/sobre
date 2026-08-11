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
#   ruby sobre.rb verificar <sobre.json> --llave-url https://host/publickey
#   ruby sobre.rb verificar <sobre.json> --llave llave.pem
#   ruby sobre.rb llave-id llave.pem
#
# Salida: 0 verificable · 1 firma invalida · 2 firma valida, sobre incompleto

require "json"
require "openssl"
require "base64"
require "digest"
# Solo para expandir un decimal a notacion plana sin perder digitos. Es stdlib
# (gema por defecto), asi que el sobre sigue sin dependencias que instalar.
require "bigdecimal"
require "net/http"
require "uri"
require "time"

module Sobre
  VERSION = "1"

  # Un documento que NO se puede canonicalizar de forma interoperable. Es un
  # error del insumo, no del verificador: se lanza igual al firmar y al
  # verificar, asi que los dos lados coinciden en rechazarlo en vez de producir
  # firmas que no se entienden entre si.
  class ErrorDeCanonicalizacion < StandardError; end

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
    when Float then normalizar_flotante!(v)
    when Integer then entero_seguro!(v)
    else v
    end
  end

  # El techo de los enteros: 2^53 - 1.
  #
  # Arriba de eso JavaScript **no puede leer el numero sin redondearlo**, asi
  # que un sobre con 9007199254740993 se canonicaliza distinto en Ruby y en JS
  # —medido: JS devuelve ...992— y las firmas divergen SIN QUE NADA AVISE. Es
  # el peor modo de falla posible para este formato: el emisor cree que firmo
  # bien y el verificador de enfrente dice invalido.
  ENTERO_MAXIMO = (2**53) - 1

  def self.entero_seguro!(n)
    return n if n.abs <= ENTERO_MAXIMO

    raise ErrorDeCanonicalizacion,
          "entero fuera del rango seguro (|n| > 2^53-1): #{n}. JavaScript no puede " \
          "leerlo sin redondear, asi que la firma no seria interoperable. Codificalo " \
          "como string si necesitas mas precision."
  end

  # ── Los decimales ───────────────────────────────────────────────────────────
  #
  # Este bloque se reescribio entero el 2026-08-10, el mismo dia que se escribio,
  # porque la primera version RECHAZABA TODO DECIMAL y eso rompio produccion: la
  # entrega real trae `baseGravableUvt: 105.4` —los UVT son fraccionarios por
  # definicion— y el verificador desplegado paso a llamar `INVALIDO` a un sobre
  # legitimo y bien firmado. Un verificador que rechaza evidencia valida es peor
  # que no tener verificador.
  #
  # El diagnostico que justificaba aquel rechazo era falso. Se midio de nuevo,
  # comparando los BITS del double y no su texto, sobre 60.000 valores
  # aleatorios:
  #
  #   1. **El parseo NO diverge.** El mismo literal da el mismo double en Ruby y
  #      en JS, bit a bit. Los dos hacen conversion correctamente redondeada.
  #   2. **El que se desvia es la gema `json` al IMPRIMIR.** ECMAScript le exige
  #      a JavaScript la representacion mas corta que round-trippea; `JSON.generate`
  #      emite el equivalente de `%.17g`. Medido sobre el double 40d9b6ca11b1d92b:
  #      `JSON.generate` da `26331.157329999998` y JavaScript da `26331.15733`.
  #      Mismo numero, distinto texto, distinta firma.
  #
  # Ojo con el detalle, porque invita a un atajo equivocado: `Float#to_s` SI da la
  # forma corta. Delegar en el seria Ruby-especifico y ademas cambia a exponencial
  # en umbrales distintos que JS, asi que no se puede escribir en una spec que
  # otro lenguaje tiene que poder cumplir.
  #
  # O sea: los decimales SI son interoperables; lo que no servia era delegar el
  # formato en el generador de JSON. Se emula el algoritmo de JS buscando la
  # precision mas chica que vuelve al mismo double —eso ES "shortest round-trip",
  # se implementa con un bucle en cualquier lenguaje y no depende de la libreria
  # de nadie— y se emite en notacion plana, que es la que JS usa en toda la banda
  # admitida. Con eso las 60.000 coinciden: 0 divergencias.
  #
  # Queda UNA banda rechazada, y es angosta a proposito: `0 < |x| < 1e-6`. Ahi
  # JS pasa a exponencial (`1e-7`) y Ruby todavia imprime plano (`0.0000001`).
  # Reconciliar eso obligaria a reimplementar las reglas de formato de ECMAScript
  # —la barrera de implementacion que este formato dice no querer— para valores
  # que no significan nada como evidencia. Por el otro extremo no hace falta
  # cortar: todo flotante no entero es menor que 2^52, muy por debajo del punto
  # donde JS cambiaria de notacion.
  DECIMAL_MINIMO = 1e-6

  def self.normalizar_flotante!(f)
    unless f.finite?
      raise ErrorDeCanonicalizacion,
            "#{f} no es representable en JSON (ni Infinity ni NaN lo son)."
    end

    # `1.0`, `1e3` y `-0.0` son enteros disfrazados: en JavaScript son EL MISMO
    # VALOR que `1`, `1000` y `0` despues del parse, y alli se emiten sin punto.
    # `-0.0` va incluido a proposito — `(-0.0).to_i` da 0, que es lo que hace JS.
    return entero_seguro!(f.to_i) if f == f.to_i

    if f.abs < DECIMAL_MINIMO
      raise ErrorDeCanonicalizacion,
            "decimal demasiado chico para canonicalizar de forma interoperable (#{f}). " \
            "Abajo de 1e-6 JavaScript cambia a notacion exponencial y Ruby no, asi que " \
            "la firma no coincidiria. Codificalo como string o en una unidad mayor."
    end

    Crudo.new(decimal_canonico(f))
  end

  # Los digitos EXACTOS que emitiria JavaScript: la precision mas chica que
  # round-trippea. Se prueba de 1 a 17 porque 17 siempre alcanza para un double.
  def self.decimal_canonico(f)
    (1..17).each do |p|
      s = format("%.#{p}g", f)
      next unless s.to_f == f

      # `%g` puede salir en exponencial; JS usa plana en toda esta banda, asi que
      # se expande sin perder digitos. El `.0` sobrante no se llega a dar acá
      # —los enteros ya salieron por `entero_seguro!`— pero se poda por si acaso.
      return BigDecimal(s).to_s("F").sub(/\.0\z/, "")
    end

    # Inalcanzable con un double: se deja explicito en vez de devolver nil y
    # producir `null` en la salida, que es la clase de fallo silencioso que este
    # archivo entero existe para evitar.
    raise ErrorDeCanonicalizacion, "no se encontro representacion que round-trippee para #{f}"
  end

  # Un numero ya serializado, que `JSON.generate` tiene que emitir TAL CUAL.
  #
  # Hace falta porque la canonicalizacion produce objetos de Ruby y recien
  # despues se genera el JSON: si `decimal_canonico` devolviera un String, saldria
  # entrecomillado y cambiaria el tipo del campo. `to_json` es el gancho que
  # `JSON.generate` llama para los objetos que no conoce.
  class Crudo
    def initialize(texto) = @texto = texto
    def to_json(*_args) = @texto
    def to_s = @texto
    def ==(other) = other.is_a?(Crudo) ? to_s == other.to_s : to_s == other.to_s
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

  # ── Firmar ────────────────────────────────────────────────────────────────
  #
  # Existe porque adoptar el sobre es EMITIRLO, no verificarlo. Hasta el
  # 2026-08-09 la implementacion de referencia solo sabia verificar: quien
  # queria emitir escribia el firmador desde el documento, a ciegas, sin nada
  # contra que contrastarlo. Es al reves de lo que la adopcion necesita.
  #
  # `publicKeyId` se deriva de la llave PUBLICA sacada de la privada, no se pide
  # aparte: pedirla seria dejar que alguien declare un id que no corresponde a la
  # llave con la que firmo, y eso es exactamente el ataque que `llave_declarada`
  # existe para cazar. Que el emisor no pueda cometerlo es mejor que detectarlo.
  def self.firmar(doc, pem_privado)
    sk = OpenSSL::PKey.read(pem_privado)
    raise ArgumentError, "la llave no es Ed25519" unless sk.oid == "ED25519"

    # `bytes_canonicos` ya descarta `signature`, asi que re-firmar un sobre
    # produce la misma firma. No se prohibe: es util para rotar una llave.
    bytes = bytes_canonicos(doc)
    doc.reject { |k, _| k == "signature" }.merge(
      "signature" => {
        "algo" => "ed25519",
        "valor" => Base64.strict_encode64(sk.sign(nil, bytes)),
        "publicKeyId" => id_de_llave(sk.public_to_pem),
        "cubreCampos" => "todos_menos_signature",
        "canonical" => "sorted_keys_utf8_json"
      },
    )
  end

  # Lo que le falta a un documento para llegar a `verificable`. Se avisa al
  # firmar —no se bloquea— porque un sobre sin `reglasHash` es un estado LEGAL
  # del formato (§6): "firmado sin procedencia". Pero emitirlo sin darse cuenta
  # es el error mas facil de cometer y el mas dificil de ver despues, asi que el
  # firmador lo dice en voz alta.
  def self.faltantes_para_procedencia(doc)
    %w[reglasHash reglasVerificadasAl habeasData].reject { |c| doc.key?(c) }
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
        ruby sobre.rb firmar <documento.json> --llave-privada <llave.pem>
        ruby sobre.rb llave-id <llave.pem>

      `-` en vez del archivo lee de la entrada estandar:

        curl -s https://host/ejemplo | jq .output |
          ruby sobre.rb verificar - --llave-url https://host/publickey --json

      Firmar escribe el sobre en la salida estandar, asi que se encadena:

        ruby sobre.rb firmar doc.json --llave-privada k.pem | ruby sobre.rb verificar -

      Salida de verificar: 0 verificable · 1 firma invalida · 2 firmado sin procedencia
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

  when "firmar"
    archivo = ARGV.shift or uso
    i = ARGV.index("--llave-privada") or uso
    priv = File.read(ARGV[i + 1])

    doc = Sobre.cargar(archivo)
    firmado = Sobre.firmar(doc, priv)

    # Los avisos van a stderr y el sobre a stdout, para que la tuberia del `uso`
    # funcione sin que un warning contamine el JSON.
    faltan = Sobre.faltantes_para_procedencia(doc)
    unless faltan.empty?
      warn "  aviso: firmado, pero le falta #{faltan.join(', ')} — va a verificar"
      warn "         como `firmado_sin_procedencia`, no como `verificable` (§6)."
    end

    puts JSON.generate(firmado)
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
