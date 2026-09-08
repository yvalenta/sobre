---
estado: propuesta
dueño: sesión
fecha: 2026-09-07
tema: PATRONES.md §1 promete que el ancla externa cubre los bytes canónicos «con signature incluida», pero `Sobre.bytes_canonicos` descarta `signature` — la prosa y el código dicen cosas distintas
criterio_cierre: PATRONES.md §1, el número fijado en patrones_test.rb y la implementación (Ruby y JS) coinciden en QUÉ bytes ancla el patrón; con prueba negativa que distinga sobre firmado de sin firmar por su ancla si se decide incluir la firma
---

Encontrado el 2026-09-07 desde `~/Developer/testigo` (el verificador de DX402
con sobre adentro) al fijar qué significa «el texto plano es la serialización
canónica del sobre».

**El hecho.** `PATRONES.md` §1, regla 1: «El hash externo se calcula sobre los
bytes canónicos del sobre completo (con `signature` incluida)». Pero
`Sobre.canonicalizar` hace `reject { |k, _| k == "signature" || val.nil? }`,
y `bytes_canonicos` = `JSON.generate(canonicalizar(doc))`: **sin** firma. El
número que `patrones_test.rb` fija (`e636c7bd…918d`) es sobre los bytes sin
firma. Consecuencia: dos sobres con el mismo contenido y firmas distintas
(dos emisores, o una llave rotada) anclan el MISMO hash — el ancla no
distingue quién firmó, y la prosa dice que sí.

**Dos salidas posibles, a decidir:**
1. La prosa se corrige: el ancla cubre lo firmado, no la firma; la autoría la
   da la firma del sobre por separado (es lo que el código hace hoy y la tabla
   del patrón ya lo reparte así por capas).
2. El patrón cambia a anclar la serialización canónica CON `signature`
   (claves ordenadas, sin nulos, `signature` canonicalizada también). Rompe el
   número fijado en `patrones_test.rb` y hay que decir cuál función produce
   esos bytes (hoy ninguna: testigo trae una,
   `Testigo::SobreAdentro.bytes_canonicos_con_firma`, que se podría subir).

No se tocó nada de este repo desde testigo; `sobre.rb` va vendorizado con
guarda de deriva.

## Bitácora
- 2026-09-07: declarada desde la sesión de testigo (sigilo
  `tareas/2026-09-07-dx402-verificador-testigo` → `testigo/tareas/`). Sin
  cambios en este repo.
