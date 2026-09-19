---
estado: propuesta
dueño: yonatan
fecha: 2026-09-08
tema: `sorted_keys_utf8_json` no es interoperable para claves fuera del BMP — Ruby ordena por bytes UTF-8, JavaScript por unidades UTF-16
criterio_cierre: la spec fija UN orden (por code point, o por bytes UTF-8, que coinciden) y las implementaciones Ruby y JS lo prueban con un vector cuya clave tiene un code point > U+FFFF junto a uno en U+E000..U+FFFF; o la spec prohíbe esas claves y `firmar` las rechaza
---

Hallazgo del refutador de testigo (cuarta pasada, 2026-09-08), sin arreglar
en sobre porque `vendor/sobre/sobre.rb` no se toca desde allá.

`Sobre.canonicalizar` ordena con `sort_by { |k, _| k }`: en Ruby compara
bytes UTF-8. `Array.prototype.sort` en JS compara unidades UTF-16. Los dos
órdenes coinciden salvo cuando una clave tiene un code point > U+FFFF (en
UTF-16 es un par sustituto D800–DBFF) y otra clave está en U+E000..U+FFFF:
UTF-8 pone la primera después (F0 > EE/EF), UTF-16 la pone antes (D8 < E0).
Un sobre con esas claves verifica en Ruby y falla en JS, o al revés, sin que
nada avise — el mismo modo de falla que `ENTERO_MAXIMO` existe para evitar.

Testigo lo reporta como aviso informativo (`sobre.keys_sorted_alike`), no
como inválido, porque es de la spec. Repro en testigo:
`test/sobre_inside_test.rb` (`SobreInsideFourthPassTest`).
