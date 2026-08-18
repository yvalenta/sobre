# sobre en la constelación

Declaración de este repo para el grafo de proyectos de la casa (lo lee
el observatorio interno de la casa, que documenta el formato). Repo público:
solo superficies públicas.

| campo | valor |
|---|---|
| id | sobre |
| clase | producto |
| qué | la spec pública del sobre verificable (bilingüe, dominio público) con conformidad y cuatro implementaciones (Ruby, JS, …) |
| dónde | GitHub; se vendoriza en quien lo usa |
| servicio | `—` (una spec y sus pruebas) |
| atiende | sesiones de Claude a demanda |
| contexto | `README.md` → `SPEC.md` |
| visibilidad | público: `github:yvalenta/sobre` |

## Aristas

| a | b | tipo | por | medición |
|---|---|---|---|---|
| nomicheck | sobre | consume | el formato del comprobante | `—` |
| nomicheck_ops | sobre | consume | vendorizado en `scripts/sobre` con guarda de deriva | `—` |
| nagual | sobre | consume | vendorizado en `vendor/` con guarda de deriva | `—` |
| sobre | github | publica | el repo público es la superficie | `remoto origin` |
