# Harness de desarrollo

Dos instancias de Technitium en Docker para desarrollar y verificar el rediseño
de la consola sin tocar ningún DNS real.

| Instancia | Puerto | Qué sirve |
|---|---|---|
| `dev` | http://127.0.0.1:5380 | `DnsServerCore/www/` montado desde el repo |
| `ref` | http://127.0.0.1:5381 | el `www` de la imagen oficial, intacto |

Usuario `admin`, contraseña `technitium-ui-dev` en ambas.

```bash
docker compose up -d      # levantar
./check-paridad.sh        # comparar la portada de dev contra ref
./check-paridad.sh /api/  # comparar otra ruta
docker compose down -v    # tirar todo, incluida la config
```

`ref` es la verdad de referencia: la restricción del proyecto es que el
comportamiento no cambie, así que cualquier divergencia entre ambas que no sea
visual es un fallo.

No se mapea el puerto 53 (`systemd-resolved` lo ocupa en WSL) ni se habilita
DHCP: aquí solo se prueba la consola web.

## Por qué la comparación normaliza los finales de línea

`check-paridad.sh` quita los `\r` antes de hashear, así que compara contenido y
no bytes. Es necesario, no cosmético:

El `.gitattributes` de upstream declara `* text=auto`. Git guarda **LF** en los
blobs del repositorio y convierte al hacer checkout según la plataforma. Nuestro
árbol en Linux tiene LF —y `git status` lo ve limpio, es byte-correcto respecto
al repositorio—, mientras que **la imagen oficial de Docker trae CRLF** porque se
construyó en Windows.

Sin normalizar, dos ficheros de contenido idéntico salen distintos por un byte
por línea: en `index.html` son 7.426 bytes de diferencia sobre 619.718. Se
detectó al ejecutar la primera comprobación de paridad de la fase 0.
