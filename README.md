# Laboratorio DNSSEC

Laboratorio de DNS y DNSSEC construido con **BIND9** en contenedores **Docker**, corrido en una máquina virtual de Kali Linux. El proyecto simula una jerarquía DNS completa (servidor root, dominios firmados y sin firmar, resolvers recursivos) para observar cómo funciona la validación DNSSEC y qué pasa cuando falla.

## Contenido del repositorio

- **`COMMANDS.md`**: historial de comandos utilizados para montar el laboratorio, configurar las zonas, levantar los contenedores, firmar las zonas con DNSSEC y verificar los resultados.
- **`root/`, `unsigned/`, `alpha/`, `signed/`, `beta/`, `gamma/`**: configuración (`named.conf`) y archivos de zona de cada servidor DNS.
- **`recursive1/`, `recursive-internet/`, `recursive-dnssec/`**: configuración de los resolvers recursivos usados en distintas etapas del laboratorio.
- **`extraer_dns.py`, `extraer_dnssec.py`, `resumen_dnssec_local.py`**: scripts en Python para analizar el tráfico DNS capturado y extraer información relevante de las consultas y respuestas.
- **`herramienta_dnssec/verificador_dnssec.py`**: herramienta propia para verificar el estado de firma de una zona (detecta expiración, ausencia de DS, DS inválido, etc).
- Archivos `resultado_*.txt`, `resultados_*.txt`: salidas generadas por los scripts anteriores durante las pruebas.

> Las capturas de tráfico (`.pcapng`) y las llaves privadas DNSSEC (`.private`) no están incluidas en el repositorio por tamaño y por buenas prácticas de seguridad, respectivamente.

## Arquitectura del laboratorio

Todos los contenedores corren la imagen `internetsystemsconsortium/bind9:9.20` conectados a una red Docker dedicada (`172.30.0.0/24`):

| Servidor | IP | Rol |
|---|---|---|
| root | 172.30.0.10 | Servidor raíz de la jerarquía simulada |
| unsigned | 172.30.0.20 | Zona sin firmar, referencia base |
| alpha | 172.30.0.30 | Zona hija de `unsigned`, sin DNSSEC |
| signed | — | Zona firmada con DNSSEC, padre de `beta` y `gamma` |
| beta | — | Zona hija firmada bajo `signed` |
| gamma | — | Zona de prueba (delegación sin firmar) |
| recursive1 | 172.30.0.100 | Resolver recursivo dentro del laboratorio |
| recursive-internet | 172.30.0.110 | Resolver recursivo con salida real a Internet, usado para probar dominios reales como `unam.mx` |
| recursive-dnssec | 172.30.0.120 | Resolver recursivo con validación DNSSEC activada |

## Cómo levantar el laboratorio

1. Instalar dependencias:
   ```bash
   sudo apt update
   sudo apt install -y docker.io bind9-utils bind9-dnsutils
   sudo systemctl enable docker --now
   ```

2. Crear la red Docker:
   ```bash
   sudo docker network create --subnet=172.30.0.0/24 dns-lab
   ```

3. Levantar cada servidor montando su `named.conf` y su carpeta de zonas correspondiente. El detalle completo de cada contenedor está en [`COMMANDS.md`](./COMMANDS.md).

4. Probar la resolución y la validación DNSSEC con `dig`, por ejemplo:
   ```bash
   dig @172.30.0.120 +dnssec beta.signed. A
   ```

## Qué se puso a prueba

- Resolución DNS recursiva normal, sin DNSSEC.
- Firma de zonas con `dnssec-keygen` y `dnssec-signzone` (algoritmo ECDSAP256SHA256).
- Delegación de confianza mediante registros `DS` entre zona padre e hija.
- Validación DNSSEC contra dominios reales (`unam.mx`) usando un resolver con salida a Internet.
- Casos de falla: zonas con firma expirada, sin DS en el padre, o con DS inválido, verificados con la herramienta `verificador_dnssec.py`.
- Análisis de tráfico DNS capturado con `tshark`, procesado con scripts propios en Python.

## Nota sobre el historial de comandos

Parte del historial de la terminal (`.zsh_history`) se corrompió durante el laboratorio. El archivo `COMMANDS.md` se reconstruyó combinando lo que se pudo recuperar del historial y evidencia de los archivos de respaldo generados durante el proyecto. Las secciones marcadas como reconstrucción son una aproximación razonable a los comandos reales, no una copia exacta.
