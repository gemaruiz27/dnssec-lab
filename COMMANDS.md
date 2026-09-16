# Historial de comandos - Laboratorio DNSSEC (Kali Linux)

Este documento reconstruye el flujo de comandos utilizado para montar y probar un laboratorio de DNSSEC con BIND9 en contenedores Docker.

## 1. Instalación de dependencias

```bash
sudo apt update
sudo apt install -y docker.io bind9-utils bind9-dnsutils
sudo systemctl enable docker --now
docker --version
dig -v
named-checkconf -v
sudo systemctl status docker --no-pager
```

## 2. Estructura del proyecto

```bash
mkdir -p dns-lab/root/zones
mkdir -p dns-lab/unsigned/zones
mkdir -p dns-lab/alpha/zones
mkdir -p dns-lab/recursive1/zones
cd dns-lab
find .
```

## 3. Configuración de zonas

### Servidor root
```bash
nano root/named.conf
cat root/named.conf
nano root/zones/db.root
cat root/zones/db.root
named-checkconf root/named.conf
named-checkzone . root/zones/db.root
sudo mkdir -p /var/cache/bind
```

### Zona unsigned
```bash
nano unsigned/named.conf
cat unsigned/named.conf
nano unsigned/zones/db.unsigned
cat unsigned/zones/db.unsigned
named-checkconf unsigned/named.conf
named-checkzone unsigned. unsigned/zones/db.unsigned
```

### Zona alpha
```bash
nano alpha/named.conf
cat alpha/named.conf
nano alpha/zones/db.alpha.unsigned
cat alpha/zones/db.alpha.unsigned
named-checkconf alpha/named.conf
named-checkzone alpha.unsigned. alpha/zones/db.alpha.unsigned
```

### Resolver recursivo (recursive1)
```bash
nano recursive1/named.conf
cat recursive1/named.conf
nano recursive1/zones/db.root.hints
cat recursive1/zones/db.root.hints
named-checkconf recursive1/named.conf
```

## 4. Red y contenedores Docker

```bash
sudo docker network create --subnet=172.30.0.0/24 dns-lab
sudo docker network inspect dns-lab
sudo docker pull internetsystemsconsortium/bind9:9.20

# Servidor root
sudo docker run -d --name root --network dns-lab --ip 172.30.0.10 \
  -v "$PWD/root/named.conf:/etc/bind/named.conf:ro" \
  -v "$PWD/root/zones:/var/lib/bind:ro" \
  internetsystemsconsortium/bind9:9.20

# Servidor unsigned
sudo docker run -d --name unsigned --network dns-lab --ip 172.30.0.20 \
  -v "$PWD/unsigned/named.conf:/etc/bind/named.conf:ro" \
  -v "$PWD/unsigned/zones:/var/lib/bind:ro" \
  internetsystemsconsortium/bind9:9.20

# Servidor alpha
sudo docker run -d --name alpha --network dns-lab --ip 172.30.0.30 \
  -v "$PWD/alpha/named.conf:/etc/bind/named.conf:ro" \
  -v "$PWD/alpha/zones:/var/lib/bind:ro" \
  internetsystemsconsortium/bind9:9.20

# Resolver recursivo
sudo docker run -d --name recursive1 --network dns-lab --ip 172.30.0.100 \
  -v "$PWD/recursive1/named.conf:/etc/bind/named.conf:ro" \
  -v "$PWD/recursive1/zones:/var/lib/bind:ro" \
  internetsystemsconsortium/bind9:9.20

sudo docker ps -a
```

## 5. Pruebas de resolución DNS

```bash
dig @172.30.0.10 . SOA
dig @172.30.0.10 . NS

dig @172.30.0.20 unsigned. SOA
dig @172.30.0.20 unsigned. NS
dig @172.30.0.20 alpha.unsigned. NS

dig @172.30.0.30 alpha.unsigned. SOA
dig @172.30.0.30 www.alpha.unsigned. A

dig @172.30.0.100 www.alpha.unsigned. A
sudo docker restart recursive1
dig @172.30.0.100 . SOA
dig @172.30.0.100 . NS
dig @172.30.0.100 ns.root. A
dig @172.30.0.100 unsigned. SOA
dig @172.30.0.100 unsigned. NS
dig @172.30.0.100 ns.unsigned. A
```

## 6. Captura y análisis de tráfico DNS

```bash
find ~ -type f -name "*.pcapng"
tshark -v
nano extraer_dns.py
python3 extraer_dns.py | tee resultados_dns.txt
```

Capturas generadas durante esta fase (confirmadas en el backup, en `Desktop/`):
- `primeracaptura.pcapng`
- `segundacaptura.pcapng`
- `terceracaptura.pcapng`
- `cuartacaptura.pcapng`

## 7. Pruebas de DNSSEC contra dominios reales (unam.mx)

```bash
dig @8.8.8.8 +dnssec nic.mx DNSKEY
dig @8.8.8.8 +dnssec unam.mx DNSKEY
dig @8.8.8.8 +dnssec unam.mx SOA
dig @8.8.8.8 +dnssec unam.mx NS
dig @8.8.8.8 +dnssec unam.mx A
dig @8.8.8.8 +dnssec unam.mx AAAA
dig @8.8.8.8 +dnssec unam.mx DS
dig @8.8.8.8 +dnssec noexiste12345.unam.mx A
```

## 8. Resolver recursivo con salida a Internet (recursive-internet)

```bash
mkdir -p recursive-internet/zones
nano recursive-internet/named.conf
cp /usr/share/dns/root.hints recursive-internet/zones/db.root.hints
head recursive-internet/zones/db.root.hints
named-checkconf recursive-internet/named.conf

sudo docker run -d --name recursive-internet --network dns-lab --ip 172.30.0.110 \
  -v "$PWD/recursive-internet/named.conf:/etc/bind/named.conf:ro" \
  -v "$PWD/recursive-internet/zones:/var/lib/bind:ro" \
  internetsystemsconsortium/bind9:9.20

sudo docker ps -a
dig @172.30.0.110 +dnssec unam.mx DNSKEY
```

### Pruebas usando este resolver como DNS del sistema
```bash
sudo cp /etc/resolv.conf /etc/resolv.conf.backup
sudo nano /etc/resolv.conf

dig +dnssec unam.mx DNSKEY
dig +dnssec unam.mx SOA
dig +dnssec unam.mx NS
dig +dnssec unam.mx A
dig +dnssec unam.mx AAAA
dig +dnssec unam.mx DS
dig +dnssec noexiste12345.unam.mx A

sudo cp /etc/resolv.conf.backup /etc/resolv.conf
cat /etc/resolv.conf
```

### Análisis del tráfico local
```bash
find /home/kali/Desktop -type f -name "*.pcapng"
nano extraer_dnssec.py
python3 extraer_dnssec.py | tee resultados_dnssec_local.txt
nano resumen_dnssec_local.py
python3 resumen_dnssec_local.py
```

Capturas generadas durante esta fase (confirmadas en el backup, en `Desktop/`):
- `unam.pcapng`
- `unam2.pcapng`
- `unam_recursivo_local.pcapng`

## 9. Solución de problemas de red (recursive-internet sin salida)

```bash
nano recursive-internet/named.conf
named-checkconf recursive-internet/named.conf
sudo docker restart recursive-internet
sudo docker exec recursive-internet rndc flush
dig @172.30.0.110 +dnssec unam.mx SOA
sudo docker logs --tail 30 recursive-internet

dig @8.8.8.8 unam.mx A
dig @198.41.0.4 . NS

ip route
ip addr
nmcli device status
sudo nmcli con mod "Wired connection 1" ipv4.method auto
sudo nmcli con down "Wired connection 1"
sudo nmcli con up "Wired connection 1"
ip addr show eth0
ip route
ping -c 3 192.168.1.1
sudo ip route add default via 192.168.1.1 dev eth0
ip route
ping -c 3 8.8.8.8
traceroute -n 8.8.8.8

sudo docker restart recursive-internet
dig @172.30.0.110 +dnssec unam.mx SOA
```

## 10. Respaldo del proyecto

```bash
cd /home/kali
cp -a dns-lab Desktop/dns-lab-parte1
sudo docker ps -a > Desktop/docker_estado_parte1.txt
tar -czf Desktop/respaldo_dns_parte1.tar.gz dns-lab Desktop/*.pcapng
ls -lh Desktop/respaldo_dns_parte1.tar.gz
```

## 11. Firma DNSSEC

> **Nota:** esta sección es una reconstrucción a partir de los archivos encontrados en el segundo backup (`Ksigned.+013+...`, `dsset-*`, `db.*.signed`), no es el historial exacto de comandos. El algoritmo `013` corresponde a ECDSAP256SHA256. Cada zona tiene dos pares de llaves, consistente con el esquema KSK/ZSK. 

### Firma de la zona root (`.`)
```bash
cd ~/dns-lab/root/zones
dnssec-keygen -a ECDSAP256SHA256 -n ZONE .
dnssec-keygen -f KSK -a ECDSAP256SHA256 -n ZONE .
dnssec-signzone -o . -3 $(head -c 1000 /dev/urandom | sha1sum | cut -c1-16) db.root
# genera: db.root.signed, dsset-.
```

### Firma de la zona "signed"
```bash
cd ~/dns-lab/signed/zones
dnssec-keygen -a ECDSAP256SHA256 -n ZONE signed
dnssec-keygen -f KSK -a ECDSAP256SHA256 -n ZONE signed
dnssec-signzone -o signed. -3 $(head -c 1000 /dev/urandom | sha1sum | cut -c1-16) db.signed
# genera: db.signed.signed, dsset-signed.
```

### Firma de la zona hija "beta.signed"
```bash
cd ~/dns-lab/beta/zones
dnssec-keygen -a ECDSAP256SHA256 -n ZONE beta.signed
dnssec-keygen -f KSK -a ECDSAP256SHA256 -n ZONE beta.signed
dnssec-signzone -o beta.signed. -3 $(head -c 1000 /dev/urandom | sha1sum | cut -c1-16) db.beta.signed
# genera: db.beta.signed.signed, dsset-beta.signed.
```

### Zona "gamma" (caso de prueba sin firmar)
`dns-lab/gamma/zones/db.gamma.signed` zona delegada sin firmar, para probar validación fallida
```bash
cd ~/dns-lab/gamma/zones
nano db.gamma.signed
named-checkzone gamma.signed. db.gamma.signed
```

### Registros DS y delegación
```bash
cat root/zones/dsset-. > signed_ds.txt
cat signed/zones/dsset-signed. > beta_ds.txt
# Los DS se insertan manualmente en el named.conf/zonefile del padre correspondiente
nano root/zones/db.root       # agregar DS de "signed"
nano signed/zones/db.signed   # agregar DS de "beta.signed"
```

### Contenedor recursivo con validación DNSSEC
```bash
mkdir -p recursive-dnssec/zones
nano recursive-dnssec/named.conf
cp root/zones/db.root.hints recursive-dnssec/zones/db.root.hints
sudo docker run -d --name recursive-dnssec --network dns-lab --ip 172.30.0.120 \
  -v "$PWD/recursive-dnssec/named.conf:/etc/bind/named.conf:ro" \
  -v "$PWD/recursive-dnssec/zones:/var/lib/bind:ro" \
  internetsystemsconsortium/bind9:9.20
```

## 12. Verificación con herramienta propia

```bash
cd ~/dns-lab
sudo docker start root signed test recursive1 recursive-dnssec
sudo docker ps --format "table {{.Names}}\t{{.Status}}"

grep -E "NSEC|NSEC3" signed/zones/db.signed.signed | head -15
grep -E "NSEC3|NSEC3PARAM" test/zones/db.test.signed | head -15
grep -E "unsigned|signed|test" root/zones/db.root | head -20
grep -E "beta|gamma|delta|epsilon|zeta" signed/zones/db.signed | head -20

cp herramienta_dnssec/verificador_dnssec.py Desktop/verificador_dnssec_backup.py

cd ~/dns-lab/herramienta_dnssec
python3 verificador_dnssec.py delta.signed | tee resultado_delta.txt
python3 verificador_dnssec.py expired.test | tee resultado_expired.txt
python3 verificador_dnssec.py nods.test | tee resultado_nods.txt
python3 verificador_dnssec.py badds.test | tee resultado_badds.txt

cd ~/dns-lab
sudo docker start root signed test recursive1 recursive-dnssec delta nods badds
dig @172.30.0.120 +dnssec delta.signed A
```
