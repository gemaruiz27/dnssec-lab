import subprocess

archivo = "/home/kali/Desktop/unam_recursivo_local.pcapng"

tipos = {
    "1": "A",
    "2": "NS",
    "6": "SOA",
    "28": "AAAA",
    "43": "DS",
    "46": "RRSIG",
    "47": "NSEC",
    "48": "DNSKEY",
    "50": "NSEC3"
}

comando = [
    "tshark",
    "-r", archivo,
    "-Y", "dns.flags.response == 1",
    "-T", "fields",
    "-e", "frame.number",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "dns.resp.name",
    "-e", "dns.resp.type",
    "-e", "dns.resp.ttl",
    "-E", "separator=|",
    "-E", "occurrence=a"
]

resultado = subprocess.run(
    comando,
    capture_output=True,
    text=True
)

print("=" * 70)
print("RESULTADOS DNSSEC - RECURSIVO LOCAL 172.30.0.110")
print("=" * 70)

for linea in resultado.stdout.splitlines():
    campos = linea.split("|")

    if len(campos) < 6:
        continue

    frame, origen, destino, nombre, tipo, ttl = campos[:6]

    tipos_encontrados = tipo.split(",")
    nombres_tipos = []

    for t in tipos_encontrados:
        nombres_tipos.append(tipos.get(t, t))

    print(f"\nFrame: {frame}")
    print(f"Origen: {origen}")
    print(f"Destino: {destino}")
    print(f"Nombre: {nombre}")
    print(f"Tipo: {', '.join(nombres_tipos)}")
    print(f"TTL: {ttl}")
