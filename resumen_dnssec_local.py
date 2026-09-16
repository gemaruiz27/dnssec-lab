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
    "-Y", "ip.src == 172.30.0.110 && dns.flags.response == 1",
    "-T", "fields",
    "-e", "dns.id",
    "-e", "dns.qry.name",
    "-e", "dns.qry.type",
    "-e", "dns.flags.rcode",
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

vistos = set()

print("=" * 75)
print("RESUMEN DNSSEC - RECURSIVO LOCAL 172.30.0.110")
print("=" * 75)

for linea in resultado.stdout.splitlines():

    if linea in vistos:
        continue

    vistos.add(linea)

    campos = linea.split("|")

    if len(campos) < 6:
        continue

    dns_id, nombre, consulta, rcode, respuestas, ttl = campos[:6]

    if "unam.mx" not in nombre:
        continue

    consulta_texto = tipos.get(consulta, consulta)

    respuestas_texto = []
    for tipo in respuestas.split(","):
        if tipo:
            respuestas_texto.append(tipos.get(tipo, tipo))

    if rcode == "3":
        estado = "NXDOMAIN"
    elif rcode == "0":
        estado = "NOERROR"
    else:
        estado = rcode

    print()
    print("Dominio:", nombre)
    print("Consulta:", consulta_texto)
    print("Estado:", estado)
    print("Registros en respuesta:", ", ".join(respuestas_texto))
    print("TTL:", ttl)
