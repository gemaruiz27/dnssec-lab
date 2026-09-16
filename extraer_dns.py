import subprocess
import glob
import os

archivos = glob.glob("/home/kali/Desktop/*.pcapng")

for archivo in archivos:
    print("\n" + "=" * 70)
    print("CAPTURA:", os.path.basename(archivo))
    print("=" * 70)

    comando = [
        "tshark",
        "-r", archivo,
        "-Y", "dns.flags.response == 1 && (dns.resp.type == 1 || dns.resp.type == 2 || dns.resp.type == 6)",
        "-T", "fields",

        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "dns.resp.name",
        "-e", "dns.resp.type",
        "-e", "dns.resp.ttl",
        "-e", "dns.a",
        "-e", "dns.ns",
        "-e", "dns.soa.mname",
        "-e", "dns.soa.rname",
        "-e", "dns.soa.serial_number",
        "-e", "dns.soa.refresh_interval",
        "-e", "dns.soa.retry_interval",
        "-e", "dns.soa.expire_limit",
        "-e", "dns.soa.minimum_ttl",

        "-E", "separator=|",
        "-E", "occurrence=a"
    ]

    resultado = subprocess.run(
        comando,
        capture_output=True,
        text=True
    )

    for linea in resultado.stdout.splitlines():
        campos = linea.split("|")

        while len(campos) < 15:
            campos.append("")

        frame = campos[0]
        origen = campos[1]
        destino = campos[2]
        nombre = campos[3]
        tipo = campos[4]
        ttl = campos[5]
        direccion_a = campos[6]
        servidor_ns = campos[7]

        if "6" in tipo:
            tipo_texto = "SOA"
        elif "2" in tipo:
            tipo_texto = "NS"
        elif "1" in tipo:
            tipo_texto = "A"
        else:
            tipo_texto = tipo

        print(f"\nFrame: {frame}")
        print(f"Origen: {origen}")
        print(f"Destino: {destino}")
        print(f"Nombre: {nombre}")
        print(f"Tipo: {tipo_texto}")
        print(f"TTL: {ttl}")

        if direccion_a:
            print(f"Direccion A: {direccion_a}")

        if servidor_ns:
            print(f"Servidor NS: {servidor_ns}")

        if campos[8]:
            print(f"SOA servidor primario: {campos[8]}")
            print(f"SOA administrador: {campos[9]}")
            print(f"SOA serial: {campos[10]}")
            print(f"SOA refresh: {campos[11]}")
            print(f"SOA retry: {campos[12]}")
            print(f"SOA expire: {campos[13]}")
            print(f"SOA minimum TTL: {campos[14]}")
