#!/usr/bin/env python3

import sys
from datetime import datetime, timezone

import dns.message
import dns.query
import dns.rdatatype
import dns.rcode
import dns.flags
import dns.name
import dns.dnssec


# ============================================================
# CONFIGURACION DEL LABORATORIO
# ============================================================

RECURSIVO_DNSSEC = "172.30.0.120"
RECURSIVO_SIN_DNSSEC = "172.30.0.100"

# Trust Anchor de la raiz privada del laboratorio
TRUST_ANCHOR = {
    "key_tag": 33493,
    "algorithm": 13,
    "digest_type": 2,
    "digest": "D52E4AB2F35B2931983579C3056F994F71D0E52FA26E091853DEF075181B111D",
}

ALGORITMOS_AUTORIZADOS = {
    8: "RSASHA256",
    10: "RSASHA512",
    13: "ECDSAP256SHA256",
    14: "ECDSAP384SHA384",
    15: "ED25519",
    16: "ED448",
}


# ============================================================
# FUNCIONES BASICAS DNS
# ============================================================

def nombre_absoluto(nombre):
    if nombre == ".":
        return "."
    return nombre.rstrip(".") + "."


def consultar(servidor, nombre, tipo, cd=True, recursion=True):
    nombre = nombre_absoluto(nombre)

    q = dns.message.make_query(
        nombre,
        tipo,
        want_dnssec=True
    )

    if cd:
        q.flags |= dns.flags.CD

    if not recursion:
        q.flags &= ~dns.flags.RD

    return dns.query.udp(q, servidor, timeout=4)


def rrsets_tipo(respuesta, tipo):
    numero = dns.rdatatype.from_text(tipo)
    encontrados = []

    for seccion in [
        respuesta.answer,
        respuesta.authority,
        respuesta.additional
    ]:
        for rrset in seccion:
            if rrset.rdtype == numero:
                encontrados.append(rrset)

    return encontrados


def padre(nombre):
    nombre = dns.name.from_text(nombre_absoluto(nombre))

    if nombre == dns.name.root:
        return None

    return nombre.parent().to_text()


def cadena_dominios(nombre):
    actual = nombre_absoluto(nombre)
    resultado = []

    while True:
        resultado.append(actual)

        if actual == ".":
            break

        actual = padre(actual)

    return list(reversed(resultado))


def fecha_dnssec(valor):
    try:
        return datetime.fromtimestamp(
            valor,
            timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(valor)


# ============================================================
# DNSKEY
# ============================================================

def analizar_dnskey(zona):
    print("\n=== DNSKEY ===")

    try:
        respuesta = consultar(
            RECURSIVO_DNSSEC,
            zona,
            "DNSKEY",
            cd=True
        )
    except Exception as e:
        print("[ERROR] No fue posible obtener DNSKEY:", e)
        return []

    dnskeys = []

    for rrset in rrsets_tipo(respuesta, "DNSKEY"):
        print(f"TTL DNSKEY: {rrset.ttl}")

        for clave in rrset:
            tag = dns.dnssec.key_id(clave)
            algoritmo = int(clave.algorithm)
            flags = int(clave.flags)

            if flags == 257:
                uso = "KSK / SEP"
            elif flags == 256:
                uso = "ZSK"
            else:
                uso = f"FLAGS={flags}"

            nombre_alg = ALGORITMOS_AUTORIZADOS.get(
                algoritmo,
                "NO AUTORIZADO / DESCONOCIDO"
            )

            autorizado = algoritmo in ALGORITMOS_AUTORIZADOS

            print(
                f"\nKey Tag: {tag}\n"
                f"Tipo: {uso}\n"
                f"Algoritmo: {algoritmo} ({nombre_alg})"
            )

            if autorizado:
                print("[OK] Algoritmo autorizado")
            else:
                print("[ERROR] Algoritmo no autorizado")

            dnskeys.append(clave)

    if not dnskeys:
        print("[!] No se encontraron DNSKEY")

    return dnskeys


# ============================================================
# RRSIG
# ============================================================

def analizar_rrsig(zona):
    print("\n=== RRSIG ===")

    try:
        respuesta = consultar(
            RECURSIVO_DNSSEC,
            zona,
            "DNSKEY",
            cd=True
        )
    except Exception as e:
        print("[ERROR]", e)
        return

    ahora = int(datetime.now(timezone.utc).timestamp())

    firmas = rrsets_tipo(respuesta, "RRSIG")

    if not firmas:
        print("[!] No se encontraron RRSIG")
        return

    for rrset in firmas:
        print(f"TTL RRSIG: {rrset.ttl}")

        for firma in rrset:
            cubre = dns.rdatatype.to_text(
                firma.type_covered
            )

            print("\nRRSet firmado:", cubre)
            print("Key Tag:", firma.key_tag)
            print("Algoritmo:", firma.algorithm)
            print("Firmante:", firma.signer)
            print(
                "Inicio:",
                fecha_dnssec(firma.inception)
            )
            print(
                "Expiracion:",
                fecha_dnssec(firma.expiration)
            )

            if ahora < firma.inception:
                print("[ERROR] Firma aun no valida")
            elif ahora > firma.expiration:
                print("[ERROR] Firma EXPIRADA")
            else:
                print("[OK] Firma vigente")


# ============================================================
# NSEC / NSEC3
# ============================================================

def analizar_negacion(zona):
    print("\n=== NSEC / NSEC3 ===")

    usa_nsec = False
    usa_nsec3 = False

    try:
        respuesta_nsec = consultar(
            RECURSIVO_DNSSEC,
            zona,
            "NSEC",
            cd=True
        )

        nsecs = rrsets_tipo(
            respuesta_nsec,
            "NSEC"
        )

        if nsecs:
            usa_nsec = True

            for rrset in nsecs:
                print(
                    f"[OK] NSEC detectado - TTL {rrset.ttl}"
                )

    except Exception:
        pass

    try:
        respuesta_nsec3param = consultar(
            RECURSIVO_DNSSEC,
            zona,
            "NSEC3PARAM",
            cd=True
        )

        parametros = rrsets_tipo(
            respuesta_nsec3param,
            "NSEC3PARAM"
        )

        if parametros:
            usa_nsec3 = True

            for rrset in parametros:
                print(
                    f"[OK] NSEC3PARAM detectado - TTL {rrset.ttl}"
                )

                for registro in rrset:
                    print(
                        "Parametros:",
                        registro.to_text()
                    )

    except Exception:
        pass

    if usa_nsec:
        print(
            "[!] La zona utiliza NSEC: "
            "los nombres pueden facilitar zone walking."
        )

    if usa_nsec3:
        print(
            "[OK] La zona utiliza NSEC3: "
            "los nombres aparecen mediante hashes."
        )

    if not usa_nsec and not usa_nsec3:
        print(
            "[!] No se detecto NSEC ni NSEC3PARAM "
            "en la consulta."
        )

    return usa_nsec, usa_nsec3


# ============================================================
# DS Y CADENA DE CONFIANZA
# ============================================================

def dnskeys_de(zona):
    respuesta = consultar(
        RECURSIVO_DNSSEC,
        zona,
        "DNSKEY",
        cd=True
    )

    resultado = []

    for rrset in rrsets_tipo(respuesta, "DNSKEY"):
        resultado.extend(list(rrset))

    return resultado


def ds_de(zona):
    respuesta = consultar(
        RECURSIVO_DNSSEC,
        zona,
        "DS",
        cd=True
    )

    resultado = []

    for rrset in rrsets_tipo(respuesta, "DS"):
        resultado.extend(list(rrset))

    return resultado


def comprobar_ds(zona):
    zona = nombre_absoluto(zona)

    try:
        registros_ds = ds_de(zona)
    except Exception:
        registros_ds = []

    try:
        claves = dnskeys_de(zona)
    except Exception:
        claves = []

    if not registros_ds:
        return "SIN_DS"

    for ds in registros_ds:
        for clave in claves:

            try:
                generado = dns.dnssec.make_ds(
                    zona,
                    clave,
                    ds.digest_type
                )

                if (
                    generado.key_tag == ds.key_tag
                    and
                    generado.algorithm == ds.algorithm
                    and
                    generado.digest_type == ds.digest_type
                    and
                    generado.digest == ds.digest
                ):
                    return "VALIDO"

            except Exception:
                continue

    return "INVALIDO"


def comprobar_trust_anchor():
    try:
        claves = dnskeys_de(".")
    except Exception:
        return False

    for clave in claves:

        if (
            dns.dnssec.key_id(clave)
            == TRUST_ANCHOR["key_tag"]
            and
            int(clave.algorithm)
            == TRUST_ANCHOR["algorithm"]
        ):

            try:
                ds = dns.dnssec.make_ds(
                    ".",
                    clave,
                    TRUST_ANCHOR["digest_type"]
                )

                if (
                    ds.digest.hex().upper()
                    == TRUST_ANCHOR["digest"]
                ):
                    return True

            except Exception:
                pass

    return False


def analizar_cadena(zona):
    print("\n=== CADENA DE CONFIANZA ===")

    cadena = cadena_dominios(zona)

    print(" -> ".join(cadena))

    root_ok = comprobar_trust_anchor()

    if root_ok:
        print("[OK] Trust Anchor de la raiz coincide")
    else:
        print("[ERROR] Trust Anchor de la raiz NO coincide")
        return "BOGUS"

    estado = "SECURE"

    for dominio in cadena[1:]:

        resultado = comprobar_ds(dominio)

        if resultado == "VALIDO":
            print(
                f"[OK] {dominio}: "
                "DS coincide con DNSKEY"
            )

        elif resultado == "SIN_DS":
            print(
                f"[!] {dominio}: "
                "no existe DS en el padre"
            )
            estado = "INSECURE"

        else:
            print(
                f"[ERROR] {dominio}: "
                "DS NO coincide con DNSKEY"
            )
            return "BOGUS"

    return estado


# ============================================================
# VALIDACION REAL DEL RESOLVER
# ============================================================

def comprobar_validador(zona):
    print("\n=== RESPUESTA DEL RECURSIVO DNSSEC ===")

    try:
        respuesta = consultar(
            RECURSIVO_DNSSEC,
            zona,
            "DNSKEY",
            cd=False
        )

        codigo = dns.rcode.to_text(
            respuesta.rcode()
        )

        ad = bool(
            respuesta.flags & dns.flags.AD
        )

        print("Estado:", codigo)
        print("AD:", "SI" if ad else "NO")

        if codigo == "SERVFAIL":
            return "BOGUS"

        if ad:
            return "SECURE"

        return "INSECURE"

    except Exception as e:
        print("[ERROR]", e)
        return "ERROR"


# ============================================================
# TTL
# ============================================================

def mostrar_ttl(zona):
    print("\n=== TTL ===")

    tipos = [
        "DNSKEY",
        "DS",
        "NSEC",
        "NSEC3PARAM"
    ]

    for tipo in tipos:

        try:
            respuesta = consultar(
                RECURSIVO_DNSSEC,
                zona,
                tipo,
                cd=True
            )

            encontrados = rrsets_tipo(
                respuesta,
                tipo
            )

            for rrset in encontrados:
                print(
                    f"{tipo}: {rrset.ttl} segundos"
                )

        except Exception:
            pass


# ============================================================
# ZONE WALKING NSEC
# ============================================================

def obtener_autoritativo(zona):
    try:
        respuesta = consultar(
            RECURSIVO_SIN_DNSSEC,
            zona,
            "NS",
            cd=True
        )

        ns_nombre = None

        for rrset in rrsets_tipo(respuesta, "NS"):
            for registro in rrset:
                ns_nombre = registro.target.to_text()
                break

        if not ns_nombre:
            return None

        respuesta_a = consultar(
            RECURSIVO_SIN_DNSSEC,
            ns_nombre,
            "A",
            cd=True
        )

        for rrset in rrsets_tipo(respuesta_a, "A"):
            for registro in rrset:
                return registro.address

    except Exception:
        pass

    return None


def zone_walk_nsec(zona, limite=15):
    print("\n=== PRUEBA DE ZONE WALKING ===")

    ip = obtener_autoritativo(zona)

    if not ip:
        print(
            "[!] No se pudo encontrar el "
            "servidor autoritativo."
        )
        return

    print("Autoritativo:", ip)

    actual = nombre_absoluto(zona)
    vistos = set()

    for _ in range(limite):

        if actual in vistos:
            break

        vistos.add(actual)

        try:
            respuesta = consultar(
                ip,
                actual,
                "NSEC",
                cd=True,
                recursion=False
            )
        except Exception:
            break

        nsecs = rrsets_tipo(
            respuesta,
            "NSEC"
        )

        if not nsecs:
            print(
                "[!] No fue posible seguir una "
                "cadena NSEC en texto claro."
            )
            return

        registro = list(nsecs[0])[0]

        siguiente = (
            registro.to_text()
            .split()[0]
        )

        print(
            f"{actual} -> {siguiente}"
        )

        siguiente = nombre_absoluto(siguiente)

        if siguiente == nombre_absoluto(zona):
            print(
                "[OK] Se completo el recorrido "
                "de la zona mediante NSEC."
            )
            return

        actual = siguiente

    print(
        "[!] Recorrido detenido por limite "
        "de seguridad."
    )


# ============================================================
# PROGRAMA PRINCIPAL
# ============================================================

def main():
    if len(sys.argv) != 2:
        print(
            "Uso:\n"
            "  python3 verificador_dnssec.py beta.signed"
        )
        sys.exit(1)

    zona = nombre_absoluto(sys.argv[1])

    print("=" * 65)
    print(" ANALIZADOR DNSSEC")
    print("=" * 65)
    print("Zona:", zona)

    analizar_dnskey(zona)
    analizar_rrsig(zona)

    usa_nsec, usa_nsec3 = analizar_negacion(zona)

    estado_cadena = analizar_cadena(zona)

    mostrar_ttl(zona)

    estado_resolver = comprobar_validador(zona)

    if usa_nsec:
        zone_walk_nsec(zona)

    if usa_nsec3:
        print("\n=== ZONE WALKING ===")
        print(
            "[OK] NSEC3 detectado. "
            "Los propietarios se representan mediante hashes, "
            "lo que mitiga la enumeracion directa que permite NSEC."
        )

    print("\n" + "=" * 65)

    if estado_resolver == "BOGUS":
        resultado = "BOGUS"
    elif estado_resolver == "SECURE":
        resultado = "SECURE"
    elif estado_cadena == "INSECURE":
        resultado = "INSECURE"
    else:
        resultado = estado_resolver

    print("RESULTADO FINAL:", resultado)
    print("=" * 65)


if __name__ == "__main__":
    main()

