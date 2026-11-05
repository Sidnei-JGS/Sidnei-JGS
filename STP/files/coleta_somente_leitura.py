#!/usr/bin/env python3
"""
Coleta SOMENTE LEITURA via SSH (Paramiko) para switches HP Comware, Aruba CX,
ArubaOS-Switch (ProCurve) e FortiSwitch.

Seguranca:
  - Executa apenas comandos de consulta (whitelist abaixo). Qualquer outro
    comando e recusado ANTES de abrir a conexao.
  - Credenciais chegam por variavel de ambiente (credencial de maquina do AWX).
    Nada e gravado em disco.

Variaveis de ambiente:
  TARGET_HOST, TARGET_USER, TARGET_PASS, TARGET_PORT (padrao 22)
  COMANDOS     JSON com a lista de comandos, ex: ["display stp brief"]
  LEGACY_SSH   "1" para habilitar algoritmos antigos (Comware 5 / ProCurve)
  TIMEOUT_CMD  segundos maximos por comando (padrao 60)

Saida (stdout):
  ##### CMD: <comando>        seguido da saida bruta do comando
  RESUMO_JSON: {...}          ultima linha, com o resumo extraido
"""
import json
import os
import re
import sys
import time

# ---------------------------------------------------------------------------
# Whitelist: so comandos de consulta ou de paginacao da propria sessao.
# ---------------------------------------------------------------------------
PERMITIDOS = re.compile(
    r"^(display|show|get|diagnose stp|screen-length disable|no page|terminal length 0)\b",
    re.IGNORECASE,
)
# separadores que permitiriam encadear um segundo comando
PROIBIDOS = re.compile(r"[;\n\r`&$]")
# unico uso de "|" aceito: filtro de saida
FILTROS_OK = re.compile(r"^\s*(include|exclude|begin|grep|section|count)\b", re.IGNORECASE)

MORE = re.compile(r"(-+\s*more\s*-+|--more--|-- more --|press any key to continue|\(q\)uit)",
                  re.IGNORECASE)
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[=>EM78]|\x08")


def validar(comandos):
    for c in comandos:
        c2 = c.strip()
        partes = c2.split("|")
        if (not PERMITIDOS.match(c2) or PROIBIDOS.search(c2)
                or not all(FILTROS_OK.match(p) for p in partes[1:])):
            raise ValueError(f"Comando recusado pela whitelist somente leitura: {c!r}")


def ler(canal, timeout, ocioso=2.0):
    """Le ate o canal ficar ocioso, respondendo prompts de paginacao."""
    buf, inicio, ultimo = "", time.time(), time.time()
    while True:
        if canal.recv_ready():
            dado = canal.recv(65535).decode("utf-8", errors="ignore")
            buf += dado
            ultimo = time.time()
            if MORE.search(dado[-120:]):
                canal.send(" ")
            continue
        if time.time() - ultimo > ocioso or time.time() - inicio > timeout:
            return buf
        time.sleep(0.1)


def limpar(texto):
    texto = ANSI.sub("", texto)
    texto = MORE.sub("", texto)
    return "\n".join(l.rstrip() for l in texto.replace("\r", "").split("\n"))


# ---------------------------------------------------------------------------
# Extracao do resumo (melhor esforco; a saida bruta sempre vai junto)
# ---------------------------------------------------------------------------
# Regras das regex: depois de ":" usar [ \t]* (nunca \s*), senao um campo VAZIO
# "pula" para a linha seguinte e captura o texto errado.
H = r"[ \t]*"
PADROES = {
    "modo": [
        r"\[Mode\s+(\w+)\]",                                  # Comware
        r"Protocol" + H + r":?" + H + r"(MSTP|RSTP|RPVST\+?|STP)\b",  # Aruba CX / ProCurve
        r"Protocol Std\." + H + ":" + H + r"IEEE" + H + r"(802\.1\w+)",
        r"^" + H + r"(MST) Instance Information",              # FortiSwitch (sempre MSTP)
    ],
    "bridge": [
        r"CIST Bridge" + H + ":" + H + r"(\S+)",                # Comware
        r"Bridge ID\s+Priority" + H + ":" + H + r"(\d+)\s+MAC-Address" + H + ":" + H + r"(\S+)",  # Aruba CX
        r"Bridge ID" + H + ":" + H + r"(\S+)",
        r"Switch MAC Address" + H + ":?" + H + r"(\S+)",        # ProCurve
        r"Bridge MAC" + H + r"([0-9a-f]{12})",                  # FortiSwitch
    ],
    "root": [
        r"CIST Root/ERPC" + H + ":" + H + r"(\S+)",             # Comware
        r"Root ID\s+Priority" + H + ":" + H + r"(\d+)\s+MAC-Address" + H + ":" + H + r"(\S+)",    # Aruba CX
        r"CST Root MAC Address" + H + ":?" + H + r"(\S+)",      # ProCurve
        r"^" + H + r"Root" + H + r"MAC" + H + r"([0-9a-f]{12})",  # FortiSwitch
    ],
    "regiao_nome": [
        r"Region name" + H + ":" + H + r"(\S.*)",
        r"MST config ID" + H + ":" + H + r"(\S.*)",
        r"Configuration Name" + H + ":" + H + r"(\S.*)",
    ],
    "regiao_revisao": [
        r"Revision level" + H + ":" + H + r"(\d+)",
        r"MST config revision" + H + ":" + H + r"(\d+)",
        r"Configuration Revision" + H + ":" + H + r"(\d+)",
    ],
    "regiao_digest": [
        r"Configuration digest" + H + ":" + H + r"(\S+)",
        r"MST config digest" + H + ":" + H + r"(\S+)",
    ],
    "bpdu_protection_global": [
        r"BPDU-Protection" + H + ":" + H + r"(\w+)",
    ],
    "ultimo_tc": [
        r"Time since last TC" + H + ":" + H + r"(\S.*)",                     # Comware
        r"Time since last (?:topology )?change" + H + ":?" + H + r"(\S.*)",  # Aruba CX / ProCurve
        r"TCN Events.*?Received" + H + r"\d+" + H + r"\((.*?)" + H + r"ago\)",  # FortiSwitch
    ],
}

# contadores de mudanca de topologia (TC): a primeira ocorrencia e a global/CIST
PADROES_TC = [
    r"TC or TCN received" + H + ":" + H + r"(\d+)",          # Comware
    r"Topology [Cc]hange [Cc]ount" + H + ":?" + H + r"(\d+)",  # Aruba CX / ProCurve
    r"Number of topology changes" + H + ":?" + H + r"(\d+)",
    r"TCN Events.*?Received" + H + r"(\d+)",                 # FortiSwitch
]
# TCs gerados pelo PROPRIO switch (so o FortiSwitch informa direto)
PADROES_TC_GERADOS = [
    r"TCN Events" + H + r"Triggered" + H + r"(\d+)",
]
FLAGS = re.IGNORECASE | re.MULTILINE


def extrair(texto):
    resumo = {}
    for campo, padroes in PADROES.items():
        for p in padroes:
            m = re.search(p, texto, FLAGS)
            if m:
                resumo[campo] = ".".join(g.strip() for g in m.groups() if g)
                break
        else:
            resumo[campo] = None
    # TC: primeira ocorrencia = global/CIST
    for campo, padroes in (("tc_recebidos", PADROES_TC), ("tc_gerados", PADROES_TC_GERADOS)):
        resumo[campo] = None
        for p in padroes:
            m = re.search(p, texto, FLAGS)
            if m:
                resumo[campo] = int(m.group(1))
                break
    # normaliza o modo
    if resumo["modo"]:
        modo = resumo["modo"].upper()
        resumo["modo"] = {"MST": "MSTP", "802.1S": "MSTP", "802.1W": "RSTP", "802.1D": "STP"}.get(modo, modo)
    # Contagem de protecoes SO em linhas de configuracao (stp ... / spanning-tree ... / set ...),
    # para nao contar linhas de status como "BPDU-Protection : Disabled".
    config = "\n".join(l for l in texto.split("\n")
                       if re.match(r"^\s*(stp|spanning-tree|set)\s", l, re.IGNORECASE)
                       and not re.search(r"\b(disable|disabled|undo)\b", l, re.IGNORECASE))
    contar = lambda p: len(re.findall(p, config, re.IGNORECASE))
    resumo["linhas_edge"] = contar(r"edged-port|admin-edge|edge-port\s+enabled")
    resumo["linhas_bpdu_guard"] = contar(r"bpdu-guard|bpdu-protection")
    resumo["linhas_root_guard"] = contar(r"root-guard|root-protection")
    resumo["linhas_loop_guard"] = contar(r"loop-protect|loop-guard|loop-protection")
    return resumo


def main():
    import paramiko  # importado aqui para os testes do parser rodarem sem paramiko

    comandos = json.loads(os.environ["COMANDOS"])
    validar(comandos)

    if os.environ.get("LEGACY_SSH") == "1":
        # ACRESCENTA algoritmos antigos (Comware 5 / ProCurve) depois dos modernos,
        # sem remover os modernos (Comware 7 / HPE 5130 negocia os atuais).
        T = paramiko.Transport
        # so acrescenta o que esta versao do paramiko suporta (o 4.x removeu DSS, por exemplo)
        def acrescentar(atual, extra, suportados):
            return tuple(atual) + tuple(a for a in extra if a not in atual and a in suportados)
        T._preferred_kex = acrescentar(T._preferred_kex, (
            "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1",
            "diffie-hellman-group1-sha1"), T._kex_info)
        T._preferred_ciphers = acrescentar(T._preferred_ciphers, (
            "aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc"), T._cipher_info)
        T._preferred_keys = acrescentar(T._preferred_keys, ("ssh-rsa", "ssh-dss"), T._key_info)
        if "ssh-rsa" not in T._key_info:
            sys.stderr.write(
                f"AVISO: paramiko {paramiko.__version__} nao suporta ssh-rsa/SHA-1. Comware 5 e ProCurve "
                "antigos podem recusar a conexao; use o mesmo Execution Environment dos playbooks HP atuais "
                "(paramiko < 4).\n")

    timeout_cmd = int(os.environ.get("TIMEOUT_CMD", 60))
    cliente = paramiko.SSHClient()
    cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cliente.connect(
        os.environ["TARGET_HOST"],
        port=int(os.environ.get("TARGET_PORT", 22)),
        username=os.environ["TARGET_USER"],
        password=os.environ["TARGET_PASS"],
        look_for_keys=False,
        allow_agent=False,
        timeout=20,
        banner_timeout=30,
        auth_timeout=30,
    )
    canal = cliente.invoke_shell(width=250, height=1000)
    ler(canal, 15)  # banner / "press any key"

    completo = []
    for cmd in comandos:
        canal.send(cmd + "\n")
        saida = limpar(ler(canal, timeout_cmd))
        print(f"##### CMD: {cmd}")
        print(saida)
        completo.append(saida)

    try:
        canal.send("quit\n" if os.environ.get("LEGACY_SSH") == "1" else "exit\n")
    finally:
        cliente.close()

    print("RESUMO_JSON: " + json.dumps(extrair("\n".join(completo)), ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # erro claro no log do AWX, sem expor credencial
        sys.stderr.write(f"ERRO_DETALHADO: {type(e).__name__} -> {e}\n")
        sys.exit(1)
