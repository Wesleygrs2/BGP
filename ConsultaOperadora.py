import paramiko
import time
import re
from tabulate import tabulate

# ====== DADOS DE ACESSO ======
ip = "172.31.253.254"
usuario = "n2akto"
senha = "6aTaGa@kt0"

# ====== OPERADORAS ======
OPERADORAS = ["OI", "TIM", "EMBRATEL1", "EMBRATEL2", "BEMOL_OPENCDN"]

# ====== DEBUG (mostra saída bruta do roteador, útil para testes) ======
DEBUG = False


# ==========================================================
# Função: executar_comando
# Objetivo: enviar um comando para o roteador e capturar a saída completa
# ==========================================================
def executar_comando(conn, comando):
    conn.send(comando + "\n")  # envia o comando via SSH
    time.sleep(1)
    saida = ""

    while True:
        time.sleep(0.4)
        if conn.recv_ready():
            # lê o buffer de dados que chega do roteador
            chunk = conn.recv(65535).decode("utf-8", errors="ignore")
            saida += chunk

            # caso o roteador mostre “--- More ---”, envia espaço para continuar
            if "--- More ---" in chunk:
                conn.send(" ")
            # quando o prompt (<>) reaparece, significa que terminou
            elif re.search(r"<.*?>", chunk):
                break
        else:
            break

    if DEBUG:
        print("\n[DEBUG] Saída bruta:\n", saida, "\n[END DEBUG]\n")

    return saida


# ==========================================================
# Função: calcular_peso_aspath
# Objetivo: contar quantos ASNs existem no campo AS-Path (prepend)
# ==========================================================
def calcular_peso_aspath(aspath_str):
    if not aspath_str or aspath_str in ["-", "NONE"]:
        return 0
    return len(re.findall(r"\d+", aspath_str))  # conta quantos números há no AS-PATH


# ==========================================================
# Função: parsear_saida
# Objetivo: ler a saída “display route-policy” e extrair informações
# ==========================================================
def parsear_saida(saida, operadora, tipo_ip):
    blocos = []  # lista final de blocos (cada cliente vira um dicionário)
    bloco_atual = None  # armazena temporariamente o bloco que está sendo lido

    # percorre linha a linha da saída do roteador
    for linha in saida.splitlines():
        linha = linha.strip()
        if not linha:
            continue  # ignora linhas em branco

        # === 1️⃣ Identifica o início de um bloco de cliente ===
        # Exemplo no roteador: "permit : 1010"
        m_inicio = re.match(r"^(permit|deny)\s*:\s*(\d+)", linha, flags=re.IGNORECASE)
        if m_inicio:
            # se já havia um bloco anterior, finaliza ele e adiciona à lista
            if bloco_atual:
                bloco_atual["Peso Prepend"] = calcular_peso_aspath(
                    bloco_atual.get("AS-Path", "NONE")
                )
                blocos.append(bloco_atual)

            # captura ação (permit/deny) e código do cliente (ex: 1010)
            acao = m_inicio.group(1).upper()
            codigo = m_inicio.group(2)

            # cria um novo bloco para este cliente
            bloco_atual = {
                "Operadora": operadora,      # qual operadora (OI, TIM etc)
                "Código": codigo,            # número do cliente (ex: 1010)
                "Ação": "PERMIT" if acao == "PERMIT" else "DENY",
                "IP-Prefix": "-",            # preenchido mais tarde
                "AS-Path": "NONE",           # preenchido mais tarde
                "Peso Prepend": 0,
            }
            continue

        # === 2️⃣ Captura o nome do prefixo (cliente) ===
        # Exemplo: "if-match prefix-list CLIENTE1010-AS263434"
        if "if-match" in linha:
            m_pl = re.search(r"prefix-list\s+(\S+)", linha, flags=re.IGNORECASE)
            if m_pl:
                prefix = m_pl.group(1)  # pega o nome (CLIENTE1010-AS263434)
            else:
                parts = linha.split()
                prefix = parts[-1] if parts else "-"

            # atualiza o bloco atual com o nome do prefixo
            if bloco_atual is None:
                bloco_atual = {
                    "Operadora": operadora,
                    "Código": "0",
                    "Ação": "-",
                    "IP-Prefix": prefix,
                    "AS-Path": "NONE",
                    "Peso Prepend": 0,
                }
            else:
                bloco_atual["IP-Prefix"] = prefix
            continue

        # === 3️⃣ Captura o AS-Path (prepend) ===
        # Exemplo: "apply as-path 263434 263434 263434"
        if "apply as-path" in linha:
            aspath_part = linha.split("apply as-path", 1)[1].strip()
            # remove palavras “additive” ou “prepend”, se existirem
            aspath_part = re.sub(
                r"\b(additive|prepend)\b", "", aspath_part, flags=re.IGNORECASE
            ).strip()

            # adiciona o AS-Path ao bloco atual
            if bloco_atual is None:
                bloco_atual = {
                    "Operadora": operadora,
                    "Código": "0",
                    "Ação": "-",
                    "IP-Prefix": "-",
                    "AS-Path": aspath_part,
                    "Peso Prepend": calcular_peso_aspath(aspath_part),
                }
            else:
                bloco_atual["AS-Path"] = aspath_part
            continue

    # adiciona o último bloco lido (se existir)
    if bloco_atual:
        bloco_atual["Peso Prepend"] = calcular_peso_aspath(
            bloco_atual.get("AS-Path", "NONE")
        )
        blocos.append(bloco_atual)

    return blocos


# ==========================================================
# ====== EXECUÇÃO PRINCIPAL DO SCRIPT ======
# ==========================================================
print(f"🔌 Conectando ao roteador {ip} ...")
try:
    # 1️⃣ Cria conexão SSH com o roteador Huawei
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=usuario, password=senha, look_for_keys=False, allow_agent=False)
    conn = ssh.invoke_shell()

    # 2️⃣ Remove limitação de paginação (screen-length)
    time.sleep(1)
    conn.recv(65535)
    conn.send("screen-length 0 temporary\n")
    time.sleep(0.5)
    conn.recv(65535)
    print("✅ Conexão estabelecida.\n")

    # 3️⃣ Usuário escolhe tipo de rota
    print("Selecione o tipo de rota:")
    print("1️⃣  IPv4")
    print("2️⃣  IPv6")
    tipo_opcao = input("\nDigite a opção desejada (1 ou 2): ").strip()
    tipo_ip = "4" if tipo_opcao == "1" else "6" if tipo_opcao == "2" else None
    if not tipo_ip:
        print("❌ Opção inválida.")
        conn.close()
        ssh.close()
        exit()

    todos_blocos = []  # lista com todos os blocos de todas as operadoras

    # 4️⃣ Executa comando em cada operadora e coleta a saída
    for operadora in OPERADORAS:
        comando = f"display route-policy OUT-IPV{tipo_ip}-{operadora}"
        print(f"\n📡 Coletando políticas de: {operadora} (IPv{tipo_ip})")
        saida = executar_comando(conn, comando)

        # verifica se a saída contém algum bloco (permit/deny)
        if not re.search(r"(permit|deny)\s*:", saida, flags=re.IGNORECASE):
            continue

        # analisa o texto e converte em blocos estruturados
        blocos = parsear_saida(saida, operadora, tipo_ip)
        if blocos:
            todos_blocos.extend(blocos)

    # encerra a sessão SSH
    conn.close()
    ssh.close()
    print("\n🔒 Conexão encerrada.\n")

    # 5️⃣ Filtra IPv4 e IPv6 corretamente
    if tipo_ip == "4":
        todos_blocos = [
            b for b in todos_blocos if b["IP-Prefix"] != "-" and ":" not in b["IP-Prefix"]
        ]
    else:
        todos_blocos = [
            b
            for b in todos_blocos
            if b["IP-Prefix"] != "-"
            and (":" in b["IP-Prefix"] or re.search(r"v6", b["IP-Prefix"], re.IGNORECASE))
        ]

    if not todos_blocos:
        print("⚠️ Nenhum dado de política encontrado para esse tipo.")
        exit()

    # 6️⃣ Ordena blocos por operadora e código numérico
    todos_blocos.sort(
        key=lambda x: (x["Operadora"], int(x["Código"]) if x["Código"].isdigit() else 0)
    )

    # ==========================================================
    # ======= EXIBIÇÃO DAS TABELAS (GERAL e OPENCDN) ===========
    # ==========================================================
    blocos_cnd = [b for b in todos_blocos if "OPENCDN" in b["Operadora"].upper()]
    blocos_geral = [b for b in todos_blocos if "OPENCDN" not in b["Operadora"].upper()]

    # === Monta tabela geral (sem repetição de prefixo) ===
    vistos_geral = set()
    lista_geral = []
    for b in blocos_geral:
        prefix_name = b["IP-Prefix"]
        nome_base = prefix_name.split("-")[0] if "-" in prefix_name else prefix_name
        if nome_base not in vistos_geral:
            lista_geral.append((b["Código"], b["IP-Prefix"]))
            vistos_geral.add(nome_base)

    tabela_geral = tabulate(lista_geral, headers=["Código", "IP-Prefix"], tablefmt="fancy_grid")

    # === Monta tabela OPENCDN apenas se for IPv4 ===
    if tipo_ip == "4" and blocos_cnd:
        vistos_cnd = set()
        lista_cnd = []
        for b in blocos_cnd:
            prefix_name = b["IP-Prefix"]
            nome_base = prefix_name.split("-")[0] if "-" in prefix_name else prefix_name
            if nome_base not in vistos_cnd:
                lista_cnd.append((b["Código"], b["IP-Prefix"]))
                vistos_cnd.add(nome_base)
        tabela_cnd = tabulate(lista_cnd, headers=["Código", "IP-Prefix (OPENCDN)"], tablefmt="fancy_grid")
    else:
        tabela_cnd = ""  # IPv6 ainda não tem OPENCDN configurado

    # === Exibe as tabelas lado a lado (ou só a geral se não houver CND) ===
    linhas_geral = tabela_geral.split("\n")
    linhas_cnd = tabela_cnd.split("\n") if tabela_cnd else []
    max_linhas = max(len(linhas_geral), len(linhas_cnd)) if linhas_cnd else len(linhas_geral)
    linhas_geral += [""] * (max_linhas - len(linhas_geral))
    if linhas_cnd:
        linhas_cnd += [""] * (max_linhas - len(linhas_cnd))

    print("\n📋 Listas de Clientes (Geral e OPENCDN lado a lado):\n")
    if linhas_cnd:
        for l1, l2 in zip(linhas_geral, linhas_cnd):
            print(f"{l1:<70} {l2}")
    else:
        for l1 in linhas_geral:
            print(l1)

    # ==========================================================
    # ====== CONSULTA INTERATIVA POR CÓDIGO DE CLIENTE ==========
    # ==========================================================
    while True:
        codigo_selecionado = input(
            "\n🔎 Digite o código do cliente (ou 'sair' para encerrar): "
        ).strip()

        if codigo_selecionado.lower() == "sair":
            print("\n👋 Encerrando o programa.")
            break

        # filtra os blocos que correspondem ao código digitado
        blocos_filtrados = [b for b in todos_blocos if b["Código"] == codigo_selecionado]
        if not blocos_filtrados:
            print("⚠️ Código não encontrado. Tente novamente.")
            continue

        # mostra tabela com detalhes do cliente
        print(f"\n📊 Informações do Cliente Código {codigo_selecionado}")
        tabela = tabulate(
            [
                [b["Ação"], b["IP-Prefix"], b["AS-Path"], b["Peso Prepend"], b["Operadora"]]
                for b in blocos_filtrados
            ],
            headers=["Ação", "IP-Prefix", "AS-Path", "Qtd ASNs (Prepend)", "Operadora"],
            tablefmt="fancy_grid",
        )
        print(tabela)

        # escolhe a operadora preferencial (menor prepend)
        blocos_permitidos = [b for b in blocos_filtrados if b["Ação"] == "PERMIT"]
        if blocos_permitidos:
            menor_prepend = min(b["Peso Prepend"] for b in blocos_permitidos)
            melhores = [b for b in blocos_permitidos if b["Peso Prepend"] == menor_prepend]

            print("\n🏁 Operadora preferencial para saída BGP (entre PERMITs):")
            for b in melhores:
                print(f"➡️  {b['Operadora']} ({b['IP-Prefix']}) — {b['Peso Prepend']} ASNs")
        else:
            print("\n🚫 Nenhuma rota PERMIT encontrada para esse código.")

except Exception as e:
    print(f"\n❌ Erro durante a execução: {e}")
