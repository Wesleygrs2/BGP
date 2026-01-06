import time
import re
from tabulate import tabulate
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

# ====== DADOS DE ACESSO E CONSTANTES ======
ip = "172.31.253.254"
usuario = "n2akto"
senha = "6aTaGa@kt0"
DEVICE_TYPE = "huawei" 
GLOBAL_DELAY = 10 
TIMEOUT_COMANDO_LONGO = 180 

# ====== OPERADORAS E MAPAS ======
OPERADORAS_PRINCIPAIS = ["OI", "TIM", "EMBRATEL1", "EMBRATEL2"]
OPERADORAS = OPERADORAS_PRINCIPAIS + ["BEMOL_OPENCDN"]
MAP_OPERADORAS = {
    "1": "OI",
    "2": "TIM",
    "3": "EMBRATEL1",
    "4": "EMBRATEL2",
}
# AS-Path padrão para prepend (Seu próprio AS)
AS_LOCAL = "65000" 
# Regex flexível para o prompt de EXECUÇÃO
PROMPT_REGEX = r'<.+?>' 
DEBUG = False 

# ==========================================================
# FUNÇÕES DE SUPORTE
# ==========================================================

def calcular_peso_aspath(aspath_str):
    if not aspath_str or aspath_str in ["-", "NONE"]:
        return 0
    # Conta quantos ASNs estão no AS-Path (separados por espaço)
    return len(aspath_str.split())

def base_sem_sufixo(prefix):
    if prefix == "-":
        return "-"
    return re.sub(r"-\d{1,3}$", "", prefix or "")

def parsear_saida(saida, operadora, tipo_ip, sentido):
    blocos = []
    bloco_atual = None
    for linha in saida.splitlines():
        linha = linha.strip()
        if not linha or '--- More ---' in linha:
            continue
        m_inicio = re.match(r"^(permit|deny)\s*:\s*(\d+)", linha, flags=re.IGNORECASE)
        if m_inicio:
            if bloco_atual:
                if sentido == "OUT":
                    bloco_atual["Peso Prepend"] = calcular_peso_aspath(bloco_atual.get("AS-Path", "NONE"))
                if sentido == "IN" and bloco_atual.get("Código") == "9999":
                    bloco_atual["IP-Prefix"] = f"({bloco_atual.get('Operadora')})"
                blocos.append(bloco_atual)
            acao = m_inicio.group(1).upper()
            codigo = m_inicio.group(2)
            bloco_atual = {
                "Operadora": operadora,
                "Código": codigo,
                "Ação": "PERMIT" if acao == "PERMIT" else "DENY",
                "IP-Prefix": "-", 
                "AS-Path": "NONE",
                "Peso Prepend": 0,
                "Local-Preference": 0, 
            }
            continue
        if "if-match" in linha:
            m_pl = re.search(r"(ip-prefix|prefix-list)\s+(\S+)", linha, flags=re.IGNORECASE)
            prefix = m_pl.group(2) if m_pl else "-"
            if bloco_atual:
                bloco_atual["IP-Prefix"] = prefix
            continue
        if "apply as-path" in linha:
            aspath_part = linha.split("apply as-path", 1)[1].strip()
            # Captura a string exata usada para o prepend, ignorando 'additive' ou 'prepend'
            m_aspath = re.search(r"(?:\b(?:additive|prepend)\b\s*)?([\d\s,]+)", aspath_part, flags=re.IGNORECASE)
            if m_aspath:
                 aspath_str = m_aspath.group(1).strip()
            else:
                 aspath_str = "NONE"
            
            if bloco_atual:
                bloco_atual["AS-Path"] = aspath_str
            continue
        if "apply local-preference" in linha:
            m_lp = re.search(r"apply local-preference\s+(\d+)", linha, flags=re.IGNORECASE)
            if m_lp:
                lp_val = int(m_lp.group(1))
                if bloco_atual:
                    bloco_atual["Local-Preference"] = lp_val
            continue
    if bloco_atual:
        if sentido == "OUT":
            bloco_atual["Peso Prepend"] = calcular_peso_aspath(bloco_atual.get("AS-Path", "NONE"))
        if sentido == "IN" and bloco_atual.get("Código") == "9999":
            bloco_atual["IP-Prefix"] = f"({bloco_atual.get('Operadora')})"
        blocos.append(bloco_atual)
    return blocos


# ==========================================================
# FUNÇÕES DE CONFIGURAÇÃO
# ==========================================================
def configurar_local_preference(net_connect, operadora, tipo_ip, codigo, novo_lp):

    policy_name = f"IN-IPV{tipo_ip}-{operadora}"

    comandos = [
        "system-view", 
        f"route-policy {policy_name} permit node {codigo}",
        f"apply local-preference {novo_lp}",
        "commit",
        "quit"
    ]

    print(f"\n⚙️  Tentando configurar Local-Preference {novo_lp} para {policy_name} no código {codigo}...")
    
    try:
        saida = net_connect.send_config_set(
            comandos, 
            exit_config_mode=True, 
            cmd_verify=True
        )
        
        if "Error" in saida or "failed" in saida or "Unrecognized command" in saida:
            print(f"❌ Falha na configuração para {policy_name}, código {codigo}.")
            print(f"  Saída do erro:\n{saida}")
            return False
            
        print(f"✅ Sucesso! LP alterado para {novo_lp} na política {policy_name} (Código: {codigo}).")
        return True
        
    except Exception as e:
        print(f"❌ Erro durante a configuração: {e}")
        return False

def configurar_as_path_prepend(net_connect, operadora, tipo_ip, codigo, as_path_str):
    
    policy_name = f"OUT-IPV{tipo_ip}-{operadora}"
    
    # Normaliza a string (remove 'NONE' ou '0')
    as_path_str = as_path_str.strip().upper()
    
    # Verifica se deve remover o prepend (limpar)
    if not as_path_str or as_path_str in ["0", "NONE"]:
        comandos = [
            "system-view", 
            f"route-policy {policy_name} permit node {codigo}",
            "undo apply as-path",
            "commit",
            "quit"
        ]
        log_message = "Prepend removido/resetado"
    else:
        # Verifica se a string contém apenas números e espaços
        if not re.fullmatch(r"[\d\s]+", as_path_str):
             print("\n❌ A string do AS-Path contém caracteres inválidos. Use apenas números e espaços.")
             return False

        comandos = [
            "system-view", 
            f"route-policy {policy_name} permit node {codigo}",
            "undo apply as-path", # Remove a configuração anterior
            f"apply as-path prepend {as_path_str}",
            "commit",
            "quit"
        ]
        log_message = f"Prepend alterado para '{as_path_str}'"


    print(f"\n⚙️  Tentando configurar AS-Path para {policy_name} no código {codigo}...")
    
    try:
        saida = net_connect.send_config_set(
            comandos, 
            exit_config_mode=True, 
            cmd_verify=True
        )
        
        if "Error" in saida or "failed" in saida or "Unrecognized command" in saida:
            print(f"❌ Falha na configuração para {policy_name}, código {codigo}.")
            print(f"  Saída do erro:\n{saida}")
            return False
            
        print(f"✅ Sucesso! {log_message} na política {policy_name} (Código: {codigo}).")
        return True
        
    except Exception as e:
        print(f"❌ Erro durante a configuração: {e}")
        return False


# ==========================================================
# EXECUÇÃO PRINCIPAL
# ==========================================================
def bgp_visualizacao_e_configuracao():
    print(f"🔌 Conectando ao roteador {ip} via Netmiko...")
    net_connect = None
    
    # TRATAMENTO DE EXCEÇÕES DE CONEXÃO
    try:
        net_connect = ConnectHandler(
            device_type=DEVICE_TYPE,
            host=ip,
            username=usuario,
            password=senha,
            session_timeout=120, 
            timeout=120,
            global_delay_factor=GLOBAL_DELAY, 
            read_timeout_override=TIMEOUT_COMANDO_LONGO 
        )
        
        net_connect.send_command('\n', expect_string=PROMPT_REGEX, read_timeout=10) 
        net_connect.send_command('screen-length 0 temporary', expect_string=PROMPT_REGEX, read_timeout=10)
        time.sleep(1) 
        
        print("✅ Conexão estabelecida e pronta para coleta.\n")

    except NetmikoAuthenticationException:
        print("❌ FALHA DE AUTENTICAÇÃO: Verifique o usuário e a senha no código.")
        return 
    except NetmikoTimeoutException:
        print(f"❌ FALHA DE TEMPO LIMITE: O roteador {ip} não respondeu ao login dentro do tempo esperado.")
        return 
    except Exception as e:
        print(f"\n❌ Erro Inesperado durante a conexão: {e}")
        return

    # --- INÍCIO DA LÓGICA DE VISUALIZAÇÃO ---
    print("Selecione o sentido da política de rota:")
    print("1️⃣  Saída (OUT)")
    print("2️⃣  Entrada (IN)")
    sentido_opcao = input("\nDigite a opção desejada (1 ou 2): ").strip()
    sentido = "OUT" if sentido_opcao == "1" else "IN" if sentido_opcao == "2" else None
    if not sentido:
        print("❌ Opção inválida.")
        return
    
    print("\nSelecione o tipo de rota:")
    print("1️⃣  IPv4")
    print("2️⃣  IPv6")
    tipo_opcao = input("\nDigite a opção desejada (1 ou 2): ").strip()
    tipo_ip = "4" if tipo_opcao == "1" else "6" if tipo_opcao == "2" else None
    if not tipo_ip:
        print("❌ Opção inválida.")
        return

    todos_blocos = []

    for operadora in OPERADORAS:
        comando = f"display route-policy {sentido}-IPV{tipo_ip}-{operadora} | no-more" 
        saida = net_connect.send_command(comando, expect_string=PROMPT_REGEX, read_timeout=TIMEOUT_COMANDO_LONGO)
        
        if re.search(r"Error: The route-policy does not exist", saida, re.IGNORECASE):
            continue
        
        if not re.search(r"(permit|deny)\s*:", saida, flags=re.IGNORECASE):
            continue
            
        blocos = parsear_saida(saida, operadora, tipo_ip, sentido) 
        if blocos:
            todos_blocos.extend(blocos)

    if not todos_blocos:
        print("⚠️ Nenhum dado de política encontrado.")
        return
        
    if sentido == "OUT":
        if tipo_ip == "4":
            todos_blocos = [b for b in todos_blocos if b.get("IP-Prefix", "-") != "-" and ":" not in b.get("IP-Prefix", "-")]
        else: 
            todos_blocos = [b for b in todos_blocos if b.get("IP-Prefix", "-") != "-" and (":" in b.get("IP-Prefix", "-") or re.search(r"v6", b.get("IP-Prefix", ""), re.IGNORECASE))]
    else:
        if tipo_ip == "4":
            todos_blocos = [b for b in todos_blocos if b.get("Código") == "9999" and ":" not in b.get("IP-Prefix", "")]
        else:
            todos_blocos = [b for b in todos_blocos if b.get("Código") == "9999" and (":" in b.get("IP-Prefix", "-") or b.get("IP-Prefix", "-") == "-" or re.search(r"\(.+\)", b.get("IP-Prefix", "")))]

    if not todos_blocos:
        print(f"⚠️ Nenhum dado encontrado após filtragem.")
        return
        
    todos_blocos.sort(key=lambda x: (x["Operadora"], int(x["Código"]) if x["Código"].isdigit() else 0))

    blocos_geral = [b for b in todos_blocos if b["Operadora"] in OPERADORAS_PRINCIPAIS]
    blocos_outros = [b for b in todos_blocos if b["Operadora"] not in OPERADORAS_PRINCIPAIS]

    vistos_prefixo_codigo_geral = set()
    lista_geral = []
    for b in blocos_geral:
        prefix = b.get("IP-Prefix", "-")
        key = (b["Código"], base_sem_sufixo(prefix)) 
        if key not in vistos_prefixo_codigo_geral:
            display_prefix = prefix
            lista_geral.append((b["Código"], display_prefix))
            vistos_prefixo_codigo_geral.add(key)

    lista_geral.sort(key=lambda item: int(item[0]) if item[0].isdigit() else float("inf"))

    tabela_geral = tabulate(lista_geral, headers=["Código", f"IP-Prefix ({'IPv6' if tipo_ip == '6' else 'IPv4'} - 4 Operadoras)"], tablefmt="fancy_grid")
    
    lista_outros = []
    vistos_prefixo_codigo_outros = set()
    for b in blocos_outros:
        prefix = b.get("IP-Prefix", "-")
        key = (b["Código"], base_sem_sufixo(prefix))
        if key not in vistos_prefixo_codigo_outros:
            display_prefix = f"{prefix} ({b['Operadora']})"
            lista_outros.append((b["Código"], display_prefix))
            vistos_prefixo_codigo_outros.add(key)

    lista_outros.sort(key=lambda item: int(item[0]) if item[0].isdigit() else float("inf"))
    
    tabela_outros = tabulate(lista_outros, headers=["Código", "IP-Prefix (Outros Provedores)"], tablefmt="fancy_grid")

    linhas_geral = tabela_geral.split("\n")
    linhas_outros = tabela_outros.split("\n")
    max_linhas = max(len(linhas_geral), len(linhas_outros))
    linhas_geral += [""] * (max_linhas - len(linhas_geral))
    linhas_outros += [""] * (max_linhas - len(linhas_outros))

    print(f"\n📋 Listas de Clientes Únicos (Sentido: {sentido} | IPv{tipo_ip}):\n")
    for l1, l2 in zip(linhas_geral, linhas_outros):
        print(f"{l1:<70} {l2}")

    # ==========================================================
    # LOOP V/C/S
    # ==========================================================
    try:
        while True:
            acao = input("\n🛠️  Deseja (V)isualizar, (C)onfigurar Local-Preference / AS-Path, ou (S)air? ").strip().lower()
            if acao == "s":
                print("\n👋 Encerrando o programa.")
                break
            
            if acao == "v" or acao == "c":
                
                # --- Lógica de Seleção do Código ---
                if sentido == "IN" and acao == "v":
                    codigo_selecionado = "9999"
                    print("\n🔎 Código do cliente assumido para resumo de LP: **9999**")
                else:
                    codigo_selecionado = input("🔎 Digite o código do cliente: ").strip()
                
                # -----------------------------------
                
                blocos_filtrados = [b for b in todos_blocos if b["Código"] == codigo_selecionado]
                
                if not blocos_filtrados:
                    print(f"⚠️ Código {codigo_selecionado} não encontrado. Tente novamente.")
                    continue
                
                print(f"\n📊 Informações do Cliente (Sentido: {sentido} | Código: {codigo_selecionado})")

                # 2. DEFINIR O DATASET E CABEÇALHOS PARA VISUALIZAÇÃO
                if sentido == "OUT":
                    # ✅ Visualização simplificada para OUT
                    headers = ["Operadora", "AS-Path", "Qtd ASNs (Prepend)"]
                    data = [[b["Operadora"], b.get("AS-Path", "NONE"), b.get("Peso Prepend", 0)] for b in blocos_filtrados]
                    
                else: # Sentido IN
                    headers = ["Operadora", "Local-Preference"]
                    data = [[b["Operadora"], b.get("Local-Preference", 0)] for b in blocos_filtrados if b["Operadora"] in OPERADORAS_PRINCIPAIS] 
                    
                tabela = tabulate(data, headers=headers, tablefmt="fancy_grid")
                print(tabela) 

                # 3. SUMÁRIO DE PREFERÊNCIA
                if sentido == "IN":
                    max_lp = max(b.get("Local-Preference", 0) for b in blocos_filtrados)
                    melhores_operadoras = [b["Operadora"] for b in blocos_filtrados if b.get("Local-Preference", 0) == max_lp]
                    
                    if max_lp > 0:
                        print(f"\nOperadora(s) de entrada preferencial (LP: {max_lp}): **{', '.join(melhores_operadoras)}**")
                    else:
                        print("\n⚠️ Nenhuma Local-Preference configurado (ou LP=0).")

                if sentido == "OUT":
                    melhor_operadora = min(blocos_filtrados, key=lambda x: x["Peso Prepend"])["Operadora"]
                    print(f"\nOperadora de saída preferencial (Menor Prepend): **{melhor_operadora}**")

                # 4. CONFIGURAÇÃO ('C')
                if acao == "c":
                    if sentido == "IN": 
                        # Lógica de Configuração de Local-Preference (sem alteração)
                        print("\n**Selecione o NÚMERO da operadora para configurar o Local-Preference:**")
                        for num, op in MAP_OPERADORAS.items():
                            print(f"{num} - {op}")
                            
                        op_escolha = input("\nDigite o NÚMERO da operadora: ").strip()
                        operadora_alvo = MAP_OPERADORAS.get(op_escolha)
                        
                        if not operadora_alvo:
                            print("❌ Opção de operadora inválida.")
                            continue

                        try:
                            novo_lp = int(input(f"Digite o NOVO Local-Preference para {operadora_alvo}: "))
                            if novo_lp < 0 or novo_lp > 4294967295: 
                                print("❌ Local-Preference fora do range válido.")
                                continue
                                
                            confirma = input(f"CONFIRMA a alteração do LP para {novo_lp} na política {operadora_alvo} (código {codigo_selecionado}, IPv{tipo_ip})? (s/n): ").strip().lower()
                            
                            if confirma == "s":
                                configurar_local_preference(net_connect, operadora_alvo, tipo_ip, codigo_selecionado, novo_lp)
                            else:
                                print("❌ Configuração cancelada pelo usuário.")
                            
                        except ValueError:
                            print("❌ LP inválido. Digite um número inteiro.")

                    elif sentido == "OUT":
                        # ✅ Lógica de Configuração de AS-Path Prepend (NOVA entrada de dados)
                        print("\n**Selecione o NÚMERO da operadora para configurar o AS-Path Prepend:**")
                        for num, op in MAP_OPERADORAS.items():
                            print(f"{num} - {op}")
                            
                        op_escolha = input("\nDigite o NÚMERO da operadora: ").strip()
                        operadora_alvo = MAP_OPERADORAS.get(op_escolha)
                        
                        if not operadora_alvo:
                            print("❌ Opção de operadora inválida.")
                            continue

                        # O usuário digita a string do AS-Path
                        as_path_str = input(f"Digite o AS-Path (ex: 65000 65000) ou '0'/'NONE' para remover o prepend para {operadora_alvo}: ").strip()
                        
                        # Calcula a quantidade de ASNs para exibir na confirmação
                        qtd_asns = calcular_peso_aspath(as_path_str)

                        if qtd_asns == 0 and as_path_str.upper() not in ["0", "NONE", ""]:
                            print("❌ A string do AS-Path não foi reconhecida como válida (use apenas números e espaços).")
                            continue

                        # Monta a mensagem de confirmação
                        if qtd_asns > 0:
                            msg_confirm = f"CONFIRMA a aplicação do AS-Path '{as_path_str}' ({qtd_asns}x) na política {operadora_alvo} (código {codigo_selecionado}, IPv{tipo_ip})? (s/n): "
                        else:
                            msg_confirm = f"CONFIRMA a REMOÇÃO/RESET do AS-Path Prepend na política {operadora_alvo} (código {codigo_selecionado}, IPv{tipo_ip})? (s/n): "

                        confirma = input(msg_confirm).strip().lower()
                        
                        if confirma == "s":
                            # Chama a função de configuração com a string bruta
                            configurar_as_path_prepend(net_connect, operadora_alvo, tipo_ip, codigo_selecionado, as_path_str)
                        else:
                            print("❌ Configuração cancelada pelo usuário.")
                        
            else:
                print("❌ Opção inválida. Tente 'V', 'C' ou 'S'.")
        
    except Exception as e:
        print(f"\n❌ Erro na execução da lógica: {e}")
    finally:
        if net_connect:
            net_connect.disconnect()
            print("\n🔒 Conexão encerrada.")

if __name__ == "__main__":
    bgp_visualizacao_e_configuracao()