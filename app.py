import re
import time
from flask import Flask, render_template, request, redirect, url_for
from logging import basicConfig, DEBUG, error, debug
from netmiko import ConnectHandler

# Configura o logger para mostrar logs de DEBUG no terminal
basicConfig(level=DEBUG, format='%(levelname)s: %(message)s')

# ==========================================================
# CONFIGURAÇÕES DA APLICAÇÃO
# ==========================================================
app = Flask(__name__)

# ====== DADOS DE ACESSO E CONSTANTES ======
# ATUALIZE COM SUAS CREDENCIAIS E IP
ip = "172.31.253.254" 
usuario = "n2akto"
senha = "6aTaGa@kt0"
DEVICE_TYPE = "huawei" 
GLOBAL_DELAY = 10 
TIMEOUT_COMANDO_LONGO = 180 

# ** IMPORTANTE: ATUALIZE O AS_LOCAL CORRETAMENTE **
AS_LOCAL = "263434" 

# ====== OPERADORAS, OPEN CDN E MAPAS PARA EXCLUSÃO ======
OPERADORAS_PRINCIPAIS = ["OI", "TIM", "EMBRATEL1", "EMBRATEL2"]
OPENCDN_BASE_NAME = "BEMOL_OPENCDN" # Nome base da policy para o CDN

MAP_OPERADORAS = {
    "1": "OI",
    "2": "TIM",
    "3": "EMBRATEL1",
    "4": "EMBRATEL2",
}

# ==========================================================
# LOCAL PREFERENCE PADRÃO E PRINCIPAL (IN)
# ==========================================================
LP_PRINCIPAL = 950

LP_DEFAULTS = {
    "OI": 600,
    "TIM": 700,
    "EMBRATEL1": 800,
    "EMBRATEL2": 900
}

PROMPT_REGEX = r'<.+?>' 

# ==========================================================
# FUNÇÕES DE REDE 
# ==========================================================

def get_net_connect():
    """Tenta conectar e retorna o objeto net_connect ou None em caso de falha."""
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
        net_connect.send_command('\n', expect_string=PROMPT_REGEX, read_timeout=50) 
        net_connect.send_command('screen-length 0 temporary', expect_string=PROMPT_REGEX, read_timeout=50)
        time.sleep(1) 
        return net_connect
    except Exception as e:
        error(f"Erro de conexão (Netmiko): {e}")
        return None

def coletar_policies_cliente(net_connect, tipo_ip, sentido):
    """
    Usa 'display route-policy | no-more' e uma regex robusta para capturar 
    nomes de políticas de cliente (excluindo operadoras e OPENCDN).
    """
    if not net_connect:
        return []
        
    policies_encontradas_brutas = set()
    
    comando = "display route-policy | include (IN|OUT)-IPV | no-more" 
    
    # Regex robusta: Captura qualquer string não-espaço (\S+) após declarações de policy ou prefix-list
    regex_policy_name = r"(?:Route-policy:\s*|Match-route-policy:\s*|ip-prefix\s+)(\S+)" 
    
    try:
        saida = net_connect.send_command(comando, expect_string=PROMPT_REGEX, read_timeout=TIMEOUT_COMANDO_LONGO)
        
        for linha in saida.splitlines():
            linha = linha.strip()
            
            m = re.search(regex_policy_name, linha, flags=re.IGNORECASE)
            
            if m:
                policy_name = m.group(1).strip()
                policy_name_upper = policy_name.upper()
                
                # 1. Garante que não sejam apenas números (código de node)
                if policy_name.isdigit():
                    continue
                
                # 2. Exclui palavras-chave simples
                if policy_name_upper not in ["ROUTE-POLICY", "PERMIT", "DENY", "IF-MATCH", "APPLY", "MATCH", "CLAUSES", "DESCRIPTION", "UNDO", "COMMIT", "QUIT", "MATCH-ROUTE-POLICY", "IP-PREFIX", "PREFIX-LIST", "NODE", "IPV4", "IPV6"]:
                     policies_encontradas_brutas.add(policy_name)
                    
        debug(f"Policies encontradas BRUTAS (após limpeza de keywords): {policies_encontradas_brutas}")
        
        # Filtro Operadora e CDN: Exclui as políticas de operadora/CDN
        policies_a_excluir = set()
        
        # Excluir Operadoras
        for o in OPERADORAS_PRINCIPAIS:
            for s in ["IN", "OUT"]:
                policies_a_excluir.add(f"{s}-IPV4-{o}".upper())
                policies_a_excluir.add(f"{s}-IPV6-{o}".upper())
        
        # Excluir OPEN CDN
        for s in ["IN", "OUT"]:
            policies_a_excluir.add(f"{s}-IPV4-{OPENCDN_BASE_NAME}".upper())
            policies_a_excluir.add(f"{s}-IPV6-{OPENCDN_BASE_NAME}".upper())
            
        # O resultado são as policies que estão em 'brutas' MENOS as de 'operadoras' e 'CDN'
        policies_clientes_finais_set = policies_encontradas_brutas - policies_a_excluir

        # Filtra as policies pelo SENTIDO selecionado (IN ou OUT)
        policies_final_por_sentido = []
        sentido_upper = sentido.upper()
        
        for policy in policies_clientes_finais_set:
            # Mantém apenas as policies que começam com o sentido (Ex: IN-IPV4- ou OUT-IPV6-)
            if policy.upper().startswith(f'{sentido_upper}-'):
                policies_final_por_sentido.append(policy)
        
        policies_clientes_finais_set = set(policies_final_por_sentido)
        
        # 4. Filtragem flexível de IP: Inclui todas que sobraram, exceto se for IPv6 E o usuário escolheu IPv4, etc.
        policies_final_por_ip = []
        for policy in policies_clientes_finais_set:
            # Se o usuário escolheu IPv4, e a policy tem 'IPV6', pula.
            if tipo_ip == '4' and 'IPV6' in policy.upper():
                continue
            # Se o usuário escolheu IPv6, e a policy tem 'IPV4', pula.
            if tipo_ip == '6' and 'IPV4' in policy.upper():
                continue
            policies_final_por_ip.append(policy)
            
        policies_final_por_ip = sorted(list(policies_final_por_ip))
        
        debug(f"Policies de Cliente FINAIS para {sentido} | IPv{tipo_ip}: {policies_final_por_ip}")
        return policies_final_por_ip
    
    except Exception as e:
        error(f"Erro ao coletar nomes de políticas: {e}")
        return []

def calcular_peso_aspath(aspath_str):
    """Calcula o peso de prepend baseado no AS_LOCAL."""
    if not aspath_str or aspath_str in ["-", "NONE"]:
        return 0
    as_list = aspath_str.split()
    if as_list and as_list[0] == AS_LOCAL:
        return as_list.count(AS_LOCAL)
    return len(as_list) 

def parsear_saida(saida, operadora, tipo_ip, sentido):
    """Analisa a saída do display route-policy e extrai os atributos por node."""
    blocos = []
    bloco_atual = None
    for linha in saida.splitlines():
        linha = linha.strip()
        if not linha or '--- More ---' in linha:
            continue
            
        m_inicio = re.match(r"^(permit|deny)\s*(?:\:\s*|node\s*)?(\d+)", linha, flags=re.IGNORECASE)
        
        if m_inicio:
            if bloco_atual:
                if sentido == "OUT":
                    bloco_atual["Peso Prepend"] = calcular_peso_aspath(bloco_atual.get("AS-Path", "NONE"))
                if sentido == "IN" and bloco_atual.get("Código") == "9999" and operadora in MAP_OPERADORAS.values(): 
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
                "Community": "-", 
            }
            continue
            
        # Bloco de Match Clauses (if-match)
        if "if-match" in linha and bloco_atual:
            # Captura IP-Prefix (Nome da prefix-list)
            m_pl = re.search(r"(ip-prefix|prefix-list)\s+(\S+)", linha, flags=re.IGNORECASE)
            prefix = m_pl.group(2) if m_pl else bloco_atual["IP-Prefix"]
            bloco_atual["IP-Prefix"] = prefix 

            # Captura if-match community (Nome da community-list ou valor direto)
            m_comm_match = re.search(r"if-match\s+community\s+(\S+)", linha, flags=re.IGNORECASE)
            if m_comm_match:
                community_match_name = m_comm_match.group(1).strip()
                current_comm = bloco_atual["Community"]
                bloco_atual["Community"] = community_match_name if current_comm == "-" else f"{current_comm} / {community_match_name}"
            
            # Captura if-match community-filter (Nome do community-filter)
            m_comm_filter_match = re.search(r"if-match\s+community-filter\s+(\S+)", linha, flags=re.IGNORECASE)
            if m_comm_filter_match:
                community_filter_name = m_comm_filter_match.group(1).strip()
                current_comm = bloco_atual["Community"]
                bloco_atual["Community"] = community_filter_name if current_comm == "-" else f"{current_comm} / {community_filter_name}"

            continue
            
        # Bloco de Apply Clauses
        
        if "apply as-path" in linha and bloco_atual:
            aspath_part = linha.split("apply as-path", 1)[1].strip()
            m_aspath = re.search(r"(?:\b(?:additive|prepend)\b\s*)?([\d\s,]+)", aspath_part, flags=re.IGNORECASE)
            aspath_str = m_aspath.group(1).strip() if m_aspath else "NONE"
            bloco_atual["AS-Path"] = aspath_str
            continue
            
        if "apply local-preference" in linha and bloco_atual:
            m_lp = re.search(r"apply local-preference\s+(\d+)", linha, flags=re.IGNORECASE)
            if m_lp:
                bloco_atual["Local-Preference"] = int(m_lp.group(1))
            continue
        
        # Captura apply community (valor da community)
        if "apply community" in linha and bloco_atual:
            m_comm_apply = re.search(r"apply\s+community\s+(.+?)(?:\s+(?:additive|subtract|none))?\s*$", linha, flags=re.IGNORECASE)
            
            if m_comm_apply:
                community_str = m_comm_apply.group(1).strip()
                current_comm = bloco_atual["Community"]
                
                # Se for a primeira comunidade encontrada, usa o valor. Senão, concatena.
                bloco_atual["Community"] = community_str if current_comm == "-" else f"{current_comm} / {community_str}"
            continue
            
    if bloco_atual:
        if sentido == "OUT":
            bloco_atual["Peso Prepend"] = calcular_peso_aspath(bloco_atual.get("AS-Path", "NONE"))
        if sentido == "IN" and bloco_atual.get("Código") == "9999" and operadora in MAP_OPERADORAS.values():
            bloco_atual["IP-Prefix"] = f"({bloco_atual.get('Operadora')})"
        blocos.append(bloco_atual)
    return blocos


def coletar_codigos_unicos(net_connect, sentido, tipo_ip):
    """Coleta e retorna uma lista de todos os códigos de clientes únicos e suas prefix-lists em políticas de Operadora."""
    
    clientes_encontrados = {} 
    todos_blocos_brutos = []
    
    for operadora in OPERADORAS_PRINCIPAIS:
        policy_name = f"{sentido}-IPV{tipo_ip}-{operadora}"
        comando = f"display route-policy {policy_name} | no-more" 
        try:
            saida = net_connect.send_command(comando, expect_string=PROMPT_REGEX, read_timeout=TIMEOUT_COMANDO_LONGO)
            blocos = parsear_saida(saida, operadora, tipo_ip, sentido) 
            if blocos:
                todos_blocos_brutos.extend(blocos)
        except Exception as e:
            error(f"Erro ao coletar dados para {operadora} em coletar_codigos_unicos: {e}")
            pass 
            
    for bloco in todos_blocos_brutos:
        codigo = bloco.get("Código")
        prefix_name = bloco.get("IP-Prefix")
        
        if not codigo or codigo in clientes_encontrados:
            continue
            
        if codigo:
            if codigo == "9999":
                identificador = "RESUMO (Tráfego sem política específica)"
            else:
                identificador = prefix_name
            
            clientes_encontrados[codigo] = identificador
            
    lista_para_ordenar = [(cod, nome) for cod, nome in clientes_encontrados.items()]
    lista_ordenada = sorted(lista_para_ordenar, key=lambda x: int(x[0]) if x[0].isdigit() else 99999)

    return lista_ordenada 


# === FUNÇÕES DE CONFIGURAÇÃO ===
# (Mantidas as mesmas do passo anterior, não houve alteração)
# ...

def configurar_local_preference(net_connect, policy_name, codigo, novo_lp):
    """Aplica o apply local-preference dentro do nó da route-policy."""
    comandos = [
        f"route-policy {policy_name} permit node {codigo}",
        "undo apply local-preference", 
        f"apply local-preference {novo_lp}",
        "commit",
        "quit"
    ]
    try:
        saida = net_connect.send_config_set(comandos, exit_config_mode=True, cmd_verify=True)
        
        if "Error" in saida or "Configuration fail" in saida:
             return f"❌ Erro na sintaxe ou no commit: {saida.splitlines()[-2]}", None
             
        return f"✅ Sucesso! Local-Preference alterado para {novo_lp} no Node {codigo} da Policy {policy_name}.", saida
        
    except Exception as e:
        return f"❌ Erro de Netmiko durante a configuração: {e}", None


def configurar_as_path_prepend(net_connect, policy_name, codigo, as_path_str):
    """Aplica ou remove o apply as-path prepend dentro do nó da route-policy."""
    as_path_str = as_path_str.strip().upper()
    
    commands_to_send = []

    if not as_path_str or as_path_str in ["0", "NONE"]:
        commands_to_send = [
            f"route-policy {policy_name} permit node {codigo}",
            "undo apply as-path",
            "commit",
            "quit"
        ]
        log_message = "Prepend removido/resetado"
    else:
        if not re.fullmatch(r"[\d\s]+", as_path_str):
             return "❌ A string do AS-Path contém caracteres inválidos. Use apenas números e espaços.", None

        commands_to_send = [
            f"route-policy {policy_name} permit node {codigo}",
            "undo apply as-path", 
            f"apply as-path prepend {as_path_str} additive ",
            "commit",
            "quit"
        ]
        log_message = f"Prepend alterado para '{as_path_str}'"

    try:
        saida = net_connect.send_config_set(commands_to_send, exit_config_mode=True, cmd_verify=True)
        
        if "Error" in saida or "Configuration fail" in saida:
             return f"❌ Erro na sintaxe ou no commit: {saida.splitlines()[-2]}", None
             
        return f"✅ Sucesso! {log_message} no Node {codigo} da Policy {policy_name}.", saida
    except Exception as e:
        return f"❌ Erro na configuração: {e}", None


# ==========================================================
# FUNÇÕES DE LÓGICA
# ==========================================================

def get_policy_details_and_summary(net_connect, sentido, tipo_ip, tipo_politica, codigo, policy_name_cliente):
    """Função centralizada para coletar dados, filtrar e gerar o sumário."""
    
    blocos_filtrados = []
    client_identifier = ""
    policy_name_visualizada = ""
    policy_alvo_config = ""
    
    if tipo_politica == "OPERADORA":
        policy_name_visualizada = f"Operadoras (Código {codigo})"
        policy_alvo_config = f"{sentido}-IPV{tipo_ip}-{{OPERADORA_ALVO}}"
        client_identifier = codigo 
        
        todos_blocos_brutos = []
        for operadora in OPERADORAS_PRINCIPAIS:
            policy_name = f"{sentido}-IPV{tipo_ip}-{operadora}"
            comando = f"display route-policy {policy_name} | no-more" 
            try:
                saida = net_connect.send_command(comando, expect_string=PROMPT_REGEX, read_timeout=TIMEOUT_COMANDO_LONGO)
                blocos = parsear_saida(saida, operadora, tipo_ip, sentido) 
                if blocos:
                    # Inclui todos os blocos brutos para filtragem
                    todos_blocos_brutos.extend(blocos)
            except Exception as e:
                error(f"Erro ao coletar dados para {operadora}: {e}")
                pass 
        
        # Filtra apenas os blocos que correspondem ao código solicitado
        blocos_filtrados = [b for b in todos_blocos_brutos if b["Código"] == codigo]
        
        if blocos_filtrados:
            # Sobrescreve o identificador se for encontrado um IP-Prefix mais descritivo
            prefix_info = blocos_filtrados[0].get("IP-Prefix", codigo)
            if prefix_info and prefix_info not in ["-", "RESUMO (Tráfego sem política específica)"]:
                client_identifier = prefix_info

    elif tipo_politica == "CLIENTE":
        policy_name = policy_name_cliente
        policy_name_visualizada = policy_name
        policy_alvo_config = policy_name 
        client_identifier = policy_name
        codigo = "" 
        
        comando = f"display route-policy {policy_name} | no-more"
        
        try:
            saida = net_connect.send_command(comando, expect_string=PROMPT_REGEX, read_timeout=TIMEOUT_COMANDO_LONGO)
            operadora_cliente = policy_name 
            blocos_filtrados = parsear_saida(saida, operadora_cliente, tipo_ip, sentido)
        except Exception as e:
            error(f"Erro ao coletar dados para o cliente {policy_name}: {e}")
            pass
    
    elif tipo_politica == "OPENCDN":
        policy_name = f"{sentido}-IPV{tipo_ip}-{OPENCDN_BASE_NAME}"
        policy_name_visualizada = f"OPEN CDN: {policy_name}"
        policy_alvo_config = policy_name 
        client_identifier = OPENCDN_BASE_NAME
        codigo = "" 
        
        comando = f"display route-policy {policy_name} | no-more"
        
        try:
            saida = net_connect.send_command(comando, expect_string=PROMPT_REGEX, read_timeout=TIMEOUT_COMANDO_LONGO)
            operadora_cliente = OPENCDN_BASE_NAME # Usa o nome do CDN no campo operadora do bloco
            blocos_filtrados = parsear_saida(saida, operadora_cliente, tipo_ip, sentido)
        except Exception as e:
            error(f"Erro ao coletar dados para OPEN CDN ({policy_name}): {e}")
            pass
            
    # Processamento e Sumário
    dados_tabela = []
    headers = []
    sumario = ""
    melhores = []
    
    if sentido == "IN":
        # Community e IP-Prefix já estão incluídos
        headers = ["Operadora/Peer", "Ação", "Local-Preference", "Community", "IP-Prefix", "Código"] 
        
        # Filtro de blocos válidos para o cálculo do melhor caminho
        blocos_validos = [b for b in blocos_filtrados if b["Ação"] == "PERMIT" and not (tipo_politica == "OPERADORA" and b["Código"] == "")]
        
        dados_tabela = [
            # Community já está incluída
            {"Operadora": b["Operadora"], "Ação": b["Ação"], "Local-Preference": b.get("Local-Preference", 0), "Código": b["Código"], "IP-Prefix": b["IP-Prefix"], "Community": b.get("Community", "-")} 
            for b in blocos_filtrados
        ]
        
        if blocos_validos:
            max_metric = max(b.get("Local-Preference", 0) for b in blocos_validos)
            melhores = [b["Operadora"] for b in blocos_validos if b["Local-Preference"] == max_metric]
            sumario = f"Melhor caminho (LP: {max_metric})"
        else:
            melhores = ["Nenhuma rota PERMITIDA/principal encontrada"]
            sumario = "ATENÇÃO: Nenhuma rota de entrada permitida ou principal encontrada"
            
    elif sentido == "OUT":
        # Community e IP-Prefix já estão incluídos
        headers = ["Operadora/Peer", "Ação", "AS-Path", "Peso Prepend", "Community", "IP-Prefix", "Código"] 
        blocos_validos = [b for b in blocos_filtrados if b["Ação"] == "PERMIT"]

        dados_tabela = [
            # Community já está incluída
            {"Operadora": b["Operadora"], "Ação": b["Ação"], "AS-Path": b.get("AS-Path", "NONE"), "Peso Prepend": b.get("Peso Prepend", 0), "Código": b["Código"], "IP-Prefix": b["IP-Prefix"], "Community": b.get("Community", "-")} 
            for b in blocos_filtrados
        ]
        
        if blocos_validos:
            min_prepend = min(b.get("Peso Prepend", 9999) for b in blocos_validos)
            melhores = [b["Operadora"] for b in blocos_validos if b["Peso Prepend"] == min_prepend]
            sumario = f"Melhor caminho (Menor Prepend: {min_prepend})"
        else:
            melhores = ["Nenhuma rota PERMITIDA/principal encontrada"]
            sumario = "ATENÇÃO: Nenhuma rota de saída permitida ou principal encontrada"
            
    return {
        'blocos_filtrados': blocos_filtrados,
        'client_identifier': client_identifier,
        'policy_name_visualizada': policy_name_visualizada,
        'policy_alvo_config': policy_alvo_config,
        'tabela_detalhe': dados_tabela,
        'headers': headers,
        'sumario': sumario,
        'melhores': melhores,
        'codigo': codigo 
    }


# ==========================================================
# ROTAS FLASK 
# ==========================================================

@app.route('/', methods=['GET'])
def home():
    """Rota inicial: Exibe a interface com os formulários."""
    
    policy_clientes = []
    net_connect = get_net_connect()
    
    # Ao carregar a página, sempre tentamos carregar a lista de clientes (por padrão, IPv4)
    if net_connect:
        net_connect.disconnect()

    return render_template(
        'index.html', 
        operadoras_map=MAP_OPERADORAS,
        sentido_sel='IN', 
        tipo_ip_sel='4',
        tipo_politica_sel='OPERADORA',
        codigo='', 
        policy_name_cliente='', 
        instrucao="Selecione 'Operadora' e **deixe o Código vazio** para listar todos os códigos. Selecione 'Cliente' ou 'OPEN CDN' e clique em 'Visualizar' para continuar."
    )

@app.route('/visualizar', methods=['POST', 'GET'])
def visualizar():
    """
    Rota que processa a visualização/configuração de um código/policy name.
    """
    # 🔹 Coleta SOMENTE nodes válidos do OPENCDN
    lista_nodes_opencdn = []
    lista_nodes_cliente = []
    
    # 1. RECEBIMENTO DE VARIÁVEIS (POST > GET)
    sentido = request.values.get('sentido', 'IN')
    tipo_ip = request.values.get('tipo_ip', '4')
    tipo_politica = request.values.get('tipo_politica', 'OPERADORA')
    codigo = request.values.get('codigo_cliente', '').strip()
    policy_name_cliente = request.values.get('policy_name_cliente', '').strip().upper() 
    config_status = request.values.get('config_status')


    # 2. Conexão e tratamento de erro
    net_connect = get_net_connect()
    if not net_connect:
        return render_template('index.html', error="❌ Erro ao conectar ao roteador. Verifique as credenciais/acesso/Firewall.",
                               sentido_sel=sentido, tipo_ip_sel=tipo_ip, codigo=codigo, tipo_politica_sel=tipo_politica, operadoras_map=MAP_OPERADORAS), 500

    # Carrega a lista de clientes (policys) - Só é usada se tipo_politica == "CLIENTE"
    policy_clientes = coletar_policies_cliente(net_connect, tipo_ip, sentido)

    # === LÓGICA PARA POLÍTICAS DE OPERADORA (CÓDIGOS) ===
    if tipo_politica == "OPERADORA":
        
        # Lógica de Listagem (Código vazio)
        if not codigo:
            lista_codigos_e_nomes = coletar_codigos_unicos(net_connect, sentido, tipo_ip)
            net_connect.disconnect()
            
            if not lista_codigos_e_nomes:
                return render_template('index.html', 
                                        error=f"⚠️ Nenhum código de cliente encontrado para o Sentido {sentido} | IPv{tipo_ip}.",
                                        sentido_sel=sentido, tipo_ip_sel=tipo_ip, codigo="", tipo_politica_sel=tipo_politica, operadoras_map=MAP_OPERADORAS)
            
            # RETORNA A LISTA DE CÓDIGOS PARA O USUÁRIO ESCOLHER
            return render_template('index.html', 
                                    sentido_sel=sentido, 
                                    tipo_ip_sel=tipo_ip, 
                                    tipo_politica_sel=tipo_politica,
                                    lista_codigos=lista_codigos_e_nomes, 
                                    operadoras_map=MAP_OPERADORAS)
        
        # Se um CÓDIGO foi fornecido (Visualização Detalhada de Operadora)
        data = get_policy_details_and_summary(net_connect, sentido, tipo_ip, tipo_politica, codigo, policy_name_cliente)
        
        if not data['blocos_filtrados']:
            net_connect.disconnect()
            return render_template('index.html', 
                                    error=f"⚠️ Código **{codigo}** não encontrado nas políticas de operadora ({sentido} | IPv{tipo_ip}).",
                                    sentido_sel=sentido, tipo_ip_sel=tipo_ip, codigo=codigo, tipo_politica_sel=tipo_politica, operadoras_map=MAP_OPERADORAS)

    # === LÓGICA PARA POLÍTICAS DE CLIENTE (NOME) ===
    elif tipo_politica == "CLIENTE":
        if not policy_name_cliente:
            net_connect.disconnect()
            
            if not policy_clientes:
                return render_template('index.html', 
                                        error=f"⚠️ Nenhuma Route-Policy de cliente encontrada para o Sentido {sentido} | IPv{tipo_ip}.",
                                        sentido_sel=sentido, tipo_ip_sel=tipo_ip, tipo_politica_sel=tipo_politica, operadoras_map=MAP_OPERADORAS)

            # RETORNA A LISTA CLICÁVEL DE POLICIES
            lista_policies_cliente_formatada = [(name, name) for name in policy_clientes]
            
            return render_template('index.html', 
                                    sentido_sel=sentido, 
                                    tipo_ip_sel=tipo_ip, 
                                    tipo_politica_sel=tipo_politica,
                                    lista_policies_cliente=lista_policies_cliente_formatada, 
                                    operadoras_map=MAP_OPERADORAS)
        
        # Se um POLICY_NAME_CLIENTE foi fornecido (Visualização Detalhada de Cliente)
        data = get_policy_details_and_summary(net_connect, sentido, tipo_ip, tipo_politica, codigo, policy_name_cliente)

        if not data['blocos_filtrados']:
            net_connect.disconnect()
            return render_template('index.html', 
                                    error=f"⚠️ Route-Policy **{policy_name_cliente}** não encontrada ou vazia.",
                                    sentido_sel=sentido, tipo_ip_sel=tipo_ip, tipo_politica_sel=tipo_politica, policy_name_cliente=policy_name_cliente, operadoras_map=MAP_OPERADORAS)
            
        
        
    # === LÓGICA PARA POLÍTICAS DE OPENCDN ===
    elif tipo_politica == "OPENCDN":
        # Define o nome base e constrói o nome real usado no roteador
        policy_name_cliente = OPENCDN_BASE_NAME
        policy_real_router = f"{sentido}-IPV{tipo_ip}-{policy_name_cliente}"
        
        # Busca os detalhes
        data = get_policy_details_and_summary(net_connect, sentido, tipo_ip, tipo_politica, codigo="", policy_name_cliente=policy_name_cliente)
        
        # Adiciona a chave correta para o frontend exibir o nome completo
        data['policy_alvo_config'] = policy_real_router
        
        for bloco in data['blocos_filtrados']:
            codigo_node = bloco.get("Código")

            if codigo_node and codigo_node.isdigit() and codigo_node != "9999":
                lista_nodes_opencdn.append(codigo_node)

        # remove duplicados e ordena
        lista_nodes_opencdn = sorted(set(lista_nodes_opencdn), key=int)


        if not data['blocos_filtrados']:
            net_connect.disconnect()
            return render_template('index.html', 
                                    error=f"⚠️ Route-Policy OPEN CDN **{sentido}-IPV{tipo_ip}-{OPENCDN_BASE_NAME}** não encontrada ou vazia.",
                                    sentido_sel=sentido, tipo_ip_sel=tipo_ip, tipo_politica_sel=tipo_politica, policy_name_cliente=policy_name_cliente,
                                    operadoras_map=MAP_OPERADORAS,lista_nodes_opencdn=lista_nodes_opencdn)


    # 3. Retorno da Visualização Detalhada
    return render_template(
        'index.html',
        sentido_sel=sentido,
        tipo_ip_sel=tipo_ip,
        tipo_politica_sel=tipo_politica,
        codigo=data['codigo'] if tipo_politica == 'OPERADORA' else "",
        policy_name_cliente=policy_name_cliente, 
        client_identifier=data['client_identifier'], 
        tabela_detalhe=data['tabela_detalhe'], 
        headers=data['headers'],
        sumario=data['sumario'],
        melhores=data['melhores'],
        operadoras_map=MAP_OPERADORAS,
        policy_name_visualizada=data['policy_name_visualizada'],
        policy_alvo_config=data['policy_alvo_config'],
        config_status=config_status,
        lista_nodes_opencdn=lista_nodes_opencdn,
        lista_nodes_cliente=lista_nodes_cliente
        
    )


@app.route('/configurar', methods=['POST'])
def configurar():
    """Rota que recebe e aplica a nova configuração de LP ou AS-Path."""
    
    sentido = request.form.get('sentido_config')
    tipo_ip = request.form.get('tipo_ip_config')
    tipo_politica = request.form.get('tipo_politica_config')
    
    # Captura o código/policy name para usar no redirecionamento (inputs universais)
    codigo = request.form.get('codigo_config') 
    policy_name_cliente_redirect = request.form.get('policy_name_alvo') # Usado para CLIENTE e OPENCDN
    
    op_num = request.form.get('operadora_alvo')
    mensagem = ""
    node_alvo = ""
    
    net_connect = get_net_connect()
    if not net_connect:
         mensagem="❌ Erro de conexão ao roteador para aplicar a configuração."
    else:
        # 1. Definir o target da configuração (Policy Name e Node)
        if tipo_politica == "OPERADORA":
            operadora_alvo = MAP_OPERADORAS.get(op_num)
            if not operadora_alvo:
                mensagem="❌ Operadora inválida para configuração."
            else:
                policy_name_config = f"{sentido}-IPV{tipo_ip}-{operadora_alvo}"
                node_alvo = codigo # o codigo_config é o node alvo
            
        elif tipo_politica == "CLIENTE" or tipo_politica == "OPENCDN":
            # policy_name_cliente_redirect é o nome da policy (Ex: CLIENTE-X ou BEMOL_OPENCDN)
            policy_name_config = policy_name_cliente_redirect 
            node_alvo = request.form.get('node_alvo_cliente') 
            
            nome_tipo = "Cliente" if tipo_politica == "CLIENTE" else "OPEN CDN"
            
            if not node_alvo or not node_alvo.isdigit():
                 mensagem=f"❌ O campo 'Código' (Node) do {nome_tipo} é obrigatório e deve ser numérico."
                 
        if not mensagem: # Se não houver erro preliminar
           
           # =========================
            # OPENCDN (SEM PREPEND)
            # =========================
            if tipo_politica == "OPENCDN":

                node = request.form.get("node_alvo_cliente")
                acao = request.form.get("acao_route")

                if not node or not node.isdigit():
                    mensagem = "❌ Node inválido para OPENCDN."
                else:
                    policy = f"{sentido}-IPV{tipo_ip}-{OPENCDN_BASE_NAME}"

                    comandos = [
                        f"route-policy {policy} {acao.lower()} node {node}",
                        "commit",
                        "quit"
                    ]

                    net_connect.send_config_set(
                        comandos,
                        exit_config_mode=True,
                        cmd_verify=True
                    )

                    mensagem = f"✅ OPENCDN: Node {node} definido como {acao}"


           
           # ======================================================
            # 🔥 OPERADORA PRINCIPAL - SENTIDO IN
            # ======================================================
            if sentido == "IN" and tipo_politica == "OPERADORA":

                operadora_alvo = MAP_OPERADORAS.get(op_num)

                if not operadora_alvo:
                    mensagem = "❌ Operadora inválida para configuração."
                else:
                    resultados = []

                    for operadora in OPERADORAS_PRINCIPAIS:
                        policy_name_config = f"IN-IPV{tipo_ip}-{operadora}"

                        if operadora == operadora_alvo:
                            novo_lp = LP_PRINCIPAL
                        else:
                            novo_lp = LP_DEFAULTS[operadora]

                        msg, _ = configurar_local_preference(
                            net_connect,
                            policy_name_config,
                            node_alvo,  # código do cliente
                            novo_lp
                        )

                        resultados.append(f"{operadora}: LP {novo_lp}")

                    mensagem = (
                        f"✅ Operadora principal definida: {operadora_alvo} | "
                        + " | ".join(resultados)
                    )


            elif sentido == "OUT" and tipo_politica != "OPENCDN":
                
                operadora_alvo = MAP_OPERADORAS.get(op_num)

                if not operadora_alvo:
                    mensagem = "❌ Operadora inválida para prepend."
                else:
                    policy_name_config = f"OUT-IPV{tipo_ip}-{operadora_alvo}"

                qtd_prepend_str = request.form.get('qtd_prepend')

                try:
                    qtd_prepend = int(qtd_prepend_str)

                    if qtd_prepend < 0 or qtd_prepend > 5:
                        mensagem = "❌ Quantidade de prepend inválida (use 0 a 5)."
                    else:
                        # Montagem automática do AS-PATH
                        if qtd_prepend == 0:
                            as_path_str = "NONE"
                        else:
                            as_path_str = " ".join([AS_LOCAL] * qtd_prepend)

                        mensagem, _ = configurar_as_path_prepend(
                            net_connect,
                            policy_name_config,
                            node_alvo,
                            as_path_str
                        )

                except (ValueError, TypeError):
                    mensagem = "❌ Quantidade de prepend inválida."

                except Exception as e:
                    mensagem = f"❌ Erro ao aplicar configuração: {e}"


    
    # Redirecionamento de volta para a rota visualizar com os parâmetros
        redirect_params = {
            "sentido": sentido,
            "tipo_ip": tipo_ip,
            "tipo_politica": tipo_politica,
            "config_status": mensagem
        }

        if tipo_politica == "OPERADORA":
            redirect_params["codigo_cliente"] = codigo
            redirect_params["policy_name_cliente"] = ""
        else:
            redirect_params["codigo_cliente"] = ""
            redirect_params["policy_name_cliente"] = policy_name_cliente_redirect

        return redirect(url_for("visualizar", **redirect_params))


# ==========================================================
# INICIALIZAÇÃO DA APLICAÇÃO
# ==========================================================

if __name__ == '__main__':
    app.run(debug=True)