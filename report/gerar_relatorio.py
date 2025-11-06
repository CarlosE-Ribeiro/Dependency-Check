import google.generativeai as genai
import json
import os
import logging
from pathlib import Path

# --- CONFIGURAÇÃO ---

# API KEY lida do ambiente (ISSO ESTÁ CORRETO, MANTENHA ASSIM)
API_KEY = os.environ.get('API_KEY_GEMINI', 'ERRO_KEY_NAO_DEFINIDA')

# Caminhos
JSON_INPUT_PATH = "target/dependency-check-report.json"
HTML_OUTPUT_PATH = "relatorio_vulnerabilidades.html"

# Configura o logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- FUNÇÕES ---

def configurar_ia():
    """Configura a API do Gemini e retorna o modelo."""
    try:
        genai.configure(api_key=API_KEY)
        model = genai.GenerativeModel('gemini-pro')
        logging.info("Modelo Gemini (gemini-pro) configurado com sucesso.")
        return model
    except Exception as e:
        logging.error(f"Falha ao configurar a API do Gemini. Verifique sua API Key. Erro: {e}")
        return None

def analisar_json(filepath):
    """Lê o JSON do OWASP e extrai a lista de vulnerabilidades."""
    logging.info(f"Analisando o arquivo JSON em: {filepath}")
    vulnerabilidades_encontradas = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        if 'dependencies' not in data:
            logging.warning("Nenhuma chave 'dependencies' encontrada no JSON.")
            return []

        for dep in data['dependencies']:
            if 'vulnerabilities' in dep and dep['vulnerabilities']:
                dep_nome = dep.get('fileName', 'Dependência desconhecida')
                
                for vuln in dep['vulnerabilities']:
                    
                    # --- MUDANÇA AQUI ---
                    # Vamos pegar o Score CVSS. Priorizamos o v3, depois o v2.
                    score = "N/A"
                    if 'cvssv3' in vuln and vuln['cvssv3'].get('baseScore'):
                        score = vuln['cvssv3'].get('baseScore')
                    elif 'cvssv2' in vuln and vuln['cvssv2'].get('score'):
                        score = vuln['cvssv2'].get('score')
                    
                    vulnerabilidades_encontradas.append({
                        "cve": vuln.get('name', 'N/A'),
                        "severidade": vuln.get('severity', 'Desconhecida'),
                        "descricao_en": vuln.get('description', 'Sem descrição.'),
                        "dependencia": dep_nome,
                        "score": score  # <-- NOVO CAMPO
                    })
        
        logging.info(f"Extraídas {len(vulnerabilidades_encontradas)} vulnerabilidades do JSON.")
        return vulnerabilidades_encontradas

    except FileNotFoundError:
        logging.error(f"ERRO: Arquivo JSON não encontrado em {filepath}")
        return []
    except json.JSONDecodeError:
        logging.error(f"ERRO: Falha ao decodificar o JSON. O arquivo está corrompido?")
        return []

def obter_dados_ia(modelo, cve, dependencia, descricao_en):
    """
    Pergunta ao Gemini a SOLUÇÃO e a TRADUÇÃO da descrição.
    Exige uma resposta em JSON para ser mais robusto.
    """
    logging.info(f"Consultando IA para dados da {cve}...")
    
    # --- MUDANÇA DRÁSTICA NO PROMPT ---
    # Agora pedimos um JSON como resposta, é muito mais confiável.
    prompt = f"""
    Você é um especialista em cibersegurança e engenharia de software (em português brasileiro).
    Analise a seguinte vulnerabilidade:
    - CVE: {cve}
    - Dependência: {dependencia}
    - Descrição (Inglês): "{descricao_en}"

    Responda APENAS com um objeto JSON válido, contendo duas chaves:
    1. "descricao_pt": A tradução técnica e precisa da descrição para o português brasileiro.
    2. "solucao": A solução prática e direta (ex: "Atualize a dependência {dependencia} para a versão X.Y.Z ou superior.").

    Exemplo de saída:
    {{
      "descricao_pt": "Uma falha de desserialização...",
      "solucao": "Atualize {dependencia} para a versão 5.0.0 ou superior."
    }}
    """

    try:
        response = modelo.generate_content(prompt)
        
        # Limpa a resposta da IA (ela às vezes adiciona ```json ... ```)
        texto_limpo = response.text.strip().replace("```json", "").replace("```", "")
        
        # Decodifica a resposta JSON da IA
        dados_ia = json.loads(texto_limpo)
        
        return dados_ia['descricao_pt'], dados_ia['solucao']

    except Exception as e:
        logging.warning(f"Não foi possível obter dados da IA para {cve}. A resposta foi: {response.text_safe if 'response' in locals() else str(e)}")
        fallback_desc = f"(Tradução falhou) {descricao_en}"
        fallback_sol = "Falha ao consultar a IA para uma solução."
        return fallback_desc, fallback_sol

def gerar_relatorio_html(dados_finais, output_path):
    """Cria um arquivo HTML bonito com a tabela formatada."""
    logging.info(f"Gerando relatório HTML em: {output_path}")

    # --- CSS TOTALMENTE NOVO ---
    # Adiciona bordas (linhas), cores fracas (pastéis) e cores na severidade.
    html_style = """
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; 
            margin: 20px; 
            background-color: #f9f9f9; 
            color: #333;
        }
        h1 { 
            color: #004a9e; 
            border-bottom: 2px solid #004a9e;
            padding-bottom: 5px;
        }
        p {
            font-size: 0.9em;
            color: #555;
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
            margin-top: 25px;
        }
        th, td { 
            border: 1px solid #ddd; /* <-- LINHAS DE SEPARAÇÃO */
            padding: 12px; 
            text-align: left; 
            vertical-align: top;
        }
        th { 
            background-color: #f0f0f0; /* <-- COR FRACA (CINZA PASTEL) */
            color: #333;
            font-weight: 600;
        }
        tr:nth-child(even) { 
            background-color: #fdfdfd; /* Linha sim */
        }
        tr:nth-child(odd) { 
            background-color: #f7f7f7; /* Linha não (zebra) */
        }
        tr:hover { 
            background-color: #e6f0ff; /* Destaque ao passar o mouse */
        }
        
        /* Largura das colunas */
        .col-cve { width: 12%; }
        .col-score { width: 6%; }
        .col-sev { width: 8%; }
        .col-desc { width: 44%; }
        .col-sol { width: 30%; }

        /* Cores de Severidade */
        .severity-CRITICAL { color: #D73A49; font-weight: bold; }
        .severity-HIGH { color: #F56A00; font-weight: bold; }
        .severity-MODERATE { color: #DBAB09; }
        .severity-LOW { color: #31704B; }
    </style>
    """

    # Montando as linhas da tabela (com as novas colunas)
    table_rows = ""
    for item in dados_finais:
        severidade_class = f"severity-{item['severidade'].upper()}"
        table_rows += f"""
        <tr>
            <td class="col-cve">{item['cve']}</td>
            <td class="col-score" style="text-align: center;"><b>{item['score']}</b></td>
            <td class="col-sev {severidade_class}">{item['severidade']}</td>
            <td class="col-desc">{item['descricao_pt']}</td>
            <td class="col-sol">{item['solucao']}</td>
        </tr>
        """

    # Montando o HTML final
    html_content = f"""
    <html>
    <head>
        <title>Relatório de Vulnerabilidades</title>
        <meta charset="UTF-8">
        {html_style}
    </head>
    <body>
        <h1>Relatório de Análise de Vulnerabilidades</h1>
        <p>Este relatório foi gerado processando a saída do OWASP Dependency-Check e consultando a IA (Gemini) para traduções e soluções.</p>
        <table>
            <thead>
                <tr>
                    <th class="col-cve">CVE</th>
                    <th class="col-score">Score</th>
                    <th class="col-sev">Severidade</th>
                    <th class="col-desc">Descrição (Traduzida)</th>
                    <th class="col-sol">Solução Recomendada (IA)</th>
                </tr>
            </thead>
            <tbody>
                {table_rows}
            </tbody>
        </table>
    </body>
    </html>
    """

    # Salvando o arquivo
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        logging.info(f"Relatório salvo com sucesso em {Path(output_path).resolve()}!")
    except Exception as e:
        logging.error(f"Falha ao salvar o arquivo HTML. Erro: {e}")

# --- EXECUÇÃO PRINCIPAL ---

def main():
    if API_KEY == 'ERRO_KEY_NAO_DEFINIDA':
        logging.error("A variável de ambiente 'API_KEY_GEMINI' não foi definida no Jenkins.")
        return

    modelo_ia = configurar_ia()
    if not modelo_ia:
        return

    vulnerabilidades = analisar_json(JSON_INPUT_PATH)
    if not vulnerabilidades:
        logging.info("Nenhuma vulnerabilidade encontrada ou o arquivo JSON está vazio. Saindo.")
        return

    dados_com_solucao = []
    for vuln in vulnerabilidades:
        # Pula se a severidade for baixa (opcional, você pode remover isso)
        if vuln['severidade'] in ['LOW', 'Desconhecida']:
             logging.info(f"Pulando {vuln['cve']} (Severidade: {vuln['severidade']}).")
             continue
        
        # --- MUDANÇA AQUI ---
        # Agora chamamos a IA para obter dois valores
        descricao_pt, solucao = obter_dados_ia(
            modelo_ia, 
            vuln['cve'], 
            vuln['dependencia'], 
            vuln['descricao_en']
        )
        
        dados_com_solucao.append({
            "cve": vuln['cve'],
            "severidade": vuln['severidade'],
            "score": vuln['score'],
            "descricao_pt": descricao_pt, # <-- NOVO
            "solucao": solucao
        })

    if not dados_com_solucao:
        logging.info("Nenhuma vulnerabilidade (Moderada ou superior) encontrada para gerar relatório.")
        return

    gerar_relatorio_html(dados_com_solucao, HTML_OUTPUT_PATH)

if __name__ == "__main__":
    main()