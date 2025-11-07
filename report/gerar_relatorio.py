import json
import os
import logging
import urllib.request  # <--- Usando a biblioteca nativa
import re
import ssl
from pathlib import Path

# --- CONFIGURAÇÃO ---
API_KEY = os.environ.get('API_KEY_GEMINI', 'ERRO_KEY_NAO_DEFINIDA')
JSON_INPUT_PATH = "target/dependency-check-report.json"
HTML_OUTPUT_PATH = "relatorio_vulnerabilidades.html"
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- FUNÇÕES ---

def analisar_json(filepath):
    """Lê o JSON do OWASP e extrai a lista de vulnerabilidades."""
    logging.info(f"Analisando o arquivo JSON em: {filepath}")
    vulnerabilidades_encontradas = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if 'dependencies' not in data:
            return []
        for dep in data['dependencies']:
            if 'vulnerabilities' in dep and dep['vulnerabilities']:
                dep_nome = dep.get('fileName', 'Dependência desconhecida')
                for vuln in dep['vulnerabilities']:
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
                        "score": score
                    })
        logging.info(f"Extraídas {len(vulnerabilidades_encontradas)} vulnerabilidades do JSON.")
        return vulnerabilidades_encontradas
    except FileNotFoundError:
        logging.error(f"ERRO: Arquivo JSON não encontrado em {filepath}")
        return []
    except json.JSONDecodeError:
        logging.error(f"ERRO: Falha ao decodificar o JSON. O arquivo está corrompido?")
        return []

def obter_dados_ia(cve, dependencia, descricao_en):
    """
    Pergunta ao Gemini a SOLUÇÃO e a TRADUÇÃO usando urllib.
    """
    logging.info(f"Consultando IA (via urllib) para dados da {cve}...")

    # --- A GRANDE MUDANÇA ESTÁ AQUI ---
    # Usando a API v1 (moderna) e o modelo gemini-1.5-flash
    url = f"https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash:generateContent?key={API_KEY}"
    
    prompt_texto = f"""
    Você é um assistente de cibersegurança.
    Analise a vulnerabilidade:
    - CVE: {cve}
    - Dependência: {dependencia}
    - Descrição (Inglês): "{descricao_en}"

    Sua resposta deve ser APENAS um objeto JSON.
    NÃO use markdown (```json), NÃO adicione "Claro, aqui está:", apenas o JSON.
    
    O JSON deve conter as chaves "descricao_pt" e "solucao".
    Exemplo:
    {{
      "descricao_pt": "Uma falha de desserialização...",
      "solucao": "Atualize {dependencia} para a versão 5.0.0 ou superior."
    }}
    """
    
    # O payload da API 'v1' é um pouco diferente
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt_texto}
                ]
            }
        ]
    }
    
    data = json.dumps(payload).encode('utf-8')
    headers = {"Content-Type": "application/json"}

    raw_response_text = ""
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method='POST')
        
        # Adiciona um contexto SSL (boa prática)
        context = ssl.create_default_context()
        
        with urllib.request.urlopen(req, context=context) as response:
            response_body = response.read().decode('utf-8')
            raw_response_text = response_body
            response_json = json.loads(response_body)
            
            # Navega na resposta JSON
            solucao_bruta = response_json['candidates'][0]['content']['parts'][0]['text']
            
            # A IA ainda pode ser "tagarela", então usamos regex
            match = re.search(r"\{.*\}", solucao_bruta, re.DOTALL)
            if not match:
                raise ValueError("Nenhum JSON válido encontrado na resposta da IA")

            dados_ia = json.loads(match.group(0))
            return dados_ia.get('descricao_pt', 'IA falhou em gerar descrição.'), \
                   dados_ia.get('solucao', 'IA falhou em gerar solução.')

    except Exception as e:
        logging.error(f"===== FALHA AO PROCESSAR IA (urllib) para {cve} =====")
        logging.error(f"Erro: {e}")
        logging.error(f"Resposta BRUTA da API: {raw_response_text}")
        logging.error("==========================================")
        fallback_desc = f"(Tradução falhou) {descricao_en}"
        fallback_sol = "Falha ao consultar a IA para uma solução."
        return fallback_desc, fallback_sol

def gerar_relatorio_html(dados_finais, output_path):
    # ... (Esta função continua EXATAMENTE igual, com o CSS e a tabela) ...
    logging.info(f"Gerando relatório HTML em: {output_path}")
    html_style = """
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 20px; background-color: #f9f9f9; color: #333; }
        h1 { color: #004a9e; border-bottom: 2px solid #004a9e; padding-bottom: 5px; }
        p { font-size: 0.9em; color: #555; }
        table { width: 100%; border-collapse: collapse; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-top: 25px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; vertical-align: top; }
        th { background-color: #f0f0f0; color: #333; font-weight: 600; }
        tr:nth-child(even) { background-color: #fdfdfd; }
        tr:nth-child(odd) { background-color: #f7f7f7; }
        tr:hover { background-color: #e6f0ff; }
        .col-cve { width: 12%; }
        .col-score { width: 6%; }
        .col-sev { width: 8%; }
        .col-desc { width: 44%; }
        .col-sol { width: 30%; }
        .severity-CRITICAL { color: #D73A49; font-weight: bold; }
        .severity-HIGH { color: #F56A00; font-weight: bold; }
        .severity-MODERATE { color: #DBAB09; }
        .severity-LOW { color: #31704B; }
    </style>
    """
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
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        logging.info(f"Relatório salvo com sucesso em {Path(output_path).resolve()}!")
    except Exception as e:
        logging.error(f"Falha ao salvar o arquivo HTML. Erro: {e}")

def main():
    # ... (Esta função continua EXATAMENTE igual) ...
    if API_KEY == 'ERRO_KEY_NAO_DEFINIDA':
        logging.error("A variável de ambiente 'API_KEY_GEMINI' não foi definida no Jenkins.")
        return
    # Note que não configuramos mais a IA aqui
    
    vulnerabilidades = analisar_json(JSON_INPUT_PATH)
    if not vulnerabilidades:
        logging.info("Nenhuma vulnerabilidade encontrada ou o arquivo JSON está vazio. Saindo.")
        return
    
    dados_com_solucao = []
    for vuln in vulnerabilidades:
        if vuln['severidade'] in ['LOW', 'Desconhecida']:
             logging.info(f"Pulando {vuln['cve']} (Severidade: {vuln['severidade']}).")
             continue
        
        # A chamada da função mudou, não passamos mais o "modelo"
        descricao_pt, solucao = obter_dados_ia(
            vuln['cve'], 
            vuln['dependencia'], 
            vuln['descricao_en']
        )
        dados_com_solucao.append({
            "cve": vuln['cve'],
            "severidade": vuln['severidade'],
            "score": vuln['score'],
            "descricao_pt": descricao_pt,
            "solucao": solucao
        })
    if not dados_com_solucao:
        logging.info("Nenhuma vulnerabilidade (Moderada ou superior) encontrada para gerar relatório.")
        return
    gerar_relatorio_html(dados_com_solucao, HTML_OUTPUT_PATH)

if __name__ == "__main__":
    main()