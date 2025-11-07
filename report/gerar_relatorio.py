import json
import os
import logging
import urllib.request
import re
import ssl
from pathlib import Path

# ------------ Config -------------
API_KEY = os.environ.get('API_KEY_GEMINI', 'ERRO_KEY_NAO_DEFINIDA')
GEMINI_MODEL = os.environ.get('GEMINI_MODEL', 'gemini-1.5-flash')  # pode trocar por gemini-1.5-pro
JSON_INPUT_PATH = "target/dependency-check-report.json"
HTML_OUTPUT_PATH = "relatorio_vulnerabilidades.html"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Opcional: garantir UTF-8 no Windows/Jenkins
try:
    import sys
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    pass
# ---------------------------------

def analisar_json(filepath):
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

def _first_json_block(texto: str) -> str | None:
    """Extrai o primeiro bloco { ... } bem-formado da string."""
    stack = 0
    start = -1
    for i, ch in enumerate(texto):
        if ch == '{':
            if stack == 0:
                start = i
            stack += 1
        elif ch == '}':
            if stack > 0:
                stack -= 1
                if stack == 0 and start != -1:
                    return texto[start:i+1]
    return None

def obter_dados_ia(cve, dependencia, descricao_en):
    """
    Pergunta ao Gemini a SOLUÇÃO e a TRADUÇÃO usando urllib (API v1beta).
    """
    logging.info(f"Consultando IA (via urllib) para dados da {cve}...")

    # Endpoint correto (v1beta) + modelo configurável
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={API_KEY}"

    logging.info(f"VERIFICAÇÃO DE URL: Estou chamando: {url}")

    prompt_texto = (
        "Você é um assistente de cibersegurança.\n"
        "Analise a vulnerabilidade e responda APENAS um objeto JSON com as chaves \"descricao_pt\" e \"solucao\".\n"
        "Não use Markdown, não escreva nada além do JSON.\n\n"
        f"- CVE: {cve}\n"
        f"- Dependência: {dependencia}\n"
        f"- Descrição (Inglês): \"{descricao_en}\"\n\n"
        "Exemplo de resposta:\n"
        "{\n"
        "  \"descricao_pt\": \"Resumo objetivo da falha em PT-BR\",\n"
        "  \"solucao\": \"Ação concreta: atualizar para versão X, aplicar patch Y, mitigar com Z\"\n"
        "}"
    )

    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt_texto}]
            }
        ]
    }
    data = json.dumps(payload).encode('utf-8')
    headers = {"Content-Type": "application/json; charset=utf-8"}
    raw_response_text = ""

    try:
        req = urllib.request.Request(url, data=data, headers=headers, method='POST')
        context = ssl.create_default_context()
        with urllib.request.urlopen(req, context=context, timeout=30) as response:
            response_body = response.read().decode('utf-8', errors='replace')
            raw_response_text = response_body
            response_json = json.loads(response_body)

            # Caminho típico da resposta Gemini v1beta
            txt = response_json["candidates"][0]["content"]["parts"][0]["text"]

            # Extrai JSON da resposta textual do modelo
            bloco = _first_json_block(txt)
            if not bloco:
                raise ValueError("Nenhum JSON válido encontrado na resposta da IA")

            dados_ia = json.loads(bloco)
            return dados_ia.get('descricao_pt', 'IA falhou em gerar descrição.'), \
                   dados_ia.get('solucao', 'IA falhou em gerar solução.')

    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode('utf-8', errors='replace')
        except Exception:
            pass
        logging.error(f"===== FALHA AO PROCESSAR IA (urllib) para {cve} =====")
        logging.error(f"HTTP {e.code} {e.reason}")
        logging.error(f"Resposta BRUTA da API: {body or raw_response_text}")
        logging.error("==========================================")
    except Exception as e:
        logging.error(f"===== FALHA AO PROCESSAR IA (urllib) para {cve} =====")
        logging.error(f"Erro: {e}")
        logging.error(f"Resposta BRUTA da API: {raw_response_text}")
        logging.error("==========================================")

    # Fallback (mantive seu 'falou' para você distinguir versões)
    fallback_desc = f"(Tradução falou) {descricao_en}"
    fallback_sol = "Falha ao consultar a IA para uma solução."
    return fallback_desc, fallback_sol

def gerar_relatorio_html(dados_finais, output_path):
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
        .severity-MEDIUM, .severity-MODERATE { color: #DBAB09; }
        .severity-LOW { color: #31704B; }
    </style>
    """
    table_rows = ""
    for item in dados_finais:
        sev_upper = (item['severidade'] or "").upper()
        severidade_class = f"severity-{sev_upper}"
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
    if API_KEY == 'ERRO_KEY_NAO_DEFINIDA':
        logging.error("A variável de ambiente 'API_KEY_GEMINI' não foi definida no Jenkins.")
        return
    vulnerabilidades = analisar_json(JSON_INPUT_PATH)
    if not vulnerabilidades:
        logging.info("Nenhuma vulnerabilidade encontrada ou o arquivo JSON está vazio. Saindo.")
        return
    dados_com_solucao = []
    for vuln in vulnerabilidades:
        # pule leves/desconhecidas
        if vuln['severidade'] in ['LOW', 'Desconhecida']:
            logging.info(f"Pulando {vuln['cve']} (Severidade: {vuln['severidade']}).")
            continue
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
