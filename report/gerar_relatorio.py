import json
import os
import logging
import urllib.request
import urllib.error
import ssl
import time
import webbrowser
import sys
from pathlib import Path

# =========================
# CONFIGURAÇÕES GERAIS
# =========================

API_KEY = os.environ.get("API_KEY_GEMINI", "ERRO_KEY_NAO_DEFINIDA")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

# Se o caminho do JSON for passado via linha de comando, usa ele.
# Senão, usa um padrão (ajuste para o seu caminho real).
if len(sys.argv) > 1:
    JSON_INPUT_PATH = sys.argv[1]
else:
    JSON_INPUT_PATH = r"C:\Users\Carlos Eduardo\Desktop\Programacao\Dependency-Check\report\dependency-check-report.json"

# Caminho padrão de saída do HTML (pode ser no mesmo diretório do JSON)
if len(sys.argv) > 2:
    HTML_OUTPUT_PATH = sys.argv[2]
else:
    HTML_OUTPUT_PATH = str(Path(JSON_INPUT_PATH).parent / "relatorio_vulnerabilidades.html")

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


# =========================
# LEITURA E ANÁLISE DO JSON
# =========================

def analisar_json(filepath: str):
    """
    Lê o JSON do Dependency-Check e extrai uma lista de vulnerabilidades no formato:
    {
      "cve": ...,
      "severidade": ...,
      "descricao_en": ...,
      "dependencia": ...,
      "score": ...
    }
    """
    logging.info(f"Analisando o arquivo JSON em: {filepath}")
    vulnerabilidades_encontradas = []

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        if "dependencies" not in data:
            logging.warning("JSON não possui a chave 'dependencies'.")
            return []

        for dep in data["dependencies"]:
            if "vulnerabilities" in dep and dep["vulnerabilities"]:
                dep_nome = dep.get("fileName", "Dependência desconhecida")

                for vuln in dep["vulnerabilities"]:
                    score = "N/A"
                    if "cvssv3" in vuln and vuln["cvssv3"].get("baseScore"):
                        score = vuln["cvssv3"].get("baseScore")
                    elif "cvssv2" in vuln and vuln["cvssv2"].get("score"):
                        score = vuln["cvssv2"].get("score")

                    vulnerabilidades_encontradas.append({
                        "cve": vuln.get("name", "N/A"),
                        "severidade": vuln.get("severity", "Desconhecida"),
                        "descricao_en": vuln.get("description", "Sem descrição."),
                        "dependencia": dep_nome,
                        "score": score
                    })

        logging.info(f"Extraídas {len(vulnerabilidades_encontradas)} vulnerabilidades do JSON.")
        return vulnerabilidades_encontradas

    except FileNotFoundError:
        logging.error(f"ERRO: Arquivo JSON não encontrado em {filepath}")
        return []
    except json.JSONDecodeError:
        logging.error("ERRO: Falha ao decodificar o JSON. O arquivo está corrompido?")
        return []


# =========================
# CHAMADA AO GEMINI (LOCAL)
# =========================

def obter_dados_ia(cve, dependencia, descricao_en):
    """
    Consulta o Gemini (v1beta) em modo JSON para obter:
      - descricao_pt
      - solucao

    Necessário:
      - variável de ambiente API_KEY_GEMINI setada
      - GEMINI_MODEL (ex: gemini-2.5-flash)
    """
    logging.info(f"Consultando IA (via urllib) para dados da {cve}...")

    if API_KEY == "ERRO_KEY_NAO_DEFINIDA":
        logging.error("API_KEY_GEMINI não definida na máquina local.")
        fallback_desc = f"(Sem IA) {descricao_en}"
        fallback_sol = "Configure a variável de ambiente API_KEY_GEMINI para usar a IA."
        return fallback_desc, fallback_sol

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"
    logging.info(f"VERIFICAÇÃO DE URL: Estou chamando: {url}")

    prompt_texto = f"""
Você é um assistente de cibersegurança.
Analise a vulnerabilidade:

- CVE: {cve}
- Dependência afetada: {dependencia}
- Descrição original em inglês: "{descricao_en}"

Gere uma resposta em PORTUGUÊS contendo:

1) "descricao_pt": um resumo técnico claro da vulnerabilidade em português, em até 4 frases.
2) "solucao": orientações objetivas de mitigação/correção (por exemplo: atualizar versão, aplicar patch, alterar configuração, mitigar com WAF etc.).

A resposta DEVE ser estritamente um JSON VÁLIDO, sem comentários, sem markdown, sem texto extra.
Exemplo de formato:

{{
  "descricao_pt": "Resumo da falha em português...",
  "solucao": "Passos claros de mitigação/correção..."
}}
"""

    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt_texto}]
            }
        ],
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseSchema": {
                "type": "OBJECT",
                "properties": {
                    "descricao_pt": {"type": "STRING"},
                    "solucao": {"type": "STRING"}
                },
                "required": ["descricao_pt", "solucao"]
            }
        }
    }

    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "x-goog-api-key": API_KEY,
    }

    raw_response_text = ""

    for tentativa in range(3):
        try:
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            context = ssl.create_default_context()
            with urllib.request.urlopen(req, context=context, timeout=30) as response:
                response_body = response.read().decode("utf-8", errors="replace")
                raw_response_text = response_body
                response_json = json.loads(response_body)

                texto_json = response_json["candidates"][0]["content"]["parts"][0]["text"]
                dados_ia = json.loads(texto_json)

                return (
                    dados_ia.get("descricao_pt", "IA falhou em gerar descrição."),
                    dados_ia.get("solucao", "IA falhou em gerar solução."),
                )

        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass

            logging.error(f"===== FALHA AO PROCESSAR IA (urllib) para {cve} (tentativa {tentativa+1}/3) =====")
            logging.error(f"HTTP {e.code} {e.reason}")
            logging.error(f"Resposta BRUTA da API: {body}")
            logging.error("==========================================")

            # Se for modelo sobrecarregado, tenta de novo
            if e.code == 503 and tentativa < 2:
                espera = 2 * (tentativa + 1)
                logging.info(f"Modelo sobrecarregado (503). Aguardando {espera}s e tentando novamente...")
                time.sleep(espera)
                continue
            else:
                break

        except Exception as e:
            logging.error(f"===== FALHA AO PROCESSAR IA (urllib) para {cve} =====")
            logging.error(f"Erro: {e}")
            logging.error(f"Resposta BRUTA da API: {raw_response_text}")
            logging.error("==========================================")
            break

    # Se chegou aqui, falhou em todas as tentativas
    fallback_desc = f"(Tradução falou) {descricao_en}"
    fallback_sol = "Falha ao consultar a IA para uma solução."
    return fallback_desc, fallback_sol


# =========================
# GERAÇÃO DO HTML + ABRIR NO NAVEGADOR
# =========================

def gerar_relatorio_html(dados_finais, output_path, abrir_navegador=True):
    logging.info(f"Gerando relatório HTML em: {output_path}")

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
            margin-top: 25px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        th, td {
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
            vertical-align: top;
        }
        th {
            background-color: #f0f0f0;
            font-weight: 600;
        }
        tr:nth-child(even) { background-color: #fdfdfd; }
        tr:nth-child(odd) { background-color: #f7f7f7; }
        tr:hover { background-color: #e6f0ff; }
        .severity-CRITICAL { color: #D73A49; font-weight: bold; }
        .severity-HIGH { color: #F56A00; font-weight: bold; }
        .severity-MEDIUM, .severity-MODERATE { color: #DBAB09; }
        .severity-LOW { color: #31704B; }
    </style>
    """

    linhas = []
    for item in dados_finais:
        sev_upper = (item["severidade"] or "").upper()
        severidade_class = f"severity-{sev_upper}"
        linhas.append(f"""
        <tr>
            <td>{item['cve']}</td>
            <td style="text-align:center;"><b>{item['score']}</b></td>
            <td class="{severidade_class}">{item['severidade']}</td>
            <td>{item['descricao_pt']}</td>
            <td>{item['solucao']}</td>
        </tr>
        """)

    html = f"""
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Relatório de Vulnerabilidades</title>
      {html_style}
    </head>
    <body>
      <h1>Relatório de Análise de Vulnerabilidades</h1>
      <p>Relatório gerado a partir do OWASP Dependency-Check e da IA (Gemini).</p>
      <table>
        <thead>
          <tr>
            <th>CVE</th>
            <th>Score</th>
            <th>Severidade</th>
            <th>Descrição (PT-BR)</th>
            <th>Solução Recomendada</th>
          </tr>
        </thead>
        <tbody>
          {''.join(linhas)}
        </tbody>
      </table>
    </body>
    </html>
    """

    saida = Path(output_path)
    try:
        saida.write_text(html, encoding="utf-8")
        logging.info(f"Relatório salvo com sucesso em {saida.resolve()}!")
    except Exception as e:
        logging.error(f"Falha ao salvar o arquivo HTML. Erro: {e}")
        return

    if abrir_navegador:
        try:
            url = saida.resolve().as_uri()
            logging.info(f"Abrindo relatório no navegador: {url}")
            webbrowser.open(url, new=2)
        except Exception as e:
            logging.error(f"Falha ao abrir o relatório no navegador. Erro: {e}")


# =========================
# MAIN
# =========================

def main():
    logging.info(f"Usando JSON em: {JSON_INPUT_PATH}")
    logging.info(f"HTML de saída: {HTML_OUTPUT_PATH}")
    vulnerabilidades = analisar_json(JSON_INPUT_PATH)
    if not vulnerabilidades:
        logging.info("Nenhuma vulnerabilidade encontrada no JSON.")
        return

    dados_com_solucao = []
    for vuln in vulnerabilidades:
        # Se quiser pular LOW, pode usar:
        # if vuln["severidade"] in ["LOW", "Desconhecida"]:
        #     continue
        descricao_pt, solucao = obter_dados_ia(
            vuln["cve"],
            vuln["dependencia"],
            vuln["descricao_en"]
        )
        dados_com_solucao.append({
            "cve": vuln["cve"],
            "severidade": vuln["severidade"],
            "score": vuln["score"],
            "descricao_pt": descricao_pt,
            "solucao": solucao
        })

    if not dados_com_solucao:
        logging.info("Nenhuma vulnerabilidade processada pela IA para gerar relatório.")
        return

    gerar_relatorio_html(dados_com_solucao, HTML_OUTPUT_PATH, abrir_navegador=True)


if __name__ == "__main__":
    main()
