import google.generativeai as genai
import json
import os
import logging
from pathlib import Path
from keys import API_KEY

# --- CONFIGURAÇÃO ---
# 1. LEIA A API KEY DA VARIÁVEL DE AMBIENTE
# O Jenkins vai injetar essa variável. Se não encontrar, usa 'ERRO'
API_KEY = os.environ.get('API_KEY_GEMINI', 'ERRO_KEY_NAO_DEFINIDA')

# 2. Defina os caminhos dos arquivos
#    Este é o JSON gerado pelo Jenkins
JSON_INPUT_PATH = "target/dependency-check-report.json"
#    Este é o HTML que vamos criar
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
                    vulnerabilidades_encontradas.append({
                        "cve": vuln.get('name', 'N/A'),
                        "severidade": vuln.get('severity', 'Desconhecida'),
                        "descricao": vuln.get('description', 'Sem descrição.'),
                        "dependencia": dep_nome
                    })
        
        logging.info(f"Extraídas {len(vulnerabilidades_encontradas)} vulnerabilidades do JSON.")
        return vulnerabilidades_encontradas

    except FileNotFoundError:
        logging.error(f"ERRO: Arquivo JSON não encontrado em {filepath}")
        return []
    except json.JSONDecodeError:
        logging.error(f"ERRO: Falha ao decodificar o JSON. O arquivo está corrompido?")
        return []

def obter_solucao_ia(modelo, cve, dependencia):
    """Pergunta ao Gemini como corrigir uma CVE específica."""
    logging.info(f"Consultando IA para solução da {cve}...")
    
    # Este é o "prompt" que você mencionou.
    # É uma instrução direta para a IA.
    prompt = f"""
    Você é um especialista em cibersegurança e engenharia de software.
    Para a vulnerabilidade {cve} encontrada na dependência "{dependencia}", 
    forneça uma solução prática e concisa para um desenvolvedor.

    Fale em português brasileiro.
    Seja direto. Exemplo: 'Atualize a dependência {dependencia} para a versão X.Y.Z ou superior.'
    """

    try:
        response = modelo.generate_content(prompt)
        # Remove markdown e limpa a resposta
        solucao = response.text.strip().replace('*', '').replace('`', '')
        return solucao
    except Exception as e:
        logging.warning(f"Não foi possível obter solução da IA para {cve}. Erro: {e}")
        return "Não foi possível obter a solução da IA."

def gerar_relatorio_html(dados_finais, output_path):
    """Cria um arquivo HTML bonito com uma tabela dos dados."""
    logging.info(f"Gerando relatório HTML em: {output_path}")

    # CSS para deixar a tabela bonita
    html_style = """
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 20px; background-color: #f9f9f9; }
        h1 { color: #333; }
        table { width: 100%; border-collapse: collapse; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #004a9e; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        tr:hover { background-color: #e6f7ff; }
        .severity-CRITICAL { color: #D73A49; font-weight: bold; }
        .severity-HIGH { color: #F56A00; font-weight: bold; }
        .severity-MODERATE { color: #DBAB09; }
        .severity-LOW { color: #31704B; }
    </style>
    """

    # Montando as linhas da tabela
    table_rows = ""
    for item in dados_finais:
        severidade_class = f"severity-{item['severidade'].upper()}"
        table_rows += f"""
        <tr>
            <td>{item['cve']}</td>
            <td class='{severidade_class}'>{item['severidade']}</td>
            <td>{item['descricao']}</td>
            <td>{item['solucao']}</td>
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
        <p>Este relatório foi gerado processando a saída do OWASP Dependency-Check e consultando a IA (Gemini) para soluções.</p>
        <table>
            <thead>
                <tr>
                    <th>CVE</th>
                    <th>Severidade</th>
                    <th>Descrição</th>
                    <th>Solução Recomendada (IA)</th>
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
        if vuln['severidade'] in ['LOW', 'MODERATE', 'Desconhecida']:
             logging.info(f"Pulando {vuln['cve']} (Severidade: {vuln['severidade']}).")
             continue
        
        solucao = obter_solucao_ia(modelo_ia, vuln['cve'], vuln['dependencia'])
        
        dados_com_solucao.append({
            "cve": vuln['cve'],
            "severidade": vuln['severidade'],
            "descricao": vuln['descricao'],
            "solucao": solucao
        })

    if not dados_com_solucao:
        logging.info("Nenhuma vulnerabilidade de alta criticidade encontrada para gerar relatório.")
        return

    gerar_relatorio_html(dados_com_solucao, HTML_OUTPUT_PATH)

if __name__ == "__main__":
    main()