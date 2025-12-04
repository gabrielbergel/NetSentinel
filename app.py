# -*- coding: utf-8 -*-
import os
import subprocess
import glob
import google.generativeai as genai
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv

# Carrega variaveis de ambiente
load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    print("ERRO: API Key nao encontrada. Verifique o arquivo .env")

genai.configure(api_key=API_KEY)

# Configuracao da IA
generation_config = {
  "temperature": 0.3,
  "top_p": 0.95,
  "top_k": 64,
  "max_output_tokens": 8192,
}

MODEL_NAME = "models/gemini-2.5-flash"

# Pasta para salvar o historico
HISTORY_DIR = "history"
if not os.path.exists(HISTORY_DIR):
    os.makedirs(HISTORY_DIR)

app = Flask(__name__)

# Prompt sem acentos para evitar erros de encoding
SYSTEM_PROMPT = (
    "ATENCAO: Voce e uma IA de Auditoria de Redes e Analise Forense (NetSentinel).\n"
    "Sua missao e analisar logs brutos do TCPDump e gerar um Relatorio Tecnico Formal.\n\n"
    
    "DIRETRIZES DE ANALISE:\n"
    "1. FILTRAGEM DE RUIDO (Ignorar, exceto se for ataque volumetrico):\n"
    "   - Trafego mDNS/Bonjour (porta 5353), SSDP (1900), LLMNR (5355).\n"
    "   - Requisicoes ARP normais (Who-has).\n"
    "   - Trafego de broadcast/multicast padrao de IoT (Google Cast, Spotify).\n\n"
    
    "2. FOCO EM AMEACAS REAIS (Prioridade Alta):\n"
    "   - Port Scans (Multiplas conexoes rapidas a portas distintas ou sequenciais).\n"
    "   - ARP Spoofing (Multiplos MACs para o mesmo IP ou mudancas frequentes).\n"
    "   - Tentativas de conexao suspeitas (Portas altas incomuns, IPs externos desconhecidos).\n"
    "   - Flags TCP anomalas (Null, Xmas, Fin scan).\n"
    "   - Trafego em texto claro (HTTP, Telnet, FTP) contendo dados sensiveis.\n"
    "   - Padroes de DoS/DDoS (Syn Flood, UDP Flood).\n\n"
    
    "ESTRUTURA DO RELATORIO (Markdown Rigoroso):\n"
    "Use uma linguagem tecnica, objetiva e impessoal (Ex: 'Observou-se', 'Recomenda-se').\n"
    "O relatorio deve conter OBRIGATORIAMENTE as seguintes secoes:\n\n"
    
    "## 1. Resumo Executivo\n"
    "Visao gerencial de alto nivel. Indique se a rede esta SEGURA, SOB ALERTA ou COMPROMETIDA. Resuma os principais achados em 1 paragrafo.\n\n"
    
    "## 2. Detalhamento de Anomalias\n"
    "Para cada ameaca detectada, crie um bloco:\n"
    "- **Tipo:** (Classificacao da ameaca)\n"
    "- **Gravidade:** (Baixa/Media/Alta/Critica)\n"
    "- **Origem > Destino:** (IPs envolvidos)\n"
    "- **Evidencia Tecnica:** (Explicacao sucinta baseada no log)\n\n"
    
    "## 3. Inventario de Trafego\n"
    "Liste os protocolos e dispositivos legitimos identificados (ex: 'Trafego predominante de HTTPS e DNS. Presenca de dispositivos Apple via mDNS').\n\n"
    
    "## 4. Recomendacoes de Mitigacao\n"
    "Lista numerada de acoes praticas para resolver os problemas encontrados.\n\n"
    
    "IMPORTANTE: Se o log contiver apenas ruido, informe claramente no Resumo Executivo que nenhuma ameaca ativa foi detectada, mas sugira melhorias de segmentacao (VLANs) para reduzir o broadcast."
)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/history', methods=['GET'])
def list_history():
    """Lista todos os relatorios salvos na pasta history"""
    try:
        # Busca arquivos .md
        files = glob.glob(os.path.join(HISTORY_DIR, "*.md"))
        # Extrai apenas o nome do projeto (sem extensao e caminho)
        projects = [os.path.splitext(os.path.basename(f))[0] for f in files]
        # Ordena por data de modificacao (mais recente primeiro)
        projects.sort(key=lambda x: os.path.getmtime(os.path.join(HISTORY_DIR, x + ".md")), reverse=True)
        return jsonify({"projects": projects})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/history/<project_name>', methods=['GET'])
def get_report(project_name):
    """Retorna o conteudo Markdown de um relatorio especifico"""
    # Sanitiza nome para seguranca
    safe_name = "".join([c for c in project_name if c.isalnum() or c in ('-', '_')])
    filepath = os.path.join(HISTORY_DIR, f"{safe_name}.md")
    
    if not os.path.exists(filepath):
        return jsonify({"error": "Relatorio nao encontrado."}), 404
        
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        return jsonify({"report": content})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    project_name = data.get('project_name')

    if not project_name:
        return jsonify({"error": "Nome do projeto nao fornecido."}), 400

    # Sanitiza o nome para evitar problemas no Linux
    safe_name = "".join([c for c in project_name if c.isalnum() or c in ('-', '_')])
    txt_filename = f"{safe_name}.txt"
    
    # Configuracao da Captura
    INTERFACE = "any" 
    DURATION = "20s"

    print(f"--- Iniciando Captura: {safe_name} por {DURATION} ---")

    try:
        # COMANDO TCPDUMP
        with open(txt_filename, "w") as outfile:
            try:
                subprocess.run(
                    ["sudo", "timeout", DURATION, "tcpdump", "-i", INTERFACE, "-n", "-v"], 
                    stdout=outfile, 
                    stderr=subprocess.DEVNULL,
                    check=False 
                )
            except Exception as e:
                print(f"Erro no subprocesso: {e}")
                return jsonify({"error": f"Erro ao rodar TCPDump: {str(e)}"}), 500
                
        print("--- Captura Finalizada. Iniciando Analise de IA ---")

        if not os.path.exists(txt_filename) or os.path.getsize(txt_filename) == 0:
            return jsonify({"error": "Falha na captura: Arquivo vazio. Verifique se rodou o app com SUDO."}), 500

        with open(txt_filename, 'r', encoding='utf-8', errors='ignore') as f:
            log_content = f.read()

        full_prompt = f"{SYSTEM_PROMPT}\n\nLOG CAPTURADO ({safe_name}):\n{log_content}"
        
        model = genai.GenerativeModel(model_name=MODEL_NAME, generation_config=generation_config)
        response = model.generate_content(full_prompt)
        
        # --- SALVAR NO HISTORICO ---
        md_filepath = os.path.join(HISTORY_DIR, f"{safe_name}.md")
        with open(md_filepath, "w", encoding="utf-8") as f:
            f.write(response.text)
        
        return jsonify({"report": response.text})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)