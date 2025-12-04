NetSentinel - Auditoria de Rede com IA

Ferramenta de análise forense de rede que captura tráfego em tempo real usando TCPDump e utiliza a API do Google Gemini para gerar relatórios de segurança automatizados.

Pré-requisitos

Sistema Operacional Linux (Testado no Ubuntu Live Server)

Python 3.10 ou superior

Acesso root (sudo) para execução do TCPDump

Chave de API do Google Gemini (AI Studio)

Instalação

Atualize o sistema e instale as dependências do sistema operacional:

sudo apt update
sudo apt install python3-venv python3-pip tcpdump -y

Crie e ative o ambiente virtual (dentro da pasta do projeto):

python3 -m venv venv
source venv/bin/activate

Instale as dependências do Python:

pip install -r requirements.txt

Configuração

Crie um arquivo chamado .env na raiz do projeto.

Adicione sua chave de API no arquivo:

GEMINI_API_KEY=sua_chave_aqui_sem_aspas

Execução

A aplicação deve ser executada com permissões de superusuário para que o TCPDump possa capturar pacotes da interface de rede.

Ative o ambiente virtual (se ainda não estiver ativo):

source venv/bin/activate

Inicie o servidor Flask com sudo:

sudo ./venv/bin/python3 app.py

Acesse a interface web através do navegador:

http://localhost:XXXX
ou
http://SEU_IP_DO_SERVIDOR:XXXX

Uso

Na interface, digite um nome para o projeto (ex: cliente-A).

Clique em "INICIAR".

O sistema irá capturar pacotes por 20 segundos.

Após a captura, o log será enviado para a IA e o relatório será exibido na tela.

Os relatórios gerados ficam salvos e podem ser acessados no menu "Histórico".

Estrutura de Arquivos

app.py: Backend Flask e lógica de captura.

templates/index.html: Interface do usuário.

history/: Pasta onde os relatórios (.md) são salvos.

requirements.txt: Lista de bibliotecas Python.

.env: Arquivo de configuração de variáveis (não versionado).
