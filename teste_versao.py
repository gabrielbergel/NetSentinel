import google.generativeai as genai
import sys
import os
from dotenv import load_dotenv

load_dotenv()

print("--- DIAGNÓSTICO ---")
print(f"1. Onde está o Python: {sys.executable}")
print(f"2. Versão da biblioteca 'google-generativeai': {genai.__version__}")
print(f"3. Chave de API detectada: {'SIM' if os.getenv('GEMINI_API_KEY') else 'NÃO'}")

print("\n--- TENTANDO LISTAR MODELOS DISPONÍVEIS ---")
try:
    genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
    
    found_flash = False
    for m in genai.list_models():
        print(f" - Encontrado: {m.name}")
        if 'flash' in m.name:
            found_flash = True
            
    if found_flash:
        print("\n✅ SUCESSO: O modelo Flash está disponível para sua chave!")
    else:
        print("\n⚠️ AVISO: A conexão funcionou, mas o modelo Flash NÃO apareceu na lista.")
        
except Exception as e:
    print(f"\n❌ ERRO FATAL DE CONEXÃO: {e}")