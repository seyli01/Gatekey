import sys
from openai import OpenAI

# ==============================================================================
# Exemple d'intégration Python avec le SDK standard OpenAI pointant sur Gatekey
# Exécution sans rien installer grâce à uv :
#   uv run --with openai python client_demo.py
# ==============================================================================

# 1. URL de votre reverse proxy Gatekey
GATEKEY_BASE_URL = "http://localhost:8080/groq/v1"

# 2. Le token applicatif autorisé dans config.yaml (PAS la clé Groq !)
CLIENT_TOKEN = "mon-client-token-secret"

# 3. Initialisation du client OpenAI officiel
client = OpenAI(
    base_url=GATEKEY_BASE_URL,
    api_key="dummy-key",  # Le SDK OpenAI exige une chaîne non-vide, mais Gatekey injecte le vrai secret
    default_headers={"X-App-Token": CLIENT_TOKEN},
)

def main():
    print("[1/2] Test d'un appel standard (non-streaming)...")
    try:
        completion = client.chat.completions.create(
            model="openai/gpt-oss-20b",
            messages=[
                {"role": "user", "content": "Réponds juste : 'Gatekey fonctionne parfaitement !'"}
            ],
            stream=False,
        )
        print("Réponse :", completion.choices[0].message.content)
    except Exception as e:
        print(f"Erreur appel standard : {e}", file=sys.stderr)
        return

    print("\n[2/2] Test du streaming SSE en direct...")
    try:
        stream = client.chat.completions.create(
            model="openai/gpt-oss-20b",
            messages=[
                {"role": "user", "content": "Compte de 1 à 5 en un seul mot par ligne."}
            ],
            stream=True,
        )
        for chunk in stream:
            token = chunk.choices[0].delta.content
            if token:
                print(token, end="", flush=True)
        print("\n\nSuccès total du flux streaming !")
    except Exception as e:
        print(f"Erreur streaming : {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
