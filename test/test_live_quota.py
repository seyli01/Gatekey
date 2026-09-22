#!/usr/bin/env python3
"""
Test de validation en direct des quotas et budgets avec Gatekey, Groq et Google Gemini.
Ce script effectue des requêtes à travers Gatekey et vérifie :
1. La réponse générée par l'IA (Groq et Gemini)
2. Les en-têtes télémétriques de quota retournés (X-Quota-Tokens-*, X-Quota-Budget-*)
3. Le contenu du fichier quotas.json sauvegardé sur le disque
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error

GATEKEY_URL = "http://localhost:8080"
CLIENT_TOKEN = "mon-client-token-secret"

def call_gatekey(route: str, model: str, prompt: str, stream: bool = False):
    url = f"{GATEKEY_URL}{route}"
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": stream,
    }
    if not stream:
        payload["max_tokens"] = 30

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-App-Token": CLIENT_TOKEN,
            "User-Agent": "OpenAI/Python 1.50.0",
        },
        method="POST",
    )

    print(f"\n---> Appel vers Gatekey : POST {url}")
    print(f"     Modèle : {model} (streaming: {stream})")
    print(f"     Prompt : \"{prompt}\"")

    try:
        t0 = time.time()
        with urllib.request.urlopen(req, timeout=15) as resp:
            elapsed = (time.time() - t0) * 1000
            headers = dict(resp.headers)
            body_bytes = resp.read()

            print(f"<--- Réponse reçue en {elapsed:.1f} ms | Status: {resp.status}")

            # Extraire les en-têtes de quota
            print("\n[En-têtes Télémétriques Quotas reçus :]")
            for h in ["X-Quota-Tokens-Limit", "X-Quota-Tokens-Used", "X-Quota-Budget-Limit", "X-Quota-Budget-Used", "X-RateLimit-Remaining"]:
                if h in headers:
                    print(f"   {h}: {headers[h]}")

            # Afficher le texte généré
            if stream:
                print("\n[Flux Streaming SSE reçu :]")
                lines = body_bytes.decode("utf-8", errors="replace").split("\n")
                content_parts = []
                for line in lines:
                    if line.startswith("data: ") and not line.endswith("[DONE]"):
                        try:
                            chunk = json.loads(line[6:])
                            c = chunk.get("choices", [{}])[0].get("delta", {}).get("content", "")
                            if c:
                                content_parts.append(c)
                        except Exception:
                            pass
                print(f"   Contenu reconstitué : \"{''.join(content_parts)}\"")
            else:
                resp_json = json.loads(body_bytes.decode("utf-8"))
                msg = resp_json.get("choices", [{}])[0].get("message", {})
                content = msg.get("content", "") or msg.get("reasoning", "")
                usage = resp_json.get("usage", {})
                print(f"\n[Texte IA généré :] \"{content.strip()}\"")
                print(f"[Usage rapporté par l'amont :] {usage}")

            return True

    except urllib.error.HTTPError as e:
        print(f"[ERREUR HTTP {e.code}] : {e.read().decode('utf-8')}")
        return False
    except Exception as e:
        print(f"[ERREUR CONNEXION] : {e}")
        return False

def check_quotas_file():
    quota_path = "quotas.json"
    print("\n" + "=" * 60)
    print("VÉRIFICATION DE LA PERSISTANCE SUR DISQUE (quotas.json)")
    print("=" * 60)

    if not os.path.exists(quota_path):
        print("Note: quotas.json sera écrit sur disque dans un instant (intervalle 60s ou arrêt).")
        return

    try:
        with open(quota_path, "r") as f:
            data = json.load(f)
        print(json.dumps(data, indent=2))
    except Exception as e:
        print(f"Erreur lecture quotas.json : {e}")

def main():
    print("================================================================================")
    print("TEST LIVE GATEKEY : GROQ & GOOGLE GEMINI AVEC SUIVI DES QUOTAS")
    print("================================================================================")

    # 1. Test Groq (Standard JSON)
    print("\n--- [1/3] Test Groq (Appel Unitaire) ---")
    call_gatekey(
        route="/groq/v1/chat/completions",
        model="openai/gpt-oss-20b",
        prompt="Dis 'Bonjour depuis Groq via Gatekey !' en une phrase courte.",
        stream=False,
    )

    # 2. Test Gemini (Standard JSON)
    print("\n--- [2/3] Test Google Gemini (Appel Unitaire) ---")
    call_gatekey(
        route="/gemini/chat/completions",
        model="gemini-flash-latest",
        prompt="Dis 'Bonjour depuis Gemini via Gatekey !' en une phrase courte.",
        stream=False,
    )

    # 3. Test Groq Streaming SSE
    print("\n--- [3/3] Test Groq (Streaming Server-Sent Events) ---")
    call_gatekey(
        route="/groq/v1/chat/completions",
        model="openai/gpt-oss-20b",
        prompt="Compte de 1 à 4.",
        stream=True,
    )

    # 4. Vérification quotas
    time.sleep(0.5)
    check_quotas_file()

if __name__ == "__main__":
    main()
