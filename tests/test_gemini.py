
# from openai import OpenAI

# client = OpenAI(
#     api_key ="AIzaSyDCjKZZ9SRXTNOo5Zr-D1YoEphrQ2zbn2w",
#     base_url = "https://generativelanguage.googleapis.com/v1beta/openai/"
# )

# response = client.chat.completions.create(
#     model = "gemini-2.0-flash",
#     messages = [
#         { "role": "system", "content": "You are a helpful assistant." },
#         { "role": "user",   "content": "Hello, Gemini!" }
#     ],
#     max_tokens = 100
# )

# print(response.choices[0].message)


import requests
import json

# CHANGE THIS to your Ollama server IP
OLLAMA_URL = "http://192.168.13.162:11434/api/generate"

def query_ollama(model, prompt):
    payload = {
        "model": model,
        "prompt": prompt
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload)
        response.raise_for_status()

        # Ollama returns multiple lines of JSON
        text_output = ""
        for line in response.text.splitlines():
            try:
                data = json.loads(line)
                text_output += data.get("response", "")
            except:
                pass

        return text_output

    except Exception as e:
        print("Error:", e)
        return None


if __name__ == "__main__":
    model = "llama3.1:8b"   # change if you use different model
    prompt = "what is 2 + 2 ?"

    print(f"Sending prompt to Ollama: {prompt}")
    result = query_ollama(model, prompt)

    print("\n--- LLM Output ---")
    print(result)
