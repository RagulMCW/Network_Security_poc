
from openai import OpenAI

client = OpenAI(
    api_key ="AIzaSyDCjKZZ9SRXTNOo5Zr-D1YoEphrQ2zbn2w",
    base_url = "https://generativelanguage.googleapis.com/v1beta/openai/"
)

response = client.chat.completions.create(
    model = "gemini-2.0-flash",
    messages = [
        { "role": "system", "content": "You are a helpful assistant." },
        { "role": "user",   "content": "Hello, Gemini!" }
    ],
    max_tokens = 100
)

print(response.choices[0].message)
