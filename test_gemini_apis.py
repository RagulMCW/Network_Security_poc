#!/usr/bin/env python3
"""
Test Gemini API in the format Beelzebub expects (OpenAI-compatible)
vs the native Google Generative AI format
"""
import requests
import json

API_KEY = "AIzaSyDCjKZZ9SRXTNOo5Zr-D1YoEphrQ2zbn2w"

print("=" * 60)
print("Test 1: OpenAI-compatible endpoint (what Beelzebub uses)")
print("=" * 60)

openai_url = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
openai_payload = {
    "model": "gemini-2.0-flash-lite",
    "messages": [
        {"role": "user", "content": "Say hello"}
    ]
}

response = requests.post(
    openai_url,
    headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}"
    },
    json=openai_payload
)

print(f"Status: {response.status_code}")
print(f"Response: {response.text[:500]}")
print()

print("=" * 60)
print("Test 2: Native Gemini API endpoint")
print("=" * 60)

native_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-lite:generateContent?key={API_KEY}"
native_payload = {
    "contents": [
        {
            "parts": [
                {"text": "Say hello"}
            ]
        }
    ]
}

response = requests.post(
    native_url,
    headers={"Content-Type": "application/json"},
    json=native_payload
)

print(f"Status: {response.status_code}")
print(f"Response: {response.text[:500]}")
print()

if response.status_code == 200:
    data = response.json()
    if 'candidates' in data:
        print("✅ Native API works!")
        print(f"Response text: {data['candidates'][0]['content']['parts'][0]['text']}")
