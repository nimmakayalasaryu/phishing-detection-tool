import requests
import re
import openai
from urllib.parse import urlparse

openai.api_key = "PASTE_YOUR_OPENAI_API_KEY_HERE"

def extract_urls(text):
    url_regex = r'(https?://\S+)'
    return re.findall(url_regex, text)

def ai_email_analysis(email_text):
    prompt = f"""
You are a cybersecurity analyst. Analyze the following email and determine if it is phishing.
Give:
1. Phishing Probability (0-100%)
2. Key Indicators
3. Final Verdict

Email:
{email_text}
"""

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role":"user","content":prompt}]
    )

    return response["choices"][0]["message"]["content"]

def scan_url_virustotal(url, api_key):
    headers = {"x-apikey": api_key}
    data = {"url": url}
    
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
    result = response.json()
    return result

def main():
    print("\n--- AI Phishing Detection Tool ---\n")
    
    choice = input("1. Analyze Email\n2. Scan URL\nChoose option: ")

    if choice == "1":
        email_text = input("\nPaste email content:\n")
        print("\nAnalyzing email using AI...\n")
        result = ai_email_analysis(email_text)
        print(result)

    elif choice == "2":
        url = input("\nEnter URL:\n")
        vt_api = input("Enter your VirusTotal API key: ")
        print("\nScanning URL...\n")
        result = scan_url_virustotal(url, vt_api)
        print(result)

    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()
