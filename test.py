import requests

url1 = "http://127.0.0.1:5000/create-account"
rec = {"username":"ian","password":"password321"}

resp1 = requests.post(url1, json=rec)
print(f"POST /create-account: {rec}")
print(f"Response: {resp1.text}")

url2 = "http://127.0.0.1:5000/login"

resp2 = requests.post(url2, json=rec)
print(f"POST /login: {rec}")
print(f"Response: {resp2.text}")