import requests

r = requests.get("http://localhost:19597")
print(r.text)