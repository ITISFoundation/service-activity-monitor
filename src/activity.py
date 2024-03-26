import requests

r = requests.get("http://localhost:19597/activity")
print(r.text)
