import requests

files = {'image01': open('01.zip', 'rb')}
user_info = {'name': 'letian'}
r = requests.post("http://127.0.0.1:5000/upload", data=user_info, files=files)

print(r.text)