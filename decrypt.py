from cryptography.fernet import Fernet

key = b"CEr-3YELYudY4ORz7SKc2YmaOQWO257DuqDZmdvh2lc="  # your printed key
token = b"gAAAAABo5BoAc1HMtdSS29gnIYJp3UuJWRcPaHTldkNqqcY8bGmNtGGYAK7o6UKrkGd2GeAaCbZaUvpjdaUW8qokb8tdXFbGROX9H7eDXyMyzOmfcBxqQbY="

fernet = Fernet(key)
decrypted = fernet.decrypt(token).decode()
print("Decrypted:", decrypted)
