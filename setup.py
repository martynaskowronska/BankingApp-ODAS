from dotenv import load_dotenv
import os

load_dotenv()
print(os.getenv("SECRET_KEY"))
print(os.getenv("AES_KEY"))