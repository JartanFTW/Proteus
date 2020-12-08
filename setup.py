import sys
import subprocess

modules = ["psycopg2", "httpx"]

for module in modules:
	subprocess.check_call([sys.executable, "-m", "pip", "install", module])
	
input("Successfully installed all necessary modules.")