import asyncio
import httpx
from configparser import ConfigParser
import os
from os import system
import sys
import time
import psycopg2
import logging
import traceback

version = "3.0"

mainPath = os.path.dirname(os.path.abspath(__file__))

#Setting up logging
if not os.path.exists(os.path.join(mainPath, "logs")):
	os.makedirs(os.path.join(mainPath, "logs"))
logName = os.path.join(os.path.join(mainPath, "logs"), time.strftime('%m %d %Y %H %M %S', time.localtime()))
logging.basicConfig(filename=f"{logName}.log", level=logging.ERROR, format="%(asctime)s:%(levelname)s:%(message)s")

clear = lambda: os.system("cls")


def menuOption(options, initMessage = None):
	clear()
	while True:
		iter = 0
		if initMessage:
			print(initMessage)
		for option in options:
			iter += 1
			print(f"[{iter}] {options[iter-1]}")
			
		try:
			option = int(input("Please select an option: "))
			if abs(option) - 1 >= len(options):
				raise IndexError
			clear()
			return abs(option)
		except:
			input("That is not a valid option! Press Enter to retry.")
			clear()
			continue

def loadConfig():
	parser = ConfigParser()
	
	while True:
		try:
			parser.read(os.path.join(mainPath, "config.ini"))
			assert parser["WHITELIST"]["username"] is not None, "Whitelist Username cannot be blank."
			assert parser["WHITELIST"]["password"] is not None, "Whitelist Password cannot be blank."
			assert parser["USER"]["cookie"].split("_")[-1] is not None, "Cookie has wrong formatting or is blank."
			apiCookie = f".ROBLOSECURITY=_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_{parser['USER']['cookie'].split('_')[-1]};"
			assert parser["SETTINGS"]["groups"] is not None, "Groups cannot be blank."
			assert parser["SETTINGS"]["onlyPremium"].upper() in ["TRUE", "FALSE"], "OnlyPremium must be set to True or False."
			
			if parser["OTHER"]["debug"].upper() == "True":
				logging.getLogger("root").setLevel(logging.info)
				logging.info("Debug mode enabled. Set logging level to info.")
			
			return parser["WHITELIST"]["username"], parser["WHITELIST"]["password"], apiCookie, [x.strip() for x in parser["SETTINGS"]["groups"].split(",")], parser["SETTINGS"]["onlyPremium"].upper(), parser["OTHER"]["blacklist"]
			
		except Exception as error:
			logging.warning(f"Failed to load config: {error}")
			print(error)
			input("Press Enter to try again.")

async def titleManager(thing, thing2):
	while True:
		await asyncio.sleep(1)
		system("title " + f"Proteus v{version} | Jartan#7450 | My title here.")

async def checkWhitelist(whitelistUsername, whitelistPassword):
	while True:
		await asyncio.sleep(3600)
		#Check whitelist code here.

async def getUserID(cookie):
	while True:
		async with httpx.AsyncClient() as client:
			request = await client.post("https://www.roblox.com/game/GetCurrentUser.ashx", headers={"Cookie": cookie})
		if request.status_code == 200:
			return int(request.text)
		if request.status_code == 429:
			continue
		else:
			raise UnknownResponse(request.status_code, "https://www.roblox.com/game/GetCurrentUser.ashx")

async def getFollowers(ID, cursor=None):
	while True:
		followedUsers = []
		async with httpx.AsyncClient() as client:
			request = await client.get(f"https://friends.roblox.com/v1/users/{ID}/followings", params={"sortOrder": "Asc", "limit": 100, "cursor": cursor})
		if request.status_code == 200:
			requestJSON = request.json()
			for player in requestJSON["data"]:
				followedUsers.append(player["id"])
			return followedUsers, requestJSON["nextPageCursor"]
		elif request.status_code == 429:
			continue
		else:
			raise UnknownResponse(request.status_code, f"https://friends.roblox.com/v1/users/{ID}/followings")

class InvalidCookie(Exception):
	def __init__(self, cookie):
		self.cookie = cookie
		self.err = f"Cookie {self.cookie} is invalid."
		super().__init__(self.err)

class UnknownResponse(Exception):
	def __init__(self, responseCode, requestURL):
		self.response = responseCode
		self.request = requestURL
		self.err = f"Unknown response code {self.response} on request {self.request}"
		super().__init__(self.err)

async def unfollowProvider(queue, ID):
	followed, cursor = await getFollowers(ID)
	for i in followed:
		await queue.put(i)
	while cursor != None:
		followed, cursor = await getFollowers(cursor, ID)
		for i in followed:
			await queue.put(i)
	await queue.put(None)
			
async def unfollowUser(user, cookie, csrfToken):
	while True:
		async with httpx.AsyncClient() as client:
			request = await client.post(f"https://friends.roblox.com/v1/users/{user}/unfollow", headers={"Cookie": cookie, "X-CSRF-TOKEN": csrfToken, "Content-Length": "0"})
		if request.status_code == 200:
			print("Successfully unfollowed {user}")
			return
		elif request.status_code == 429:
			continue
	
async def unfollowConsumer(queue, user):
	target = await queue.get()
	while target != None:
		await unfollowUser(target, user.cookie, user.csrf)
		target = await queue.get()
	
async def unfollowAll(user, loop):
	ID = await getUserID(user.cookie)
	toUnfollow = asyncio.Queue(maxsize=100)
	tasks = []
	tasks.append(loop.create_task(unfollowProvider(toUnfollow, ID)))
	tasks.append(loop.create_task(unfollowConsumer(toUnfollow, user)))
	await asyncio.wait(tasks)


class User():
	
	def __init__(self, cookie, loop):
		self.cookie = cookie
		# loop.create_task(self.updateCSRF(self.cookie))
	
	async def updateCSRF(self):
		while True:
			try:
				async with httpx.AsyncClient() as client:
					request = await client.get("https://auth.roblox.com/v1/logout", headers={"Cookie": self.cookie})
			except Exception as error:
				raise(error)
			
			try:
				self.csrf = request.headers["x-csrf-token"]
			except Exception:
				try:
					if request.status_code == 429:
						continue
					if request.status_code == 401:
						raise InvalidCookie(self.cookie)
					raise UnknownResponse(request.status_code, "https://auth.roblox.com/v1/logout")
				except Exception as error:
					raise(error)

async def main():
	#Loading config
	print(f"Proteus v{version}")
	print("By Jartan#7450 \n")
	
	loop = asyncio.get_event_loop()
	
	print("Loading Configuration.")
	logging.info("Loading Configuration.")
	whitelistUsername, whitelistPassword, apiCookie, groups, onlyPremium, blacklist = loadConfig()
	logging.info("Configuration Loaded Successfully.")
	print("Configuration Loaded Successfully.")
	
	print("Checking Whitelist.")
	logging.info("Init Whitelist Check.")
	#loop.run_until_complete(checkWhitelist())
	logging.info("Successfully Complete Init Whitelist Check.")
	print("Whitelist Validated.")
	
	print("Checking Cookie.")
	logging.info("Init Checking Cookie.")
	user = User(apiCookie, loop)
	await user.updateCSRF()
	logging.info("Cookie is valid.")
	print("Cookie is Valid!")
	
	
	while True:
		choice = menuOption(["Follow players of all ranks.", "Select which ranks to follow.", "Check how many users you are following.", "Unfollow all users.", "Exit."], "Please select what you would like to do. \n")

		if choice == 1:
			pass
			#Follow players of all ranks.
		if choice == 2:
			pass
			#Select which ranks to follow.
		if choice == 3:
			pass
			#Check following count.
		if choice == 4:
			await unfollowAll(user, loop)
			#Unfollow all.
		if choice == 5:
			sys.exit()
	
	
	


if __name__ == "__main__":
	try:
		asyncio.run(main())
	except Exception as error:
		logging.critical(f"An unknown critical error occurred: {traceback.format_exc()}")
		print(f"An unknown critical error occurred: {traceback.format_exc()}")
	input("All operations have been completed. Press Enter to exit.")
	sys.exit()	