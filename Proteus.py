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
import copy

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
			
			return parser["WHITELIST"]["username"], parser["WHITELIST"]["password"], apiCookie, {x.strip() : [] for x in parser["SETTINGS"]["groups"].split(",")}, parser["SETTINGS"]["onlyPremium"].upper(), parser["OTHER"]["blacklist"]
			
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

async def getFollowers(ID, cursor=None):
	# tried = False
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
			raise UnknownResponse(request.status_code, f"https://friends.roblox.com/v1/users/{ID}/followings", requestText = request.text)

class InvalidCookie(Exception):
	def __init__(self, cookie):
		self.cookie = cookie
		self.err = f"Cookie {self.cookie} is invalid."
		super().__init__(self.err)

class UnknownResponse(Exception):
	def __init__(self, responseCode, requestURL, requestText = None):
		self.response = responseCode
		self.request = requestURL
		self.requestText = requestText
		self.err = f"Unknown response code {self.response} on request {self.request} {'Text: '+self.requestText if self.requestText is not None else None}"
		super().__init__(self.err)

async def unfollowUser(user, cookie, csrfToken):
	while True:
		async with httpx.AsyncClient() as client:
			request = await client.post(f"https://friends.roblox.com/v1/users/{user}/unfollow", headers={"Cookie": cookie, "X-CSRF-TOKEN": csrfToken, "Content-Length": "0"})
		if request.status_code == 200:
			print(f"Successfully unfollowed {user}")
			return
		elif request.status_code == 429:
			continue

async def unfollowProvider(queue, ID):
	followed, cursor = await getFollowers(ID)
	for i in followed:
		await queue.put(i)
	while cursor != None:
		followed, cursor = await getFollowers(ID, cursor=cursor)
		for i in followed:
			await queue.put(i)
	
	for i in range(0, 5):
		await queue.put(None)
	return
	
async def unfollowConsumer(queue, user):
	target = await queue.get()
	while target != None:
		await unfollowUser(target, user.cookie, user.csrf)
		queue.task_done()
		target = await queue.get()
	return
	
async def unfollowAll(user, loop):
	await user.getUserID()
	toUnfollow = asyncio.Queue(maxsize=300)
	tasks = []
	tasks.append(loop.create_task(unfollowProvider(toUnfollow, user.ID)))
	for i in range(0, 5):
		tasks.append(loop.create_task(unfollowConsumer(toUnfollow, user)))
	await asyncio.gather(*tasks)
	input("Successfully unfollowed all users. Press Enter to return to the menu.")

class User():
	
	def __init__(self, cookie):
		self.cookie = cookie
	
	async def updateCSRF(self):
		while True:
			try:
				async with httpx.AsyncClient() as client:
					request = await client.post("https://auth.roblox.com/v1/logout", headers={"Cookie": self.cookie})
			except Exception as error:
				raise(error)
			
			try:
				self.csrf = request.headers["x-csrf-token"]
				return
			except Exception:
				try:
					if request.status_code == 429:
						continue
					if request.status_code == 401:
						raise InvalidCookie(self.cookie)
					if request.status_code == 405:
						raise InvalidCookie(self.cookie)
					raise UnknownResponse(request.status_code, "https://auth.roblox.com/v1/logout", requestText = request.text)
				except Exception as error:
					raise(error)
					
	async def getUserID(self):
		while True:
			async with httpx.AsyncClient() as client:
				request = await client.post("https://www.roblox.com/game/GetCurrentUser.ashx", headers={"Cookie": self.cookie})
			if request.status_code == 200:
				self.ID = int(request.text)
				return
			elif request.status_code == 429:
				continue
			else:
				raise UnknownResponse(request.status_code, "https://www.roblox.com/game/GetCurrentUser.ashx", requestText = request.text)


async def getFollowingCount(ID):
	while True:
		try:
			async with httpx.AsyncClient() as client:
				request = await client.get(f"https://friends.roblox.com/v1/users/{ID}/followings/count")
		except Exception as error:
			raise(error)
		
		try:
			return request.json()["count"]
		except Exception as error:
			raise UnknownResponse(request.status_code, f"https://friends.roblox.com/v1/users/{ID}/followings/count", requestText = request.text)

async def checkFollowingCount(user):
	print("Working...")
	await getUserID(user.cookie)
	following = await getFollowingCount(user.ID)
	clear()
	print(f"You are currently following {following} users!")
	input("Press Enter to return to the menu.")


def getRanks():
	for groupID in groups.keys():
		ranks = []
		while True:
			try:
				request = httpx.get(f"https://groups.roblox.com/v1/groups/{groupID}/roles")
				break
			except:
				print("Hit rate-limit while grabbing ranks. Waiting 15 seconds.")
				time.sleep(15)
		requestJSON = request.json()
		for rank in requestJSON["roles"]:
			ranks.append(rank["id"])
		groups[groupID] = ranks
	
class groupManager():

	def __init__(self, groups):
		self.initGroups = groups
		self.groups = groups
	
	def resetData(self): #Easier to do this than to wipe all the ranks one by one.
		self.groups = self.initGroups
	
	async def updateGroups(self):
		await self.checkGroupValidity()
		await self.updateRanks()
	
	async def checkGroupValidity():
		for groupID in self.groups.keys().copy:
			while True:
				async with httpx.AsyncClient() as client:
					request = await client.get(f"https://groups.roblox.com/v1/groups/{groupID}")
				if request.status_code == 200:
					break
				elif request.status_code == 429:
					continue
				elif request.status_code == 400:
					self.groups.pop(groupID)
					break
				raise UnknownResponse(request.status_code, f"https://groups.roblox.com/v1/groups/{groupID}", request.text)
				
	async def updateRanks():
		for groupID in self.groups.keys():
			while True:
				async with httpx.AsyncClient() as client:
					request = await client.get(f"https://groups.roblox.com/v1/groups/{groupID}/roles")
				if request.status_code == 200:
					for rank in request.json()["roles"]:
						self.groups[groupID].append(rank["id"])
					break
				elif request.status_code == 429:
					continue
				raise UnknownResponse(request.status_code, f"https://groups.roblox.com/v1/groups/{groupID}/roles", request.text)


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
	#await checkWhitelist()
	logging.info("Successfully Complete Init Whitelist Check.")
	print("Whitelist Validated.")
	
	print("Checking Cookie.")
	logging.info("Init Checking Cookie.")
	user = User(apiCookie)
	await user.updateCSRF()
	logging.info("Cookie is valid.")
	print("Cookie is Valid!")
	
	while True:
		choice = menuOption(["Follow players of all ranks.", "Select which ranks to follow.", "Check how many users you are following.", "Unfollow all users.", "Exit."], "Please select what you would like to do. \n")
		#Dev notes: Look into using asyncio loop.run_in_executor to create an asynchronous input()
		if choice == 1: #Follow players of all ranks.
			pass
		elif choice == 2: #Select which ranks to follow.
			pass
		elif choice == 3: #Check following count.
			await checkFollowingCount(user)
		elif choice == 4: #Unfollow all.
			choice = menuOption(["Yes.", "No."], "Are you sure you want to unfollow everyone? This is non-reversible!")
			if choice == 1:
				await unfollowAll(user, loop)
		elif choice == 5: #Exit.
			sys.exit()
	
	


if __name__ == "__main__":
	try:
		asyncio.run(main())
	except Exception as error:
		logging.critical(f"An unknown critical error occurred: {traceback.format_exc()}")
		print(f"An unknown critical error occurred: {traceback.format_exc()}")
	input("All operations have been completed. Press Enter to exit.")
	sys.exit()	