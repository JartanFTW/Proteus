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
			
			if parser["OTHER"]["debug"].upper() == "TRUE":
				logging.getLogger("root").setLevel(10)
				logging.info("Debug mode enabled. Set logging level to info.")
			
			return parser["WHITELIST"]["username"], parser["WHITELIST"]["password"], apiCookie, {int(x.strip()) : [] for x in parser["SETTINGS"]["groups"].split(",")}, parser["SETTINGS"]["onlyPremium"].upper(), [int(x.strip()) for x in parser["OTHER"]["blacklist"].split(",")]
			
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

async def unfollowProvider(queue, user):
	followed, cursor = await user.getFollowing()
	for i in followed:
		await queue.put(i)
	while cursor != None:
		followed, cursor = await user.getFollowing(cursor=cursor)
		for i in followed:
			await queue.put(i)
	
	for i in range(0, 5):
		await queue.put(None)
	return
	
async def unfollowConsumer(queue, user):
	target = await queue.get()
	while target != None:
		await user.unfollowUser(target)
		print(f"Successfully unfollowed {target}")
		queue.task_done()
		target = await queue.get()
	return
	
async def unfollowAll(user, loop):
	toUnfollow = asyncio.Queue(maxsize=300)
	tasks = []
	tasks.append(loop.create_task(unfollowProvider(toUnfollow, user)))
	for i in range(0, 5):
		tasks.append(loop.create_task(unfollowConsumer(toUnfollow, user)))
	await asyncio.gather(*tasks)
	input("Successfully unfollowed all users. Press Enter to return to the menu.")

class User():
	
	def __init__(self, cookie):
		self.cookie = cookie
		self.csrf = None
		self.ID = None
		self.followingCount = None
		self.following = []
	
	async def updateCSRF(self):
		while True:
			try:
				async with httpx.AsyncClient() as client:
					request = await client.post("https://auth.roblox.com/v1/logout", headers={"Cookie": self.cookie})
			except Exception as error:
				raise(error)
			
			try:
				self.csrf = request.headers["x-csrf-token"]
				return self.csrf
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
		if self.ID != None:
			return self.ID
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
	
	async def getFollowingCount(self):
		if self.ID == None:
			await self.getUserID()
		while True:
			try:
				async with httpx.AsyncClient() as client:
					request = await client.get(f"https://friends.roblox.com/v1/users/{self.ID}/followings/count")
			except Exception as error:
				raise(error)
			if request.status_code == 200:
				self.followingCount = request.json()["count"]
				return self.followingCount
			elif request.status_code == 429:
				continue
			raise UnknownResponse(request.status_code, f"https://friends.roblox.com/v1/users/{self.ID}/followings/count", requestText = request.text)
	
	async def getAllFollowing(self):
		following, cursor = await self.getFollowing()
		for player in following:
			if player not in self.following:
				self.following.append(player)
		while cursor != None:
			following, cursor = await self.getFollowing(cursor=cursor)
			for player in following:
				if player not in self.following:
					self.following.append(player)
	
	async def getFollowing(self, cursor=None):
		if self.ID == None:
			await self.getUserID()
		while True:
			followedUsers = []
			async with httpx.AsyncClient() as client:
				request = await client.get(f"https://friends.roblox.com/v1/users/{self.ID}/followings", params={"sortOrder": "Asc", "limit": 100, "cursor": cursor})
			if request.status_code == 200:
				for player in request.json()["data"]:
					followedUsers.append(player["id"])
					if player not in self.following:
						self.following.append(player)
				return followedUsers, request.json()["nextPageCursor"]
			elif request.status_code == 429:
				continue
			raise UnknownResponse(request.status_code, f"https://friends.roblox.com/v1/users/{self.ID}/followings", requestText = request.text)
	
	async def unfollowUser(self, target):
		if self.csrf == None:
			await self.updateCSRF()
		while True:
			async with httpx.AsyncClient() as client:
				request = await client.post(f"https://friends.roblox.com/v1/users/{target}/unfollow", headers={"Cookie": self.cookie, "X-CSRF-TOKEN": self.csrf, "Content-Length": "0"})
			if request.status_code == 200:
				if target in self.following:
					self.following.remove(target)
				return
			elif request.status_code == 429:
				continue
			raise UnknownResponse(request.status_code, f"https://friends.roblox.com/v1/users/{target}/unfollow", request.text)
	
	async def followUser(self, target):
		if self.csrf == None:
			await self.updateCSRF()
		while True:
			async with httpx.AsyncClient() as client:
				request = await client.post(f"https://friends.roblox.com/v1/users/{target}/follow", headers={"Cookie": self.cookie, "X-CSRF-TOKEN": self.csrf, "Content-Length": "0"})
			if request.status_code == 200:
				self.following.append(target)
				return True
			elif request.status_code == 429:
				print("Hit follow rate-limit. Waiting 55 seconds.")
				await asyncio.sleep(55)
				continue
			elif request.status_code == 401:
				print("Updating token!")
				self.updateCSRF()
				continue
			elif request.status_code in [403, 400]:
				reqJSON = request.json()
				if reqJSON["errors"][0]["code"] == 0:
					self.updateCSRF()
					continue
				else:
					logging.warning(f"Unknown error code on followUser request: {reqJSON['errors'][0]['code']}")
					print(f"Unknown error code on followUser request: {reqJSON['errors'][0]['code']}")
					return
			elif request.status_code == 500:
				print("You just tried to follow yourself silly!")
				return False
			raise UnknownResponse(request.status_code, f"https://friends.roblox.com/v1/users/{target}/follow", request.text)

async def checkFollowingCount(user):
	print("Working...")
	following = await user.getFollowingCount()
	clear()
	print(f"You are currently following {following} users!")
	input("Press Enter to return to the menu.")
	
class groupManager():

	def __init__(self, groups):
		self.initGroups = groups
		self.groups = groups
	
	def resetData(self): #Easier to do this than to wipe all the ranks one by one.
		self.groups = self.initGroups
	
	async def updateGroups(self):
		await self.checkGroupsValidity()
		await self.updateRanks()
	
	async def checkGroupsValidity(self):
		for groupID in self.groups.copy().keys():
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
				
	async def updateRanks(self):
		for groupID in self.groups.keys():
			while True:
				async with httpx.AsyncClient() as client:
					request = await client.get(f"https://groups.roblox.com/v1/groups/{groupID}/roles")
				if request.status_code == 200:
					for rank in request.json()["roles"]:
						self.groups[groupID].append(rank)
					break
				elif request.status_code == 429:
					continue
				raise UnknownResponse(request.status_code, f"https://groups.roblox.com/v1/groups/{groupID}/roles", request.text)
				
				
	def rankSelection(self):
		for groupID in self.groups.keys():
			clear()
			print(f"{groupID}: Which ranks would you like to follow? Reply should be number of the rank separated by a space.")
			print("Ex: 4 6 12 2 5")
			for index, rank in enumerate(self.groups[groupID]):
				print(f"{index+1} | {rank['name']} | Members: {rank['memberCount']}")
			choice = input("Which ranks would you like to follow? ")
			choice = choice.split(" ")
			for i in choice.copy():
				try:
					abs(int(i))
				except ValueError:
					choice.remove(i)
			new = []
			for index in sorted(choice, key=int):
				try:
					if self.groups[groupID][int(index)-1] not in new:
						new.append(self.groups[groupID][int(index)-1])
				except IndexError:
					pass
					
			self.groups[groupID] = new
			
	async def getRankUsers(self, groupID, rankID, cursor=None):
		while True:
			users = []
			async with httpx.AsyncClient() as client:
				request = await client.get(f"https://groups.roblox.com/v1/groups/{groupID}/roles/{rankID}/users", params={"sortOrder": "Asc", "limit": 100, "cursor": cursor})
			if request.status_code == 200:
				for player in request.json()["data"]:
					users.append(player["userId"])
				return users, request.json()["nextPageCursor"]
			elif request.status_code == 429:
				continue
			raise UnknownResponse(request.status_code, f"https://groups.roblox.com/v1/groups/{groupID}/roles/{rankID}/users", requestText = request.text)


async def followProvider(user, groupObj, queue, onlyPremium, blacklist, thread):
	for groupID, data in groupObj.groups.items():
		for index, rank in enumerate(data):
			try:
				groupObj.groups[groupID][index]["cursor"]
			except:
				groupObj.groups[groupID][index]["cursor"] = None
			toFollow, groupObj.groups[groupID][index]["cursor"] = await groupObj.getRankUsers(groupID, rank["id"], cursor=groupObj.groups[groupID][index]["cursor"])
			while True:
				for target in toFollow:
					check = await checkTarget(user, target, onlyPremium, blacklist)
					if check == True:
						await queue.put(target)
					else:
						print(f"{thread} Skipping {target} because {check}")
				if groupObj.groups[groupID][index]["cursor"] == None:
					break
				toFollow, groupObj.groups[groupID][index]["cursor"] = await groupObj.getRankUsers(groupID, rank["id"], cursor=groupObj.groups[groupID][index]["cursor"])
	await queue.put(None)
	return
			

# async def followProvider(user, groupObj, queue, onlyPremium, blacklist):
	# for groupID, data in groupObj.groups.items():
		# for index, rank in enumerate(data):
			# print(groupObj.groups[groupID][index])
			# toFollow, groupObj.groups[groupID][index]["cursor"] = await groupObj.getRankUsers(groupID, rank["id"])
			# for target in toFollow:
				# check = await checkTarget(user, target, onlyPremium, blacklist)
				# if check == True:
					# await queue.put(target)
				# else:
					# print(f"Skipping {target} because {check}")
			# while groupObj.groups[groupID][index]["cursor"] != None:
				# toFollow, groupObj.groups[groupID][index]["cursor"] = await getRankUsers(groupID, rank["id"], cursor=groupObj.groups[groupID][index]["cursor"])
				# for target in toFollow:
					# check = await checkTarget(user, target, onlyPremium, blacklist)
					# if check == True:
						# await queue.put(target)
					# else:
						# print(f"Skipping {target} because {check}")
	# await queue.put(None)
	# return

async def followConsumer(user, queue):
	target = await queue.get()
	while target != None:
		followed = await user.followUser(target)
		if followed == True:
			print(f"Successfully followed {target}.")
		else:
			print("Failed to follow {target}.")
		target = await queue.get()

async def checkTarget(user, target, onlyPremium, blacklist):
	if target in user.following:
		return "already following user."
	elif target in blacklist:
		return "user is in blacklist."
	terminated = await checkTerminated(user, target)
	if terminated != True:
		return terminated
	elif onlyPremium == "TRUE":
		return await checkPremium(user, target)
	return True

async def checkTerminated(user, target):
	while True:
		try:
			async with httpx.AsyncClient() as client:
				request = await client.get(f"https://www.roblox.com/users/{target}/profile", headers={"Cookie": user.cookie, "X-CSRF-TOKEN": user.csrf})
		except httpx.ReadTimeout:
			continue
		if request.status_code == 200:
			return True
		elif request.status_code == 429:
			continue
		elif request.status_code == 404:
			return "user is terminated."
		raise UnknownResponse(request.status_code, f"https://www.roblox.com/users/{target}/profile")

async def checkPremium(user, target):
	while True:
		async with httpx.AsyncClient() as client:
			request = await client.get(f"https://premiumfeatures.roblox.com/v1/users/{target}/validate-membership", headers={"Cookie": user.cookie, "X-CSRF-TOKEN": user.csrf})
		if request.status_code == 200:
			if request.text == "false":
				return "user is not premium."
			return True
		elif request.status_code == 429:
			await asyncio.sleep(10)
			continue
		raise UnknownResponse(request.status_code, f"https://premiumfeatures.roblox.com/v1/users/{target}/validate-membership", request.text)

async def followUsers(user, groupObj, onlyPremium, blacklist, loop):
	clear()
	print("Grabbing following.")
	await user.getAllFollowing()
	print("Finished grabbing following.")	
	toFollow = asyncio.Queue(maxsize=50)
	tasks = []
	for i in range(0, 5):
		print(f"Sleeping {i}")
		await asyncio.sleep(5)
		tasks.append(loop.create_task(followProvider(user, groupObj, toFollow, onlyPremium, blacklist, i)))
	tasks.append(loop.create_task(followConsumer(user, toFollow)))
	await asyncio.gather(*tasks)
	input("Finished following input groups. Press Enter to return to the menu.")

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
	
	groupObj = groupManager(groups)
		
	while True:
		groupObj.resetData()
		
		choice = menuOption(["Follow players of all ranks.", "Select which ranks to follow.", "Check how many users you are following.", "Unfollow all users.", "Exit."], "Please select what you would like to do. \n")
		#Dev notes: Look into using asyncio loop.run_in_executor to create an asynchronous input()
		if choice == 1: #Follow players of all ranks.
			await groupObj.updateGroups()
			await followUsers(user, groupObj, onlyPremium, blacklist, loop)
		elif choice == 2: #Select which ranks to follow.
			await groupObj.updateGroups()
			groupObj.rankSelection()
			await followUsers(user, groupObj, onlyPremium, blacklist, loop)
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