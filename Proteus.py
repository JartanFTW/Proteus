import asyncio
import aiosonic
from configparser import ConfigParser
import os
from os import system
import sys
import time
import psycopg2
import logging
import traceback

version = "3.0"

#Setting up logging
if not os.path.exists(os.path.join(bot.mainPath, "logs")):
	os.makedirs(os.path.join(bot.mainPath, "logs"))
logName = os.path.join(os.path.join(bot.mainPath, "logs"), time.strftime('%m %d %Y %H %M %S', time.localtime()))
logging.basicConfig(filename=f"{logName}.log", level=logging.ERROR, format="%(asctime)s:%(levelname)s:%(message)s")


mainPath = os.path.dirname(os.path.abspath(__file__))

clear = lambda: os.system("cls")


def menuOption(options, initMessage = None):
	while True:
		iter = 0
		if initMessage:
			print(initMessage)
		for option in options:
			iter += 1
			print(f"[{iter}] {options[iter-1]}
			
		try:
			option = int(input("Please select an option: "))
			if abs(option) - 1 > len(options):
				raise IndexError
			cls()
			return abs(option) - 1
		except:
			input("That is not a valid option! Press Enter to retry.")
			cls()
			continue

def loadConfig():
	parser = ConfigParser()
	
	while True:
		try:
			parser.read(os.path.join(mainPath, "config.ini"))
			assert config["WHITELIST"]["username"] is not None, "Whitelist Username cannot be blank."
			assert config["WHITELIST"]["password"] is not None, "Whitelist Password cannot be blank."
			assert config["USER"]["cookie"].split("_")[-1] is not None, "Cookie has wrong formatting or is blank."
			apiCookie = f".ROBLOSECURITY=_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_{config['USER']['cookie'].split('_')[-1]};"
			assert config["SETTINGS"]["groups"] is not None, "Groups cannot be blank."
			assert config["SETTINGS"]["onlyPremium"].upper() in ["TRUE", "FALSE"], "OnlyPremium must be set to True or False."
			
			if config["OTHER"]["debug"].upper() == "True":
				logging.getLogger("root").setLevel(logging.info)
				logging.info("Debug mode enabled. Set logging level to info.")
			
			return config["WHITELIST"]["username"], config["WHITELIST"]["password"], apiCookie, [x.strip() for x in config["SETTINGS"]["groups"].split(",")], config["SETTINGS"]["onlyPremium"].upper(), config["OTHER"]["blacklist"]
			
		except Exception as error:
			logging.warning(f"Failed to load config: {error}")
			print(error)
			input("Press Enter to try again.")

async def titleManager(thing, thing2):
	while True:
		await asyncio.sleep(1)
		system("title " + f"Proteus v{version} | Jartan#7450 | My title here.")


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
	loop.run_until_complete(checkWhitelist())
	print("Whitelist Validated.")
	
	while True:
	choice = menuOption(["Follow players of all ranks.", "Select which ranks to follow.", "Check how many users you are following.", "Unfollow all users.", "Exit."], "Please select what you would like to do. \n")
	
	
	
	


if __name__ == "__main__":
	try:
		asyncio.run(main())
	except Exception as error:
		logging.critical(f"An unknown critical error occurred: {traceback.format_exc()}")
		print(f"An unknown critical error occurred: {traceback.format_exc()}")
	input("All operations have been completed. Press Enter to exit.")
	sys.exit()	