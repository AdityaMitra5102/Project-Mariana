import winreg
import ctypes
import pystray
from PIL import Image, ImageDraw
import threading
import signal
import sys
import os
import logging
from proxyserver import *

# Flag for controlling shutdown
exit_requested = False

def _refresh_proxy():
	INTERNET_OPTION_SETTINGS_CHANGED = 39
	INTERNET_OPTION_REFRESH = 37
	InternetSetOption = ctypes.windll.Wininet.InternetSetOptionW
	InternetSetOption(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
	InternetSetOption(0, INTERNET_OPTION_REFRESH, 0, 0)

def start_proxy():
	try:
		key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_SET_VALUE)
		winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
		winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "http=localhost:8000;https=localhost:8000")
		winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "<local>")
		winreg.CloseKey(key)
		_refresh_proxy()
		logging.info("[+] Proxy enabled.")
		start_proxythread()
	except Exception as e:
		logging.info(f"[!] Could not enable proxy: {e}")

def disable_proxy():
	try:
		key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_SET_VALUE)
		winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
		winreg.CloseKey(key)
		_refresh_proxy()
		print("[+] Proxy disabled.")
	except Exception as e:
		print(f"[!] Could not disable proxy: {e}")

def create_image():
	image = Image.open('icon.png')
	#draw = ImageDraw.Draw(image)
	#draw.ellipse((16, 16, 48, 48), fill=(255, 255, 255))
	return image

def on_exit(icon, item=None):
	global exit_requested
	print("[*] Exiting via tray or signal...")
	exit_requested = True
	disable_proxy()
	icon.stop()
	try:
		os.system('taskkill /F /IM firefox.exe')
	except:
		pass
	os._exit(0)

def open_browser():
	os.system('"C:/Program Files/Mozilla Firefox/firefox.exe" http://local.mariana')

def handle_signal(sig, frame):
	print(f"[!] Caught signal: {sig}")
	on_exit(tray_icon)


def main():
	global tray_icon
	start_proxy()
	open_browser()
	signal.signal(signal.SIGINT, handle_signal)   # Ctrl+C
	signal.signal(signal.SIGTERM, handle_signal)  # taskkill / PID

	tray_icon = pystray.Icon("MarianaTray")
	tray_icon.icon = create_image()
	tray_icon.title = "Mariana Running"
	tray_icon.menu = pystray.Menu(
		pystray.MenuItem("Browse", open_browser, default=True),
		pystray.MenuItem("Exit", on_exit)
	)

	tray_icon.run()

if __name__ == "__main__":
	main()
