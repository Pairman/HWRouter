#!/usr/bin/env python

__all__ = ("HWRouter")

from hashlib import pbkdf2_hmac as _pbkdf2_hmac, sha256 as _sha256
from hmac import new as _new
from re import search as _search, DOTALL as _DOTALL
from uuid import uuid4 as _uuid4
from aiohttp import ClientSession as _ClientSession, CookieJar as _CookieJar

class HWRouter:
	"""Huawei Router Session.
	"""
	__logged_in = False
	__async_ctxmgr = __session = __secrets = None

	def __init__(
		self, password: str, username: str = None, base_url: str = None
	):
		"""Initialize a Huawei Router Session.
		:param password: Password.
		:username: Username. Defaults to "admin".
		:base_url: Base URL for management.
		"""
		if not self.__async_ctxmgr is None:
			return
		self.__password = password
		self.__session = _ClientSession(
			base_url or "http://192.168.3.1",
			cookie_jar = _CookieJar(unsafe = True)
		)
		self.__secrets = {
			"username": username or "admin", "password": password
		}

	async def __aenter__(self):
		if not self.__async_ctxmgr is None:
			return self
		self.__async_ctxmgr = True
		await self.__session.__aenter__()
		self.__logged_in = (
			await self.login_do_csrf() and
			await self.login_do_nonce() and
			await self.login_do_proof()
		)
		return self

	async def __aexit__(self, *args, **kwargs):
		if not self.__async_ctxmgr:
			return
		await self.__session.__aexit__(*args, **kwargs)
		self.__async_ctxmgr = False

	@property
	def logged_in(self):
		return self.__logged_in

	async def get(self, *args, **kwargs):
		"""Wrapper for  ```aiohttp.ClientSession.get()```.
		:param *args: Arguments.
		:param **kwargs: Keyword arguments.
		:return: Response.
		"""
		return await self.__session.get(*args, **kwargs)

	async def post(self, *args, **kwargs):
		"""Wrapper for  ```aiohttp.ClientSession.post()```.
		:param *args: Arguments.
		:param **kwargs: Keyword arguments.
		:return: Response.
		"""
		return await self.__session.post(*args, **kwargs)

	async def login_do_csrf(self):
		"""Prepare CSRF data for logging-in.
		"""
		res = await self.__session.get("/html/index.html")
		match = _search(
			r"csrf_param.*?(\w{32}).*?csrf_token.*?(\w{32})",
			await res.text(), _DOTALL
		)
		if res.status == 200:
			self.__secrets.update({
				"csrf_param": match[1], "csrf_token": match[2]
			})
			return True
		return False

	async def login_do_nonce(self):
		"""Prepare nonce for logging-in.
		"""
		self.__secrets["firstnonce"] = _uuid4().hex * 2
		data = {
			"csrf": {
				"csrf_param": self.__secrets["csrf_param"],
				"csrf_token": self.__secrets["csrf_token"]
			},
			"data": {
				"username": self.__secrets["username"],
				"firstnonce": self.__secrets["firstnonce"]
			}
		}
		res = await self.__session.post(
			"/api/system/user_login_nonce", json = data
		)
		if res.status == 200:
			d = await res.json()
			if not d.get("err") and not d.get("errcode"):
				self.__secrets.update(d)
				return True
		return False

	async def login_do_proof(self):
		"""Proof for logging-in.
		"""
		password = _pbkdf2_hmac(
			"sha256", self.__password.encode("utf-8"),
			bytes.fromhex(self.__secrets["salt"]),
			self.__secrets["iterations"], 32
		)
		clientkey = _new(b"Client Key", password, _sha256).digest()
		storekey = _sha256(clientkey).digest()
		authmsg = (
			f"{self.__secrets['firstnonce']},"
			f"{self.__secrets['servernonce']},"
			f"{self.__secrets['servernonce']}"
		)
		clientsig = _new(
			authmsg.encode("ascii"), storekey, _sha256
		).digest()
		clientproof = bytes(
			p ^ q for p, q in zip(clientkey, clientsig)
		).hex()
		data = {
			"csrf": {
				"csrf_param": self.__secrets["csrf_param"],
				"csrf_token": self.__secrets["csrf_token"]
			},
			"data": {
				"clientproof": clientproof,
				"finalnonce": self.__secrets["servernonce"]
			}
		}
		res = await self.__session.post(
			"/api/system/user_login_proof", json = data
		)
		if res.status == 200:
			d = await res.json()
			if not d.get("err") and not d.get("errcode"):
				return True
		return False

if __name__ == "__main__":
	from asyncio import run as _run
	from sys import argv as _argv
	async def main():
		async with HWRouter(password = _argv[1]) as rt:
			if rt.logged_in:
				res = await rt.get("/api/ntwk/wandetect")
				if res.status == 200:
					print((
						await res.json()
					)["ExternalIPAddress"])
	_run(main())