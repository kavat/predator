import httpx
import asyncio
import logging
import config

class PredatorAsyncHttpClient:
  def __init__(self, base_url=None, headers=None, timeout=60):
    self.base_url = base_url
    self.headers = headers or {}
    self.timeout = timeout
    self.client = httpx.AsyncClient(http2=True, timeout=timeout, headers=self.headers, verify=False, cookies=httpx.Cookies())

  async def request(self, method, url, params=None, json=None, data=None, headers=None):
    full_url = f"{self.base_url}{url}" if self.base_url else url
    headers = {**self.headers, **(headers or {})}  # Merge degli headers

    if data != None:
      headers['Content-Length'] = str(len(data))

    #logging.basicConfig(level=logging.DEBUG)
    try:
      response = await self.client.request(
        method, full_url, params=params, json=json, data=data, headers=headers
      )
      response.raise_for_status()  # Solleva un'eccezione per errori HTTP
      return response
    except httpx.HTTPStatusError as e:
      if e.response.status_code == 404:
        config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_REVERSE_PROXY"].get_logger().info(f"{url}: Errore HTTP {e.response.status_code}")
      else:
        config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_REVERSE_PROXY"].get_logger().info(f"{url}: Errore HTTP {e.response.status_code}: {e.response.text}")
      return response
    except httpx.RequestError as e:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_REVERSE_PROXY"].get_logger().error(f"{url} Errore di richiesta: {e}")
    return None

  async def get(self, url, params=None, headers=None):
    return await self.request("GET", url, params=params, headers=headers)

  async def post(self, url, json=None, data=None, headers=None):
    return await self.request("POST", url, json=json, data=data, headers=headers)

  async def patch(self, url, json=None, data=None, headers=None):
    return await self.request("PATCH", url, json=json, data=data, headers=headers)

  async def delete(self, url, headers=None):
    return await self.request("DELETE", url, headers=headers)

  async def options(self, url, headers=None):
    return await self.request("OPTIONS", url, headers=headers)

  async def close(self):
    await self.client.aclose()
