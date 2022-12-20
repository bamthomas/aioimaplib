import asyncio
import logging
import socket
import webbrowser
from pathlib import Path
from pprint import pprint
from urllib.parse import parse_qs
import json

from httpx_oauth.oauth2 import OAuth2, OAuth2Token

from aioimaplib import IMAP4_SSL

CALLBACK_HTTP_PORT = 12345

# for office365
client = OAuth2(
    "<your-client-id>",
    "<your-client-secret>",
    "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize",
    "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
)

SCOPES = [
    "offline_access",
    "https://outlook.office.com/IMAP.AccessAsUser.All",
]

# for google
# this is not tested yet.
# from httpx_oauth.clients.google import GoogleOAuth2

# client = GoogleOAuth2(
#     "0f2c93d4-6a81-4597-8bf3-0002869d82fb",
#     "rxN8Q~FABEmDxwiS7TtflBUPf~FkGR2raAtHlaQ6",
# )
# SCOPES = ["https://mail.google.com/"]


logging.basicConfig(level=logging.DEBUG)

token_path = Path(__file__).parent / ".oauth_token.json"


async def main():

    token = await get_token()

    client = IMAP4_SSL("outlook.office365.com")

    await client.wait_hello_from_server()
    result = await client.xoauth2("<your-username>", token)
    pprint(result.lines)

    await client.select()
    result = await client.uid_search("1:*", charset="us-ascii")

    pprint(result.lines)

    await client.close()


# These are functions to aquire a token and persist it/refresh it
# if you have issues you can delete the token .oauth_token.json to re-aquire it


async def get_token():
    if not token_path.is_file():
        token = await authorization()
    else:
        with token_path.open() as f_in:
            token_dict = json.load(f_in)
        token = OAuth2Token(token_dict)

    if token.is_expired():
        token = client.refresh_token(token["refresh_token"])

    # write token to file
    with token_path.open("w") as f_out:
        json.dump(token, f_out, indent=4)

    return token["access_token"]


async def start_server_and_open_browser(url):

    response_queue = asyncio.Queue(1)

    # start callback webserver
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", CALLBACK_HTTP_PORT))
    server.listen()
    # this is set so we can restart the server quickly without getting
    # OSError: [Errno 48] Address already in use errors
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setblocking(False)

    server_task = asyncio.create_task(run_http_server(server, response_queue))

    webbrowser.open(url)

    val = await response_queue.get()
    server.close()
    server_task.cancel()

    return val


async def authorization():
    """Authorizes"""

    callback_url = f"http://localhost:{CALLBACK_HTTP_PORT}/"

    url = await client.get_authorization_url(callback_url, scope=SCOPES)
    token_respose = await start_server_and_open_browser(url)
    access_token = await client.get_access_token(token_respose["code"][0], callback_url)

    return access_token


# this is a really small webserver to be able to receive the callback from oauth
# heavlily inspired by https://github.com/jangia/http_server/blob/master/server.py

CHUNK_LIMIT = 50
DEFAULT_RESPONSE = "HTTP/1.1 {status} {status_msg}\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Encoding: UTF-8\r\nAccept-Ranges: bytes\r\nConnection: closed\r\n\r\n{html}"


def parse_request(request_str):
    part_one, part_two = request_str.split("\r\n\r\n")
    http_lines = part_one.split("\r\n")
    method, url, _ = http_lines[0].split(" ")
    if method != "GET":
        status, status_msg = 405, "Not allowed"
    else:
        status, status_msg = 200, "OK"

    return status, status_msg, url


async def build_response(request, response_queue):
    status, status_msg, url = parse_request(request)
    html = ""
    # if there is code in the response it is the one we want
    if "code" in url:
        query = parse_qs(url.split("?", 1)[1])
        await response_queue.put(query)
        html = "Thank you, auth is handed back to the cli."
    else:
        status = 404
        status_msg = "Not Found"
    response = DEFAULT_RESPONSE.format(
        status=status, status_msg=status_msg, html=html
    ).encode("utf-8")

    return response


async def read_request(client):
    request = ""
    while True:
        chunk = (await asyncio.get_event_loop().sock_recv(client, CHUNK_LIMIT)).decode(
            "utf8"
        )
        request += chunk
        if len(chunk) < CHUNK_LIMIT:
            break

    return request


async def handle_client(client, response_queue):
    request = await read_request(client)
    response = await build_response(request, response_queue)
    await asyncio.get_event_loop().sock_sendall(client, response)
    client.close()


async def run_http_server(selected_server, response_queue):
    while True:
        client, _ = await asyncio.get_event_loop().sock_accept(selected_server)
        asyncio.create_task(handle_client(client, response_queue))


if __name__ == "__main__":
    asyncio.run(main())
