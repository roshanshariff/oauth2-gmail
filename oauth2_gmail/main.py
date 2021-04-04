from pathlib import Path
from datetime import datetime, timezone, timedelta
import dateutil.parser
import json
from typing import Optional, cast

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

import keyring

import typer
app = typer.Typer()


def save_credentials(name: str, credentials: Credentials) -> None:
    keyring.set_password("oauth2-gmail", name, credentials.to_json())


def load_credentials(name: str) -> dict[str, str]:
    credentials_json = keyring.get_password("oauth2-gmail", name)
    if not credentials_json:
        return dict()
    credentials_dict = json.loads(credentials_json)
    assert isinstance(credentials_dict, dict)
    return credentials_dict

def get_token(name: str, force_refresh: bool) -> Optional[str]:

    credentials_dict = load_credentials(name)
    if not {'client_id', 'client_secret', 'refresh_token'}.issubset(credentials_dict):
        return None

    token = credentials_dict.get('token')

    if force_refresh:
        token = None

    if token and 'expiry' in credentials_dict:
        expiry = dateutil.parser.isoparse(credentials_dict['expiry'])
        if datetime.now(timezone.utc) > expiry - timedelta(minutes=5):
            token = None

    if not token:
        credentials = Credentials.from_authorized_user_info(credentials_dict)
        credentials.refresh(Request())
        save_credentials(name, credentials)
        token = credentials.token

    return token

@app.command()
def authorize(
        name: str = typer.Option("default", help="Name for this credential."),
        client_secrets: Path = typer.Argument(..., help="Path to client secrets JSON file.",
                                              exists=True, readable=True, dir_okay=False),
        headless: bool = typer.Option(False, help="Run a console-based flow.")
) -> None:

    flow = InstalledAppFlow.from_client_secrets_file(client_secrets,
                                                     scopes=['https://mail.google.com/'])

    credentials = flow.run_console() if headless else flow.run_local_server()
    save_credentials(name, credentials)


@app.command()
def get(
        name: str = typer.Argument("default", help="Name for this credential."),
        force_refresh: bool = typer.Option(False, help="Force-refresh token.")
) -> None:
    token = get_token(name, force_refresh)
    if not token:
        raise typer.Exit(code=1)
    print(token)


@app.command()
def check(
        name: str = typer.Argument("default", help="Name for this credential."),
        force_refresh: bool = typer.Option(False, help="Force-refresh token.")
) -> None:
    token = get_token(name, force_refresh)
    if not token:
        raise typer.Exit(code=1)
