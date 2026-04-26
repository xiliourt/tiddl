import typer
from datetime import datetime
from time import time, sleep
from rich.console import Console

from tiddl.cli.utils.auth.core import load_auth_data, save_auth_data, AuthData
from tiddl.core.auth import AuthAPI, AuthClientError

from typing_extensions import Annotated

console = Console()

auth_command = typer.Typer(
    name="auth", help="Manage Tidal authentication.", no_args_is_help=True
)


# TODO add context and load auth data from ctx
@auth_command.command(help="Login with your Tidal account.")
def login(
    NO_BROWSER: Annotated[
        bool,
        typer.Option(
            "--no-browser", "-n", help="Do not open browser."
        ),
    ] = False,
):
    loaded_auth_data = load_auth_data()

    if loaded_auth_data.token and loaded_auth_data.secondary_token:
        console.print("[cyan bold]Already logged in to both accounts.")
        raise typer.Exit()

    def do_login(secondary: bool = False):
        name = "secondary" if secondary else "primary"
        auth_api = AuthAPI(secondary=secondary)
        device_auth = auth_api.get_device_auth()

        uri = f"https://{device_auth.verificationUriComplete}"

        console.print(f"\n[bold cyan]Logging in to {name} account...")
        if not NO_BROWSER:
            typer.launch(uri)
        
        console.print(f"Go to '{uri}' and complete authentication!")

        auth_end_at = time() + device_auth.expiresIn
        status_text = f"Authenticating {name}..."

        with console.status(status_text) as status:
            while True:
                sleep(device_auth.interval)

                try:
                    auth = auth_api.get_auth(device_auth.deviceCode)
                    
                    if secondary:
                        loaded_auth_data.secondary_token = auth.access_token
                        loaded_auth_data.secondary_refresh_token = auth.refresh_token
                        loaded_auth_data.secondary_expires_at = auth.expires_in + int(time())
                        loaded_auth_data.secondary_user_id = str(auth.user_id)
                        loaded_auth_data.secondary_country_code = auth.user.countryCode
                    else:
                        loaded_auth_data.token = auth.access_token
                        loaded_auth_data.refresh_token = auth.refresh_token
                        loaded_auth_data.expires_at = auth.expires_in + int(time())
                        loaded_auth_data.user_id = str(auth.user_id)
                        loaded_auth_data.country_code = auth.user.countryCode
                    
                    save_auth_data(loaded_auth_data)
                    status.console.print(f"[bold green]Logged in with {name} auth!")
                    break

                except AuthClientError as e:
                    if e.error == "authorization_pending":
                        time_left = auth_end_at - time()
                        minutes, seconds = time_left // 60, int(time_left % 60)
                        status.update(
                            f"{status_text} time left: {minutes:.0f}:{seconds:02d}"
                        )
                        continue

                    if e.error == "expired_token":
                        status.console.print(
                            f"\n[bold red]Time for {name} authentication has expired."
                        )
                        break

    if not loaded_auth_data.token:
        do_login(secondary=False)
    
    if not loaded_auth_data.secondary_token:
        do_login(secondary=True)


@auth_command.command(help="Logout and remove token from app.")
def logout():
    loaded_auth_data = load_auth_data()

    if loaded_auth_data.token:
        auth_api = AuthAPI()
        auth_api.logout_token(loaded_auth_data.token)

    if loaded_auth_data.secondary_token:
        auth_api_sec = AuthAPI(secondary=True)
        auth_api_sec.logout_token(loaded_auth_data.secondary_token)

    save_auth_data(AuthData())

    console.print("[bold green]Logged out!")


@auth_command.command(help="Refreshes your token in app.")
def refresh(
    FORCE: Annotated[
        bool,
        typer.Option(
            "--force", "-f", help="Refresh token even when it is still valid."
        ),
    ] = False,
    EARLY_EXPIRE_TIME: Annotated[
        int,
        typer.Option(
            "--early-expire",
            "-e",
            help="Time to expire the token earlier",
            metavar="seconds",
        ),
    ] = 0,
):
    loaded_auth_data = load_auth_data()

    if loaded_auth_data.refresh_token is None and loaded_auth_data.secondary_refresh_token is None:
        console.print("[bold red]Not logged in.")
        raise typer.Exit()

    # Refresh primary
    if loaded_auth_data.refresh_token:
        if time() < (loaded_auth_data.expires_at - EARLY_EXPIRE_TIME) and not FORCE:
            expiry_time = datetime.fromtimestamp(loaded_auth_data.expires_at)
            remaining = expiry_time - datetime.now()
            hours, remainder = divmod(remaining.seconds, 3600)
            minutes, _ = divmod(remainder, 60)
            console.print(
                f"[green]Primary auth token expires in {remaining.days}d {hours}h {minutes}m"
            )
        else:
            auth_api = AuthAPI()
            auth_data = auth_api.refresh_token(loaded_auth_data.refresh_token)
            loaded_auth_data.token = auth_data.access_token
            loaded_auth_data.expires_at = auth_data.expires_in + int(time())
            console.print("[bold green]Primary auth token has been refreshed!")

    # Refresh secondary
    if loaded_auth_data.secondary_refresh_token:
        if time() < (loaded_auth_data.secondary_expires_at - EARLY_EXPIRE_TIME) and not FORCE:
            expiry_time = datetime.fromtimestamp(loaded_auth_data.secondary_expires_at)
            remaining = expiry_time - datetime.now()
            hours, remainder = divmod(remaining.seconds, 3600)
            minutes, _ = divmod(remainder, 60)
            console.print(
                f"[green]Secondary auth token expires in {remaining.days}d {hours}h {minutes}m"
            )
        else:
            auth_api_sec = AuthAPI(secondary=True)
            auth_data_sec = auth_api_sec.refresh_token(loaded_auth_data.secondary_refresh_token)
            loaded_auth_data.secondary_token = auth_data_sec.access_token
            loaded_auth_data.secondary_expires_at = auth_data_sec.expires_in + int(time())
            console.print("[bold green]Secondary auth token has been refreshed!")

    save_auth_data(loaded_auth_data)
