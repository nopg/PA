# import api_lib_pa as pa
import asyncio
from typing import Optional

import typer

app = typer.Typer(
    name="deduper",
    add_completion=False,
    help="PA address-object/group/services deduper",
)


@app.command("xml", help="Gather objects/services via XML")
def xml(filename: Optional[str] = typer.Option(default=None, prompt="XML FIlename: ")):
    print("XML Time!")
    print(filename)


@app.command("panorama", help="Gather objects/services via Panorama")
def panorama(
    panorama: Optional[str] = typer.Option(None, "--panorama", "-i", prompt="Panorama IP/FQDN: ", help="Panorama IP/FQDN", metavar="x.x.x.x"),
    username: Optional[str] = typer.Option(None, "--username", "-u", prompt="Panorama Username: "),
    password: Optional[str] = typer.Option(None, "--password", "-p", prompt="Panorama Password: "),
    future: Optional[str] = typer.Option(None)
):

    print("Not yet implemented.")
    print(panorama,username,password,future)

if __name__ == "__main__":
    app()
