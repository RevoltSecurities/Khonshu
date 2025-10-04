from khonshu import CLI
from khonshu import Settings
from revoltlogger import Logger
from revoltutils import Banner,HealthCheck,ConnectionInfo
from gitupdater import GitUpdater
from khonshu import Pyrunner
import asyncio

class Khonshu:
    def __init__(self) -> None:
        self.cli = CLI().build()
        self.settings = Settings(self.cli)
        self.logger = Logger(colored=not self.cli.no_color)
        self.bannerutils = Banner("Khonshu")
        self.gitutils = GitUpdater("RevoltSecurities/Khonshu", "v1.1.0", "khonshu")

    async def run(self) -> None:
        if self.cli.help:
            self.bannerutils.render()
            self.cli.display_help()
            exit(0)
        if not self.settings.silent:
            self.bannerutils.render()
            await self.gitutils.versionlog()

        if self.settings.version:
            print("v1.1.0")
            exit(0)

        if self.settings.show_updates:
            await self.gitutils.show_update_log()
            exit(0)

        if self.settings.update:
            updated = await self.gitutils.update()
            if updated:
                self.logger.info(f"Khonshu updated to the latest version successfully")
                await self.gitutils.show_update_log()
                exit(0)
            else:
                self.logger.custom("failed", "khonshu updated failed, please update manually", "CRITICAL")
                exit(1)

        if self.settings.health_check:
            info: ConnectionInfo = await HealthCheck.check_connection("google.com", 80)
            self.logger.info(f"{info.message}")
            exit(0)

        runner = Pyrunner(self.settings)
        await runner.sprint()

def main():
    asyncio.run(Khonshu().run())