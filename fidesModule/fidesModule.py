# Must imports
from slips_files.common.imports import *


class Awesome(IModule):
    # Name: short name of the module. Do not use spaces
    name = "Awesome"
    description = "My awesome module"
    authors = ["Awesome Author"]

    def init(self):
        # To which channels do you wnat to subscribe? When a message
        # arrives on the channel the module will wakeup
        # The options change, so the last list is on the
        # slips/core/database.py file. However common options are:
        # - new_ip
        # - tw_modified
        # - evidence_added
        # Remember to subscribe to this channel in database.py
        self.c1 = self.db.subscribe("new_ip")
        self.channels = {
            "new_ip": self.c1,
        }

    def pre_main(self):
        """
        Initializations that run only once before the main() function runs in a loop
        """
        utils.drop_root_privs()

    def main(self):
        """Main loop function"""
        if msg := self.get_msg("new_ip"):
            # Example of printing the number of profiles in the
            # Database every second
            data = len(self.db.getProfiles())
            self.print(f"Amount of profiles: {data}", 3, 0)