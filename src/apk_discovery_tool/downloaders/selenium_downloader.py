# Mind the App: Detecting Dual-Use Applications
# Copyright (C) 2026 Amir Hassanali
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
import os
import time
import re
from typing import Optional
import undetected_chromedriver as uc
from .base_downloader import BaseDownloader
import shutil


class SeleniumDownloader(BaseDownloader):
    def __init__(self, download_dir: str):
        super().__init__(download_dir)

        # Config broswer to not require manual intervention (automated download) to remove Save file popup window
        options = uc.ChromeOptions()
        prefs = {
            "download.prompt_for_download": False,
        }
        # Apply the preferences
        options.add_experimental_option("prefs", prefs)

        # Initialise the browser once
        print("Initialising Chrome driver...")
        # Picks a version build that is compatible with current chromium on LTS 24.04.3 Ubuntu
        self.driver = uc.Chrome(options=options, version_main=147)
        self._user_download_dir = os.path.expanduser("~/Downloads")

    # Deprecated because we pass title as filename directly
    # def _get_filename(self, filename: str) -> str:
    #     """
    #     Converts:
    #     net.familo.android_2.99.3-1361_minAPI21(nodpi)_apkmirror.com.apk
    #
    #     Into:
    #     net.familo.android_2.99.3-1361.apk
    #     """
    #     name, ext = os.path.splitext(filename)
    #
    #     # Remove the apkmirror suffix
    #     name = name.replace("_apkmirror.com", "")
    #
    #     # Keep only package + version-build
    #     # Matches: package_version-build
    #     match = re.match(r"^(.+?_\d+(?:\.\d+)*-\d+)", name)
    #
    #     if match:
    #         cleaned = match.group(1)
    #     else:
    #         cleaned = name  # fallback if pattern fails
    #
    #     return cleaned + ext

    def download_file(
        self, url: str, filename: str, timeout: int = 180
    ) -> Optional[str]:
        """
        Navigates to the URL bypassing Cloudflare and waits for Chrome to finish the download.
        """
        print(f"Navigating to: {url}")

        # Files in download directory before download
        initial_files = set(os.listdir(self._user_download_dir))

        # Trigger the download (+ Cloudflare challenge)
        self.driver.get(url)
        print("Waiting for Cloudflare challenge and download to finish...")

        start_time = time.time()
        downloaded_file = None

        # Loop to see if a new file has been downloaded
        while time.time() - start_time < timeout:
            current_files = set(os.listdir(self._user_download_dir))
            new_files = current_files - initial_files
            # Check if new files have been donwloaded

            # Filter out Chrome's temporary download files
            finished_files = [
                f for f in new_files if f.endswith(".apk") or f.endswith(".apkm")
            ]

            # If there is a new download file web break otherwise we keep waiting
            if finished_files:
                downloaded_file = finished_files[0]
                break

            # Wait a bit before checking the directory again
            time.sleep(2)

        if downloaded_file:
            # Selenium downloads to the downloads folder so we move it to the configured folder
            _, ext = os.path.splitext(downloaded_file)
            print(filename + ext)

            original_path = os.path.join(self._user_download_dir, downloaded_file)
            final_path = os.path.join(self.download_dir, filename + ext)

            # Move the file to the new name in the download directory
            shutil.move(original_path, final_path)

            print(f"Successfully downloaded: {filename}")
            return final_path
        else:
            print(f"Download timed out after {timeout} seconds.")
            return None

    def close(self):
        """Must be called at the end to close the browser."""
        if hasattr(self, "driver"):
            print("Closing Chrome driver...")
            self.driver.quit()
