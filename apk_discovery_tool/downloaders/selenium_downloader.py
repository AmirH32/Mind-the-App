import os
import time
import re
from typing import Optional
import undetected_chromedriver as uc
from .base_downloader import BaseDownloader


class SeleniumDownloader(BaseDownloader):
    def __init__(self, download_dir: str):
        super().__init__(download_dir)

        # Config broswer to not require manual intervention
        options = uc.ChromeOptions()
        prefs = {
            "download.prompt_for_download": False,
        }
        options.add_experimental_option("prefs", prefs)

        # Initialize the browser once
        print("Initializing Chrome driver...")
        self.driver = uc.Chrome(options=options, version_main=145)

    def _get_filename(self, filename: str) -> str:
        """
        Converts:
        net.familo.android_2.99.3-1361_minAPI21(nodpi)_apkmirror.com.apk

        Into:
        net.familo.android_2.99.3-1361.apk
        """
        name, ext = os.path.splitext(filename)

        # Remove the apkmirror suffix
        name = name.replace("_apkmirror.com", "")

        # Keep only package + version-build
        # Matches: package_version-build
        match = re.match(r"^(.+?_\d+(?:\.\d+)*-\d+)", name)

        if match:
            cleaned = match.group(1)
        else:
            cleaned = name  # fallback if pattern fails

        return cleaned + ext

    def download_file(self, url: str, timeout: int = 60) -> Optional[str]:
        """
        Navigates to the URL bypassing Cloudflare and waits for Chrome to finish the download.
        """
        print(f"Navigating to: {url}")

        # Files in download directory before download
        initial_files = set(os.listdir(self.download_dir))

        # Trigger the download (and Cloudflare challenge)
        self.driver.get(url)
        print("Waiting for Cloudflare challenge and download to finish...")

        start_time = time.time()
        downloaded_file = None

        while time.time() - start_time < timeout:
            current_files = set(os.listdir(self.download_dir))
            new_files = current_files - initial_files
            # Check if new files have been donwloaded

            # Filter out Chrome's temporary download files
            finished_files = [
                f for f in new_files if f.endswith(".apk") or f.endswith(".apkm")
            ]

            # If there is a new download file we wait
            if finished_files:
                downloaded_file = finished_files[0]
                break

            # Wait a bit before checking the directory again
            time.sleep(2)

        if downloaded_file:
            clean_name = self._get_filename(downloaded_file)
            original_path = os.path.join(self.download_dir, downloaded_file)
            final_path = os.path.join(self.download_dir, clean_name)

            os.rename(original_path, final_path)

            print(f"Successfully downloaded: {clean_name}")
            return final_path
        else:
            print(f"Download timed out after {timeout} seconds.")
            return None

    def close(self):
        """Must be called at the end to close the browser."""
        if hasattr(self, "driver"):
            print("Closing Chrome driver...")
            self.driver.quit()
