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
# downloaders/downloader.py
import os
import requests
from tqdm import tqdm
from typing import Optional
from urllib.parse import urlparse, unquote
from .base_downloader import BaseDownloader


class Downloader(BaseDownloader):
    def _extract_ext_from_url(self, url: str) -> Optional[str]:
        """Attempt to get a file extension from a URL's path"""
        try:
            # Parse URL into components
            parsed = urlparse(url)
            # Decode URL-encoded characters
            path = unquote(parsed.path)
            filename = os.path.basename(path)

            # Remove query parameters if they somehow got included
            if "?" in filename:
                filename = filename.split("?")[0]

            # Gets the file extension using splittext functionality
            ext = os.path.splitext(filename)[1]  # Includes the dot
            if ext is None:
                return None
            else:
                return ext

        except Exception:
            return None

    def _get_filename(
        self, response: requests.Response, filename: Optional[str] = None
    ) -> str:
        """Figure out the best filename to save the file as"""
        # Check content-dispostiion header
        c_disp = response.headers.get("Content-Disposition", "")
        if c_disp and "filename=" in c_disp:
            try:
                # Parse filename from Content-Disposition
                parts = c_disp.split("filename=")
                if len(parts) > 1:
                    filename = parts[1].strip(" \"'")
                    if filename:
                        return filename
            except Exception:
                pass

        # Try to extract from the final URL after redirects
        final_url = response.url
        ext_from_url = self._extract_ext_from_url(final_url)

        if filename:
            if filename.endswith(".apk") or filename.endswith(".apkm"):
                return filename
            # Append detected extension if available to argument passed filename
            if ext_from_url:
                return f"{filename}{ext_from_url}"
            return filename
        else:
            # Otherwise give default name
            return "downloaded_file.apk"

    def download_file(self, url: str, filename: Optional[str] = None) -> Optional[str]:
        """Downloads the file"""
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0"
            ),
            "Referer": "https://www.apkmirror.com/",
            "Accept": "*/*",
        }

        with requests.get(
            url, headers=headers, stream=True, allow_redirects=True
        ) as request:
            print(f"Downloading from: {request.url}")
            # Determine the actual filename from response
            actual_filename = self._get_filename(request, filename)

            fullpath = os.path.join(self.download_dir, actual_filename)

            if os.path.exists(fullpath):
                # Ensures we don't re download files that have already been downloaded in prior runs
                print("File already exists... Skipping")
                return fullpath

            total_size = int(request.headers.get("content-length", 0))
            chunk_size = 8192

            with (
                open(fullpath, "wb") as f,
                # Use tqdm parameters to show units for the file size
                tqdm(
                    total=total_size, unit="B", unit_scale=True, desc=actual_filename
                ) as pbar,
            ):
                # Reads the request as a stream of chunbks
                for chunk in request.iter_content(chunk_size=chunk_size):
                    f.write(chunk)
                    pbar.update(len(chunk))

        print(f"Downloaded: {fullpath}")
        return fullpath
