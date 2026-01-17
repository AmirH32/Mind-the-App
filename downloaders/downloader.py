# downloaders/downloader.py
import os
import requests
from tqdm import tqdm
from typing import Optional


class Downloader:
    def __init__(self, download_dir: str):
        self.download_dir = download_dir
        os.makedirs(download_dir, exist_ok=True)

    def download_file(self, url: str, filename: Optional[str] = None) -> str:
        """
        Downloads a file from a URL.
        :param url: URL of the file
        :param filename: Optional filename to save as. If None, uses the last part of URL
        :return: Path to downloaded file
        """
        if filename is None:
            filename = url.split("/")[-1]

        filepath = os.path.join(self.download_dir, filename)

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Referer": "https://www.apkmirror.com/",
            "Accept": "*/*",
        }

        # Stream download
        with requests.get(url, headers=headers, stream=True) as r:
            # Errors for HTTP codes
            r.raise_for_status()
            total_size = int(r.headers.get("content-length", 0))
            chunk_size = 8192

            with (
                open(filepath, "wb") as f,
                tqdm(
                    total=total_size, unit="B", unit_scale=True, desc=filename
                ) as pbar,
            ):
                for chunk in r.iter_content(chunk_size=chunk_size):
                    f.write(chunk)
                    pbar.update(len(chunk))
        print(f"Downloaded: {filepath}")
        return filepath
