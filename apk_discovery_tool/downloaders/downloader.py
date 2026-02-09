# downloaders/downloader.py
import os
import requests
from tqdm import tqdm
from typing import Optional
from urllib.parse import urlparse, unquote


class Downloader:
    def __init__(self, download_dir: str):
        self.download_dir = download_dir
        os.makedirs(download_dir, exist_ok=True)

    def _extract_extension_from_url(self, url: str) -> Optional[str]:
        """
        Extract extension from URL path, handling encoded characters.

        :param url: URL to extract extension from
        :return: Extracted filename or None
        """
        try:
            # Parse URL into components
            parsed = urlparse(url)
            # Decode URL-encoded characters
            path = unquote(parsed.path)
            filename = os.path.basename(path)

            # Remove query parameters if they somehow got included
            if "?" in filename:
                filename = filename.split("?")[0]

            # Gets the file extension
            extension = os.path.splitext(filename)[1]

            return extension if extension else None
        except Exception:
            return None

    def _get_filename_from_response(
        self, response: requests.Response, filename: Optional[str] = None
    ) -> str:
        """
        Determine the correct filename from the response headers or URL.

        :param response: HTTP response object
        :param fallback_filename: Fallback filename if detection fails
        :return: Determined filename
        """
        # Try Content-Disposition header first
        content_disp = response.headers.get("Content-Disposition", "")
        if content_disp and "filename=" in content_disp:
            try:
                # Parse filename from Content-Disposition
                parts = content_disp.split("filename=")
                if len(parts) > 1:
                    filename = parts[1].strip().strip('"').strip("'")
                    if filename:
                        return filename
            except Exception:
                pass

        # Try to extract from the final URL after redirects
        final_url = response.url
        extension = self._extract_extension_from_url(final_url)

        if filename and (filename.endswith(".apk") or filename.endswith(".apkm")):
            return filename
        elif filename:
            # Append detected extension if available
            if extension:
                return f"{filename}{extension}"
            return filename
        else:
            return "downloaded_file.apk"

    def download_file(self, url: str, filename: Optional[str] = None) -> str:
        """
        Downloads a file from a URL, automatically detecting the correct file extension.

        :param url: URL of the file
        :param filename: Optional filename to save as. Extension will be auto-detected.
        :return: Path to downloaded file
        """
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Referer": "https://www.apkmirror.com/",
            "Accept": "*/*",
        }

        # Stream download with allow_redirects to follow redirects
        with requests.get(url, headers=headers, stream=True, allow_redirects=True) as r:
            # Raise errors for HTTP codes
            r.raise_for_status()

            # Determine the actual filename from response
            actual_filename = self._get_filename_from_response(r, filename)

            filepath = os.path.join(self.download_dir, actual_filename)

            total_size = int(r.headers.get("content-length", 0))
            chunk_size = 8192

            with (
                open(filepath, "wb") as f,
                tqdm(
                    total=total_size, unit="B", unit_scale=True, desc=actual_filename
                ) as pbar,
            ):
                for chunk in r.iter_content(chunk_size=chunk_size):
                    f.write(chunk)
                    pbar.update(len(chunk))

        print(f"Downloaded: {filepath}")
        return filepath
