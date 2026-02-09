# File Purpose - used to extract static features from APKs

from androguard.core.apk import APK as AndroguardAPK
from androguard.misc import AnalyzeAPK
from concurrent.futures import ProcessPoolExecutor, TimeoutError
import androguard.util
from loguru import logger
import tqdm
import sys
import csv
import json
import gc
import re
from pathlib import Path
from typing import List


def get_suspicious_permissions() -> List[str]:
    """
    Extracts suspicious permissions from a JSON file.

    Returns:
        List[str]: List of suspicious permission names.
    """
    try:
        with open("suspicious_permissions.json", "r") as file:
            data = json.load(file)
            if isinstance(data, list):
                return [item["name"] for item in data]
            else:
                print("Invalid format in suspicious_permissions.json.")
                return []
    except FileNotFoundError:
        print("suspicious_permissions.json file not found.")
        return []


class APK:
    def __init__(self, apk_path: str):
        """
        APK wrapper class to store the metadata from static APK analysis

        Parameters:
        apk_path (Path): Path to the APK file.
        """
        self._apk_path = apk_path
        self._apk = AndroguardAPK(apk_path)
        self._package_name = self._apk.get_package()
        print(f"Analysing {self._package_name}...")
        self._app_name = self._apk.get_app_name()
        self._version_name = self._apk.get_androidversion_name()
        self._permissions = self._apk.get_permissions() or []
        self._suspicious_permissions = self._identify_suspicious_permissions()
        self._suspicious_implied_perms = self._identify_suspicious_implied_permissions()
        self._target_old_sdk = self._apk.get_target_sdk_version() <= "19"
        self._activities = self._apk.get_activities()
        # self._services = self._apk.get_services()
        # self._receivers = self._apk.get_receivers()
        # self._providers = self._apk.get_providers()
        # self._activity_aliases = self._apk.get_activity_aliases()
        self._hidden_icon, self._boot_persistance, self._user_persistance = (
            self._suspicious_intentions()
        )
        self._suspicious_libs = self._suspicious_libraries()
        self._num_sus_urls = self._find_num_sus_urls()

        # Deprecated due to memory usage + noise
        # _, self._dalvikVM, self._analysis = AnalyzeAPK(self._apk_path)
        # self._cleanup_analysis()
        # Not using api calls because there is too much noise
        # self._api_calls = self._extract_api_calls()

    def get_metadata(self):
        """
        Returns the metadata of the APK.

        Returns:
        dict: A dictionary containing package name, version name, and permissions.
        """
        return {
            "apk_name": self._apk_path,
            "app_name": self._app_name,
            "package_name": self._package_name,
            "version_name": self._version_name,
            "permissions": self._permissions,
            "suspicious_permissions": self._suspicious_permissions,
            "suspicious_implied_permissions": self._suspicious_implied_perms,
            "targets_old_sdk": self._target_old_sdk,
            # "activities": self._activities,
            # "services": self._services,
            # "receivers": self._receivers,
            # "providers": self._providers,
            # "activity_aliases": self._activity_aliases,
            # "hidden_icon": self._hidden_icon,
            "boot_persistance": self._boot_persistance,
            "user_persistance": self._user_persistance,
            "suspicious_libraries": self._suspicious_libs,
            "num_sus_urls": self._num_sus_urls,
        }

    def _identify_suspicious_permissions(self) -> List[str]:
        """
        Identifies suspicious permissions from the APK's permissions.

        Returns:
        list: A list of suspicious permissions.
        """
        flagged_perms = []
        suspicious_permissions = get_suspicious_permissions()
        for permission in self._permissions:
            if permission in suspicious_permissions:
                flagged_perms.append(permission)
        return flagged_perms

    def _identify_suspicious_implied_permissions(self) -> List[str]:
        """
        Identifies suspicious implied permissions based on targeted SDK version
        Returns:
        list: A list of suspicious implied permissions.
        """
        raw_implied = self._apk.get_uses_implied_permission_list()
        suspicious_perms = []

        high_risk_implied_permissions = [
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_PHONE_STATE",  # Could be implied on very old SDK
        ]

        for pair in raw_implied:
            if pair and len(pair) > 0:
                perm_name = pair[0]

                if perm_name in high_risk_implied_permissions:
                    suspicious_perms.append(perm_name)
        return suspicious_perms

    def _suspicious_intentions(self) -> tuple[bool, bool, bool]:
        """Check for suspicious intent-filters in activities such as LAUNCHER missing the icon, BOOT_COMPLETED, USER_PRESENT

        Returns:
            tuple: (has_launcher_activity, boot_persistance, user_persistance)
        """
        has_launcher_activity = False
        boot_persistance = False
        user_persistance = False

        # Get all activities with their intent filters
        activities = self._activities

        for activity in activities:
            # Get intent filters for this activity
            intent_filters = self._apk.get_intent_filters("activity", activity)

            if intent_filters:
                # Check if any intent filter has the LAUNCHER category
                for filter_name, filter_values in intent_filters.items():
                    if filter_name == "category":
                        if "android.intent.category.LAUNCHER" in filter_values:
                            has_launcher_activity = True

                    if "android.intent.action.BOOT_COMPLETED" in filter_values:
                        boot_persistance = True

                    if "android.intent.action.USER_PRESENT" in filter_values:
                        user_persistance = True

        return (has_launcher_activity, boot_persistance, user_persistance)

    def _has_declared_permissions(self) -> bool:
        """
        Checks if the APK has declared any permissions.

        Returns:
        bool: True if permissions are declared, False otherwise.
        """
        declared_permissions = self._apk.get_declared_permissions()
        if len(declared_permissions) > 0:
            return True
        return False

    # def _extract_api_calls(self) -> List[str]:
    #     """
    #     Extracts API calls from the APK's DEX files.
    #     Returns:
    #     dict: API calls organized by class/method
    #     Deprecated due to redundancy
    #     """
    #
    #     api_calls = {
    #         "location_apis": [],
    #         "camera_apis": [],
    #         "microphone_apis": [],
    #         "sms_apis": [],
    #         "call_log_apis": [],
    #         "contacts_apis": [],
    #         "accessibility_apis": [],
    #         "admin_apis": [],
    #     }
    #
    #     api_calls = []
    #
    #     # Iterate through all methods found in the analysis
    #     for method in self._analysis.get_methods():
    #         full_name = "{}->{}{}".format(
    #             method.class_name, method.name, method.descriptor
    #         )
    #         api_calls.append(full_name)
    #
    #     return api_calls

    def _suspicious_libraries(self):
        """Find .so files that are NOT declared in AndroidManifest.xml"""
        # Get declared libraries (from <library> tags in manifest)
        declared_libs = set(self._apk.get_libraries())

        # Find ALL .so files in the APK
        all_so_files = []
        for file_name in self._apk.zip.namelist():
            if file_name.endswith(".so"):
                all_so_files.append(file_name)

        # Identify UNDECLARED .so files
        for so_path in all_so_files:
            # Extract just the filename, e.g., 'libevil.so' from 'lib/armeabi-v7a/libevil.so'
            so_filename = so_path.split("/")[-1]

            # Convert filename to expected declared name: 'libevil.so' -> 'evil'
            if so_filename.startswith("lib") and so_filename.endswith(".so"):
                expected_declared_name = so_filename[3:-3]  # Remove 'lib' and '.so'

                # Handle version suffixes: 'libfoo-1.2.so' -> 'foo'
                if "-" in expected_declared_name:
                    expected_declared_name = expected_declared_name.split("-")[0]

                # Check if this name is declared in manifest
                if expected_declared_name not in declared_libs:
                    return True
        return False

    def _extract_urls_from_text(self, text: str) -> List[str]:
        """Extract and score URLs from text"""

        # Your URL regex pattern
        url_regex = re.compile(
            r"((https?|ftp):\/\/)?"  # Optional scheme
            r"([\w\-]+(\.[\w\-]+)+)"  # domain
            r"(:\d{1,5})?"  # Optional port
            r"(\/[^\s]*)?"  # Optional path
        )

        results = []
        distinct_ips = set()

        for match in url_regex.finditer(text):
            # Reconstruct URL from match groups
            scheme = match.group(1) or ""
            domain = match.group(3) or ""
            port = match.group(5) or ""
            path = match.group(6) or ""

            # Skip empty or malformed
            if not domain:
                continue

            full_url = f"{scheme}{domain}{port}{path}"
            results.append(full_url)

            # Check for IP address
            if re.match(r"\d+\.\d+\.\d+\.\d+", domain) and domain not in distinct_ips:
                distinct_ips.add(domain)
                print(f"Skipping IP address URL: {full_url}")

        return results

    def _scan_resources_for_urls(self) -> list[str]:
        """Scan text-based resource files"""
        resource_urls = []

        # Common text file extensions
        text_extensions = {".txt", ".json", ".xml", ".config", ".plist", ".ini", ".cfg"}
        apk_obj = self._apk

        for file_name in apk_obj.zip.namelist():
            # Check if it's a text file in assets or res
            if any(file_name.endswith(ext) for ext in text_extensions):
                try:
                    file_data = apk_obj.zip.read(file_name)
                    try:
                        text_content = file_data.decode("utf-8", errors="ignore")
                    except:
                        text_content = file_data.decode("latin-1", errors="ignore")

                    urls_found = self._extract_urls_from_text(text_content)
                    resource_urls.extend(urls_found)

                except:
                    # Skip binary files that fail to decode
                    continue

        return resource_urls

    # def _scan_dex_for_urls(self) -> list[str]:
    #     """Scan DEX files for URLs in strings"""
    #     dex_urls = []
    #     all_strings = set()
    #
    #     # Get all strings from all DEX files
    #     for dex in self._dalvikVM:
    #         try:
    #             strings = dex.get_strings()
    #             all_strings.update(strings)
    #         except Exception as e:
    #             print(f"Error reading strings from DEX: {e}")
    #             continue
    #
    #     for string in all_strings:
    #         try:
    #             # Convert to string if it's bytes
    #             if isinstance(string, bytes):
    #                 string = string.decode("utf-8", errors="ignore")
    #             urls_found = self._extract_urls_from_text(str(string))
    #             dex_urls.extend(urls_found)
    #         except Exception as e:
    #             continue
    #
    #     return dex_urls

    def _scan_libraries_for_urls(self):
        """Scan .so library files for URLs"""
        lib_urls = []
        apk_obj = self._apk

        # Look for .so files
        for file_name in apk_obj.zip.namelist():
            if file_name.endswith(".so"):
                try:
                    file_data = apk_obj.zip.read(file_name)

                    try:
                        # Try UTF-8
                        text_content = file_data.decode("utf-8", errors="ignore")
                    except:
                        try:
                            # Try Latin-1
                            text_content = file_data.decode("latin-1", errors="ignore")
                        except:
                            continue

                    urls_found = self._extract_urls_from_text(text_content)
                    lib_urls.extend(urls_found)

                except:
                    continue

        return lib_urls

    def _find_num_sus_urls(self) -> int:
        """Find potential C2 URLs in ALL parts of APK apart from bytecode/binary"""

        sus_urls = []

        # Deprecated
        # dex_urls = self._scan_dex_for_urls()
        # sus_urls.extend(dex_urls)

        lib_urls = self._scan_libraries_for_urls()
        sus_urls.extend(lib_urls)

        resource_urls = self._scan_resources_for_urls()
        sus_urls.extend(resource_urls)

        print(f"Found {len(sus_urls)} URLs in APK resources and libraries.")
        return len(sus_urls)

    # def _cleanup_analysis(self):
    # Deprecated
    #     """Cleanup analysis objects to free memory"""
    #     self._dalvikVM = None
    #     self._analysis = None
    #     self._apk = None
    #     gc.collect()


class APKanalyser:
    def __init__(self, apk_directory_path):
        """
        APK Analyser constructor. APK analyser extracts static features from APK files in the given directory.

        Parameters:
        apk_directory_path (Path): Path to the directory containing the APK files to be analysed.

        Raises:
        ValueError: If the provided path is not a directory.
        """
        if apk_directory_path.is_dir():
            self.apk_directory_path = apk_directory_path
        else:
            raise ValueError("Provided path is not a directory.")

        self.results = []  # List to hold APK objects

        self._load_apks()  # Load APKs from the directory

    @staticmethod
    def analyse_single_apk(apk_path):
        """
        Standalone function for the ProcessPool to execute.
        This must be outside the class to be 'picklable'.
        """
        try:
            # We initialize the APK object inside the child process
            apk_instance = APK(str(apk_path))
            metadata = apk_instance.get_metadata()

            # The object is destroyed when this process exits
            return metadata
        except Exception as e:
            return {"error": str(e), "apk_name": str(apk_path)}

    def _load_apks(self, timeout=150):
        """
        Private Method that constructs APK objects for each APK file in the specified directory. It then stores the metadata of each APK in the results list.

        Raises:
        Exception: If an APK file cannot be loaded.
        """

        self.results = []
        apk_files = list(self.apk_directory_path.glob("*.apk"))

        # Process one by one to keep memory low, but with a timeout
        for apk_path in tqdm.tqdm(apk_files, desc="Analysing"):
            with ProcessPoolExecutor(max_workers=1) as executor:
                future = executor.submit(self.analyse_single_apk, apk_path)
                try:
                    # Wait for the result with a strict timeout
                    result = future.result(timeout=timeout)
                    self.results.append(result)
                except TimeoutError:
                    print(f"\n[!] Timeout reached for {apk_path.name}. Skipping...")
                    # The 'with' block will clean up the hung process here
                except Exception as e:
                    print(f"\n[!] Error processing {apk_path.name}: {e}")

    def export_features(self, output_csv):
        """
        Exports extracted features to a CSV file formatted for ML training.
        Includes a 'label' column for your ground truth.
        """
        critical_permissions = get_suspicious_permissions()
        perm_headers = [f"perm_{p.split('.')[-1]}" for p in critical_permissions]

        fieldnames = [
            "apk_name",
            "package_name",
            "label",
            "risk_score_prediction",
            "targets_old_sdk",
            "boot_persistence",
            "user_persistence",
            "suspicious_libraries",
            "num_suspicious_urls",
            "num_total_permissions",
            "num_suspicious_permissions",
        ] + list(perm_headers)

        with open(output_csv, mode="w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()

            for metadata in self.results:
                if metadata.get("error"):
                    continue

                # Combine all permissions
                all_app_perms = set(
                    metadata.get("permissions", [])
                    + metadata.get("suspicious_implied_permissions", [])
                )

                row = {
                    "apk_name": metadata.get("apk_name"),
                    "package_name": metadata.get("package_name"),
                    "label": "",
                    "risk_score_prediction": "",
                    "targets_old_sdk": 1 if metadata.get("targets_old_sdk") else 0,
                    "boot_persistence": 1 if metadata.get("boot_persistance") else 0,
                    "user_persistence": 1 if metadata.get("user_persistance") else 0,
                    "suspicious_libraries": 1
                    if metadata.get("suspicious_libraries")
                    else 0,
                    "num_suspicious_urls": metadata.get("num_sus_urls", 0),
                    "num_total_permissions": len(metadata.get("permissions", [])),
                    "num_suspicious_permissions": len(
                        metadata.get("suspicious_permissions", [])
                    ),
                }

                # Fill in the 1s and 0s for critical permissions
                for i, full_perm_name in enumerate(critical_permissions):
                    header = perm_headers[i]
                    if full_perm_name in all_app_perms:
                        row[header] = 1
                    else:
                        row[header] = 0

                writer.writerow(row)

    def output_features(self):
        """
        Outputs the extracted features of all APKs to the console.
        """

        for metadata in self.results:
            if metadata.get("error"):
                print(f"Error analysing {metadata['apk_name']}: {metadata['error']}")
                continue
            else:
                print(f"APK Name: {metadata['apk_name']}")
                print(f"App Name: {metadata['app_name']}")
                print(f"Package Name: {metadata['package_name']}")
                print(f"Version Name: {metadata['version_name']}")
                print(
                    f"☢️ Suspicious Permissions: {', '.join(metadata['suspicious_permissions'])}\n"
                )
                print(
                    f"Implied Permissions: {metadata['suspicious_implied_permissions']}\n"
                )
                print(f"Targets Old SDK: {metadata['targets_old_sdk']}")
                # print(f"Activities: {', '.join(metadata['activities'])}")
                # print(f"Services: {', '.join(metadata['services'])}")
                # print(f"Receivers: {', '.join(metadata['receivers'])}")
                # print(f"Providers: {', '.join(metadata['providers'])}")
                # print(
                #     f"Activity Aliases: {', '.join(f'Name:{name} target:{target}' for name, target in metadata['activity_aliases'])}"
                # )
                # print(f"Hidden Icon: {metadata['hidden_icon']}")
                print(f"Boot Persistance: {metadata['boot_persistance']}")
                print(f"User Persistance: {metadata['user_persistance']}")
                print(f"Suspicious Libraries: {metadata['suspicious_libraries']}")
                print(f"Number of Suspicious URLs: {metadata['num_sus_urls']}")
                print("-" * 40)

        print(f"Total APKs analysed: {len(self.results)}")


def setup_androguard_logging(verbose=False):
    """
    Configure Androguard's logging level.
    Set verbose=False to suppress DEBUG and INFO messages.
    """
    if verbose:
        # Show all messages (default behavior)
        androguard.util.set_log("DEBUG")
        logger.enable("androguard")  # Ensure logger is on
        androguard.util.set_log("WARNING")

    else:
        logger.disable("androguard")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python APK_analyser.py <input_apk_directory> <output_csv_file>")
        sys.exit(1)

    # Use it before your analysis
    setup_androguard_logging(verbose=False)

    input_dir = Path(sys.argv[1])
    output_csv = sys.argv[2]

    analyser = APKanalyser(input_dir)
    analyser.output_features()
    analyser.export_features(output_csv)
