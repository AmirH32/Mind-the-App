import zipfile
import os
import shutil
from typing import Optional


class Cleaner:
    def __init__(self, target_dir: str):
        self._target_dir = target_dir

    @staticmethod
    def _is_apkm_container(file_path: str) -> bool:
        """
        Check if a file is an APKM container that contains base.apk

        Args:
            file_path (str): Path to the file to check.

        Returns:
            bool: True if the file is an APKM container, False otherwise.
        """
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                return "base.apk" in zf.namelist()
        except:
            return False

    @staticmethod
    def _extract_base_apk_from_apkm(apkm_path: str, target_dir: str) -> Optional[str]:
        """
        Extract base.apk from APKM container and place it in target directory.

        Args:
            apkm_path (str): Path to the APKM file.
            target_dir (str): Directory to place the extracted APK.

        Returns:
            Optional[str]: Name of the extracted APK file, or None if extraction failed.
        """
        try:
            file_name = os.path.basename(apkm_path)
            base_name = os.path.splitext(file_name)[0]  # Remove .apk extension

            # Create a temporary extraction folder
            temp_extract_dir = os.path.join(target_dir, f"_temp_{base_name}")
            os.makedirs(temp_extract_dir, exist_ok=True)

            # Extract the APKM
            with zipfile.ZipFile(apkm_path, "r") as zf:
                zf.extractall(temp_extract_dir)

            # Find and rename base.apk
            base_apk_path = os.path.join(temp_extract_dir, "base.apk")
            if os.path.exists(base_apk_path):
                # Create a new name for the extracted APK
                new_apk_name = f"{base_name}_base.apk"
                new_apk_path = os.path.join(target_dir, new_apk_name)

                # Copy base.apk to target directory with new name
                shutil.copy2(base_apk_path, new_apk_path)

                # Clean up temporary extraction folder
                shutil.rmtree(temp_extract_dir)

                # Remove the original APKM file
                os.remove(apkm_path)

                print(f"Extracted: {file_name} to {new_apk_name}")
                return new_apk_name
            else:
                print(f"No base.apk found in {file_name}")
                shutil.rmtree(temp_extract_dir)
                return None

        except Exception as e:
            print(f"Failed to process {os.path.basename(apkm_path)}: {e}")
            # Clean up temp folder if it exists
            if os.path.exists(temp_extract_dir):
                shutil.rmtree(temp_extract_dir, ignore_errors=True)
            return None

    @staticmethod
    def process_directory(directory_path: str):
        """
        Process all files in directory: extract APKMs and clean up non-APKs.

        Args:
            directory_path (str): Path to the target directory.
        """

        if not os.path.isdir(directory_path):
            print(f"Error: Directory '{directory_path}' not found.")
            return

        print(f"Processing directory: {directory_path}")
        print("-" * 50)

        apk_files = []
        apkm_files = []
        other_files = []

        # Step 1: Scan and categorize all files
        for filename in os.listdir(directory_path):
            file_path = os.path.join(directory_path, filename)

            if os.path.isdir(file_path):
                continue  # Skip subdirectories

            if filename.endswith(".apk"):
                # Ensure the file is not misnamed APKM
                if Cleaner._is_apkm_container(file_path):
                    apkm_files.append(file_path)
                else:
                    apk_files.append(filename)
            elif filename.endswith(".apkm"):
                apkm_files.append(file_path)
            else:
                other_files.append(file_path)

        print(
            f"Found: {len(apk_files)} APK(s), {len(apkm_files)} APKM(s), {len(other_files)} other file(s)"
        )

        # Step 2: Process all APKM containers
        extracted_apks = []
        if apkm_files:
            print("\nExtracting APKM containers:")
            for apkm_path in apkm_files:
                extracted_name = Cleaner._extract_base_apk_from_apkm(
                    apkm_path, directory_path
                )
                if extracted_name:
                    extracted_apks.append(extracted_name)
                    apk_files.append(extracted_name)  # Add to APK list for summary

        # Step 3: Clean up non-APK files
        if other_files:
            print(f"\nCleaning up {len(other_files)} non-APK file(s):")
            for file_path in other_files:
                try:
                    os.remove(file_path)
                    print(f"- Removed: {os.path.basename(file_path)}")
                except Exception as e:
                    print(f"Failed to remove {os.path.basename(file_path)}: {e}")

        # Step 4: Summary
        print("\n" + "=" * 50)
        print("PROCESSING COMPLETE")
        print(f"Original APK files: {len(apk_files) - len(extracted_apks)}")
        print(f"APKM containers processed: {len(apkm_files)}")
        print(f"Extracted APKs from APKMs: {len(extracted_apks)}")
        print(f"Non-APK files removed: {len(other_files)}")

        # Show all APK files now in directory
        final_apk_files = [f for f in os.listdir(directory_path) if f.endswith(".apk")]

        if final_apk_files:
            print(f"\nTotal APK files in directory: {len(final_apk_files)}")
            print("\nAPK files:")
            for i, apk in enumerate(final_apk_files, 1):  # Show first 15
                prefix = "- "
                if apk in extracted_apks:
                    prefix = "[+] "  # Mark extracted ones
                print(f"{i}. {prefix}{apk}")

        # Clean up any remaining temporary folders (in case of errors)
        for item in os.listdir(directory_path):
            item_path = os.path.join(directory_path, item)
            if os.path.isdir(item_path) and item.startswith("_temp_"):
                try:
                    shutil.rmtree(item_path)
                    print(f"\nCleaned up temporary folder: {item}")
                except:
                    pass
