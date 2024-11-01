"""Infostealer logs parser with file organization."""
from pathlib import Path
from io import BytesIO
from zipfile import ZipFile, BadZipFile
from py7zr import SevenZipFile
from py7zr.exceptions import PasswordRequired
from rarfile import RarFile, BadRarFile
import json
import os
import signal
import sys
import shutil

from stealer_parser.helpers import init_logger, parse_options
from stealer_parser.processing import process_archive
from stealer_parser.models.archive_wrapper import ArchiveWrapper
from stealer_parser.models.leak import Leak


def setup_processing_folders(base_dir: Path) -> tuple[Path, Path]:
    """Create success and fail folders if they don't exist."""
    success_dir = base_dir / "processed_success"
    failed_dir = base_dir / "processed_failed"
    
    success_dir.mkdir(exist_ok=True)
    failed_dir.mkdir(exist_ok=True)
    
    return success_dir, failed_dir


def move_file(file_path: Path, destination_dir: Path, logger) -> bool:
    """Safely move a file to the destination directory."""
    try:
        # Create unique filename if file already exists
        dest_path = destination_dir / file_path.name
        counter = 1
        while dest_path.exists():
            stem = file_path.stem
            suffix = file_path.suffix
            dest_path = destination_dir / f"{stem}_{counter}{suffix}"
            counter += 1
            
        shutil.move(str(file_path), str(dest_path))
        logger.info(f"Moved {file_path.name} to {destination_dir.name}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to move {file_path.name}: {e}")
        return False

def load_passwords(password_input: str | None) -> list[str]:
    """Load passwords from file or argument."""
    passwords = []
    
    if not password_input:
        return passwords
        
    # If password_input is a file path
    if os.path.isfile(password_input):
        try:
            with open(password_input, 'r', encoding='utf-8') as f:
                passwords = [line.strip() for line in f if line.strip()]
            return passwords
        except Exception as e:
            print(f"Error reading password file: {e}")
    
    # If password_input is a comma-separated list
    if ',' in password_input:
        passwords = [p.strip() for p in password_input.split(',') if p.strip()]
    else:
        # Single password
        passwords = [password_input]
        
    return passwords

def retry_failed_archives(
    logger,
    failed_dir: Path,
    output_file: Path | None,
    password_input: str | None
    ) -> tuple[int, int]:
    """Process failed directory with password retries."""
    if not os.path.exists(failed_dir) or not password_input:
        return 0, 0

    passwords = load_passwords(password_input)
    if not passwords:
        return 0, 0

    logger.info(f"Starting retry attempt on failed files with {len(passwords)} passwords")
    success_dir = failed_dir.parent / "processed_success"
    
    retry_count = 0
    success_count = 0
    
    # Process each file in failed directory
    for filepath in ArchiveWrapper.find_archives(failed_dir):
        retry_count += 1
        logger.info(f"Retrying {filepath.name} with password list")
        
        # Try each password
        for password in passwords:
            if process_single_archive(
                logger,
                filepath,
                password,
                output_file,
                success_dir,
                failed_dir
            ):
                success_count += 1
                logger.success(f"Successfully processed {filepath.name} with password")
                break
        
        if success_count < retry_count:
            logger.warning(f"All passwords failed for {filepath.name}")
    
    return success_count, retry_count

def signal_handler(signum, frame):
    """Handle interrupt signals."""
    print("\nProcessing interrupted. Cleaning up...")
    sys.exit(0)


def update_json_file(filepath: Path, leak: Leak) -> None:
    """Update JSON file with new leak data."""
    try:
        if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
            with open(filepath, 'r', encoding='utf-8') as f:
                try:
                    existing_data = json.load(f)
                except json.JSONDecodeError:
                    existing_data = {"filename": "combined_results", "systems_data": []}
        else:
            existing_data = {"filename": "combined_results", "systems_data": []}

        if leak.systems_data:
            existing_data["systems_data"].extend(leak.systems_data)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(existing_data, f, default=vars, indent=4)

    except Exception as e:
        raise RuntimeError(f"Failed to update JSON file: {e}")


def process_single_archive(
    logger, 
    filepath: Path,
    password: str | None,
    output_file: Path | None = None,
    success_dir: Path | None = None,
    failed_dir: Path | None = None
) -> bool:
    """Process a single archive and organize based on result."""
    archive = None
    success = False
    
    try:
        if not password and is_password_protected(filepath):
            logger.warning(f"Skipping password-protected file: {filepath}")
            if failed_dir:
                move_file(filepath, failed_dir, logger)
            return False

        leak = Leak(filename=str(filepath))
        with open(filepath, "rb") as file_handle:
            with BytesIO(file_handle.read()) as buffer:
                archive = read_archive(buffer, str(filepath), password)
                process_archive(logger, leak, archive)

        if output_file and leak.systems_data:
            update_json_file(output_file, leak)
            logger.info(f"Updated output file with data from {filepath}")
            success = True

    except (BadZipFile, PasswordRequired, BadRarFile) as err:
        logger.warning(f"Skipping protected/corrupted archive {filepath}: {err}")
    except Exception as err:
        logger.error(f"Error processing {filepath}: {err}")
    finally:
        if archive:
            archive.close()
        
        # Move file to appropriate directory
        if success_dir and failed_dir:
            if success:
                move_file(filepath, success_dir, logger)
            else:
                move_file(filepath, failed_dir, logger)
    
    return success


def process_directory(
    logger, 
    input_path: Path, 
    password: str | None, 
    output_file: Path | None
) -> tuple[int, int]:
    """Process all archives in a directory with organization."""
    success_dir, failed_dir = setup_processing_folders(input_path)
    processed_count = 0
    skipped_count = 0
    
    # Get list of files first to avoid issues with moving files
    archive_files = list(ArchiveWrapper.find_archives(input_path))
    total_files = len(archive_files)
    
    if total_files == 0:
        logger.warning(f"No supported archive files found in {input_path}")
        return 0, 0

    logger.info(f"Found {total_files} archives to process")
    logger.info(f"Files will be moved to {success_dir} or {failed_dir} after processing")
    
    for idx, archive_path in enumerate(archive_files, 1):
        logger.info(f"Processing archive {idx}/{total_files}: {archive_path}")
        if process_single_archive(
            logger, 
            archive_path, 
            password, 
            output_file,
            success_dir,
            failed_dir
        ):
            processed_count += 1
            logger.success(f"Successfully processed {archive_path} ({idx}/{total_files})")
        else:
            skipped_count += 1
            logger.warning(f"Failed/Skipped {archive_path} ({idx}/{total_files})")
            
    return processed_count, skipped_count


def read_archive(
    buffer: BytesIO, filename: str, password: str | None
) -> ArchiveWrapper:
    """Create appropriate archive wrapper based on file extension."""
    match Path(filename).suffix.lower():
        case ".rar":
            if password:
                archive = RarFile(buffer)
                archive.setpassword(password.encode())
            else:
                archive = RarFile(buffer)
        case ".zip":
            archive = ZipFile(buffer)
        case ".7z":
            archive = SevenZipFile(buffer, password=password)
        case other_ext:
            raise NotImplementedError(f"{other_ext} not handled.")

    return ArchiveWrapper(archive, filename=filename, password=password)


def is_password_protected(filepath: Path) -> bool:
    try:
        with open(filepath, "rb") as file_handle:
            with BytesIO(file_handle.read()) as buffer:
                suffix = filepath.suffix.lower()
                if suffix == ".zip":
                    with ZipFile(buffer) as zf:
                        first_file = zf.filelist[0] if zf.filelist else None
                        if first_file and first_file.flag_bits & 0x1:
                            return True
                elif suffix == ".7z":
                    try:
                        with SevenZipFile(buffer) as sz:
                            next(sz.list())
                    except PasswordRequired:
                        return True
                elif suffix == ".rar":
                    with RarFile(buffer) as rf:
                        try:
                            rf.namelist()
                            return rf.needs_password()
                        except BadRarFile:
                            return True
    except Exception:
        return True
    return False

def main() -> None:
    """Main entry point with file organization and password retry."""
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    args = parse_options("Parse infostealer logs archives.")
    logger = init_logger(
        name="StealerParser", verbosity_level=args.verbose
    )
    
    try:
        input_path = Path(args.filename)
        output_file = Path(args.outfile) if args.outfile else None

        # For single file processing
        if input_path.is_file():
            success_dir, failed_dir = setup_processing_folders(input_path.parent)
            passwords = load_passwords(args.password)
            
            # Try first with primary password or no password
            if process_single_archive(
                logger, 
                input_path, 
                args.password, 
                output_file,
                success_dir,
                failed_dir
            ):
                logger.success(f"Successfully processed {input_path}")
            elif passwords:  # If initial attempt failed and we have passwords
                logger.info(f"Retrying with {len(passwords)} passwords")
                success_retry, _ = retry_failed_archives(
                    logger,
                    failed_dir,
                    output_file,
                    args.password
                )
                if success_retry > 0:
                    logger.success(f"Successfully processed {input_path} after password retry")
                
            logger.info("Processing complete.")
            return

        # For directory processing
        processed_count, skipped_count = process_directory(
            logger, input_path, args.password, output_file
        )

        # Retry failed archives with password list
        if args.password and skipped_count > 0:
            logger.info("Attempting to process failed archives with passwords...")
            success_retry, total_retry = retry_failed_archives(
                logger,
                input_path / "processed_failed",
                output_file,
                args.password
            )
            if success_retry > 0:
                processed_count += success_retry
                skipped_count -= success_retry
                logger.success(
                    f"Successfully recovered {success_retry} archives from failed folder"
                )
                logger.info(f"Attempted {total_retry} files, {success_retry} succeeded")

        # Final summary
        if processed_count > 0:
            logger.success(
                f"Processing complete. Successfully processed {processed_count} archives"
            )
            if skipped_count > 0:
                logger.warning(f"Skipped {skipped_count} archives")
                logger.info("Failed files remain in processed_failed directory for future retry")
        else:
            logger.error("No archives were successfully processed")
            
        logger.info("All processing complete. Files have been organized into success/failed folders.")

    except KeyboardInterrupt:
        logger.warning("\nProcessing interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()