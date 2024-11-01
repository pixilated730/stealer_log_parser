"""Infostealer logs parser."""
from argparse import Namespace
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile, BadZipFile
from py7zr import SevenZipFile
from py7zr.exceptions import PasswordRequired
from rarfile import RarFile, BadRarFile
from verboselogs import VerboseLogger
from typing import List

from stealer_parser.helpers import dump_to_file, init_logger, parse_options
from stealer_parser.models import ArchiveWrapper, Leak
from stealer_parser.processing import process_archive


def read_archive(
    buffer: BytesIO, filename: str, password: str | None
) -> ArchiveWrapper:
    """Create appropriate archive wrapper based on file extension."""
    archive: RarFile | ZipFile | SevenZipFile

    match Path(filename).suffix.lower():
        case ".rar":
            archive = RarFile(buffer, password=password.encode() if password else None)
        case ".zip":
            archive = ZipFile(buffer)
        case ".7z":
            archive = SevenZipFile(buffer, password=password)
        case other_ext:
            raise NotImplementedError(f"{other_ext} not handled.")

    return ArchiveWrapper(archive, filename=filename, password=password)


def is_password_protected(filepath: Path) -> bool:
    """Check if an archive is password protected."""
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
                        return rf.needs_password()
    except (BadZipFile, PasswordRequired, BadRarFile, Exception):
        return True
    return False


def process_single_archive(
    logger: VerboseLogger, 
    filepath: Path,
    password: str | None,
    outfile: str | None = None
) -> bool:
    """Process a single archive file and return success status."""
    archive: ArchiveWrapper | None = None

    try:
        leak = Leak(filename=str(filepath))

        with open(filepath, "rb") as file_handle:
            with BytesIO(file_handle.read()) as buffer:
                archive = read_archive(buffer, str(filepath), password)
                process_archive(logger, leak, archive)

        # Use the existing dump_to_file helper that works well
        if outfile:
            dump_to_file(logger, outfile, leak)
        return True

    except (FileNotFoundError, NotImplementedError, OSError, PermissionError) as err:
        logger.error(f"Failed reading {filepath}: {err}")
    except (BadZipFile, PasswordRequired, BadRarFile) as err:
        logger.error(f"Archive error in {filepath}: {err}")
    except RuntimeError as err:
        logger.error(f"Failed parsing {filepath}: {err}")
    finally:
        if archive:
            archive.close()
    
    return False


def get_archive_files(path: Path, password: str | None = None) -> List[Path]:
    """Get all supported archive files from a directory or single file."""
    supported_extensions = {'.rar', '.zip', '.7z'}
    
    if path.is_file():
        return [path] if path.suffix.lower() in supported_extensions else []
    
    archive_files = []
    for ext in supported_extensions:
        for file_path in path.rglob(f"*{ext}"):
            if not password and is_password_protected(file_path):
                continue
            archive_files.append(file_path)
    
    return sorted(archive_files)


def main() -> None:
    """Program's entrypoint."""
    args: Namespace = parse_options("Parse infostealer logs archives.")
    logger: VerboseLogger = init_logger(
        name="StealerParser", verbosity_level=args.verbose
    )
    
    input_path = Path(args.filename)
    
    # For single file
    if input_path.is_file():
        if not args.password and is_password_protected(input_path):
            logger.error(f"Archive {input_path} is password protected. Please provide a password.")
            return
            
        if process_single_archive(logger, input_path, args.password, args.outfile):
            logger.success(f"Successfully processed {input_path}")
        return
    
    # For directory
    archive_files = get_archive_files(input_path, args.password)
    
    if not archive_files:
        logger.error(f"No accessible archive files found in {input_path}")
        logger.info("Note: Password-protected archives were skipped as no password was provided")
        return
        
    processed_count = 0
    skipped_count = 0
    
    # Process each archive
    for archive_path in archive_files:
        logger.info(f"Processing archive: {archive_path}")
        if process_single_archive(logger, archive_path, args.password, args.outfile):
            processed_count += 1
            logger.success(f"Successfully processed {archive_path}")
        else:
            skipped_count += 1
            logger.warning(f"Skipped {archive_path}")
    
    # Final summary
    if processed_count > 0:
        logger.success(f"Successfully processed {processed_count} archives")
        if skipped_count > 0:
            logger.warning(f"Skipped {skipped_count} archives due to errors")
    else:
        logger.error("No archives were successfully processed")


if __name__ == "__main__":
    main()