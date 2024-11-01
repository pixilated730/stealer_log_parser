"""Infostealer logs parser."""
from dataclasses import dataclass
from enum import Enum
from re import Match, Pattern, compile

from py7zr.exceptions import CrcError
from rarfile import BadRarFile
from verboselogs import VerboseLogger

from stealer_parser.models import (
    ArchiveWrapper,
    Leak,
    StealerNameType,
    System,
    SystemData,
)
from stealer_parser.parsing import (
    parse_passwords,
    parse_system,
    retrieve_ip_only,
)
from stealer_parser.ply.src.ply.lex import LexError
from stealer_parser.search_stealer_credits import search_stealer_name

# Files containing useful information such as credentials and credits.
FILENAMES_REGEX: str = r"(?i).*((password(?!cracker))|(system|information|userinfo)|(\bip)|(credits|copyright|read)).*\.txt"  # noqa: E501
# Let's break down this regex:
#
# (?i)       Case insensitive
# (password)|(\bcc(\b|.))|([^#](system|information|userinfo)) ...
#            Match substring.
#            Group 2: password not followed by cracker -> credentials
#            Group 3: system|information -> compromised machine information
#            Group 4: ip.txt -> IP address of the compromised machine.
#            Group 5: credits|copyright|read -> stealer name
# .*\.txt    Match any character except line terminators folled by a .txt
#            extension.
FILENAMES_PATTERN: Pattern[str] = compile(FILENAMES_REGEX)


class LogFileType(Enum):
    """Log files types."""

    PASSWORDS = 2
    SYSTEM = 3
    IP = 4
    COPYRIGHT = 5


@dataclass
class LogFile:

    type: LogFileType
    filename: str
    system_dir: str


def get_system_dir(filepath: str) -> str:
    start: int = filepath.find("/") + 1

    if start > 0:
        end: int = filepath.find("/", start)

        if end > start:  # Two-levels archive.
            return filepath[start:end]
        return filepath[:start]

    return filepath


def generate_file_list(root: ArchiveWrapper) -> list[LogFile]:

    files: list[LogFile] = []

    for name in sorted(root.namelist()):
        matched: Match[str] | None = FILENAMES_PATTERN.search(name)

        if matched:
            log_type: LogFileType

            if matched.group(2):
                log_type = LogFileType.PASSWORDS
            elif matched.group(3) and "#" not in name:
                log_type = LogFileType.SYSTEM
            elif matched.group(4):
                log_type = LogFileType.IP
            elif matched.group(5):
                log_type = LogFileType.COPYRIGHT

            files.append(LogFile(log_type, name, get_system_dir(name)))

    return files


def parse_file(
    logger: VerboseLogger,
    filename: str,
    system_data: SystemData,
    file: LogFile,
    text: str,
) -> None:
    try:
        match file.type:
            case LogFileType.PASSWORDS:
                system_data.credentials += parse_passwords(
                    logger, filename, text
                )

            case LogFileType.SYSTEM:
                system: System | None = parse_system(logger, filename, text)

                if system:
                    if system_data.system and system_data.system.ip_address:
                        system.ip_address = system_data.system.ip_address
                    system_data.system = system

            case LogFileType.IP:
                retrieve_ip_only(text, system_data)

    except (LexError, SyntaxError) as err:
        logger.error(f"Failed parsing file '{filename}': {err}")


def process_system_dir(
    logger: VerboseLogger,
    leak: Leak,
    archive: ArchiveWrapper,
    files: list[LogFile],
) -> int:
    stealer_name: StealerNameType | None = None
    system_data = SystemData()
    current_dir: str = files[0].system_dir
    count: int = 0

    for file in files:
        filename: str = f"{archive.filename}/{file.filename}"

        if file.system_dir != current_dir:
            break

        try:
            text: str = archive.read_file(file.filename)

            if not stealer_name:
                stealer_name = search_stealer_name(text)

            parse_file(logger, filename, system_data, file, text)

        except (CrcError, KeyError, UnicodeDecodeError, ValueError) as err:
            logger.error(f"Error reading file '{filename}': {err}")

        except TypeError as err:
            logger.error(f"Error '{filename}': {err}")

        count += 1

    if system_data.credentials and stealer_name:
        system_data.add_stealer_name(stealer_name)

    if (
        system_data.system
        and any(list(system_data.system.__dict__.values()))
        or system_data.credentials
    ):
        leak.systems_data.append(system_data)

    return count


def process_archive(
    logger: VerboseLogger, leak: Leak, archive: ArchiveWrapper
) -> None:
    logger.info(f"Processing: {archive.filename} ...")

    files: list[LogFile] = generate_file_list(archive)
    index: int = 0

    try:
        while index < len(files):
            index += process_system_dir(logger, leak, archive, files[index:])

    except BadRarFile as err:
        raise BadRarFile(f"BadRarFile: {err}") from err

    except RuntimeError as err:  # The archive was closed.
        logger.error(err)

    else:
        logger.debug(
            f"Parsed '{leak.filename}' ({len(leak.systems_data)} systems)."
        )
