"""Wrapper to manipulate several types of archive."""
import posixpath
import os
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile
from typing import Generator, Union

from py7zr import SevenZipFile
from py7zr.exceptions import CrcError
from rarfile import RarFile


class ArchiveWrapper:
    _repr: str = (
        "{self.__class__.__name__}({self.root.filename!r}, {self.at!r})"
    )

    def __init__(
        self,
        root: RarFile | ZipFile | SevenZipFile,
        at: str = "",
        filename: str | None = None,
        password: str | None = None,
    ) -> None:
        self.root = root
        self.at = at
        self.password = password

        if filename:
            self.root.filename = filename
        elif not self.root.filename:
            raise ValueError("Missing archive's name.")

        if password and not isinstance(self.root, SevenZipFile):
            self.root.setpassword(bytes(password, encoding="utf-8"))

    def __str__(self) -> str:
        return posixpath.join(self.root.filename, self.at)

    def __repr__(self) -> str:
        return self._repr.format(self=self)

    @property
    def name(self) -> str:
        return Path(self.at).name or self.filename.name

    @property
    def filename(self) -> Path:
        return Path(self.root.filename).joinpath(self.at)

    def _is_child(self, path: "ArchiveWrapper") -> bool:
        return posixpath.dirname(path.at.rstrip("/")) == self.at.rstrip("/")

    def _next(self, at: str) -> "ArchiveWrapper":
        return self.__class__(self.root, at)

    def is_closed(self) -> bool:
        if isinstance(self.root, SevenZipFile):
            return not self.root._fileRefCnt
        if isinstance(self.root, ZipFile):
            return not self.root.fp
        if isinstance(self.root._rarfile, BytesIO):
            return self.root._rarfile.closed
        return not self.root._rarfile

    def is_dir(self) -> bool:
        return not self.at or self.at.endswith("/")

    def close(self) -> None:
        if isinstance(self.root, RarFile) and isinstance(
            self.root._rarfile, BytesIO
        ):
            self.root._rarfile.close()
        elif not self.is_closed():
            self.root.close()

    def namelist(self) -> list[str]:
        if isinstance(self.root, SevenZipFile):
            return [
                f"{elem.filename}/" if elem.is_directory else elem.filename
                for elem in self.root.files
            ]
        return self.root.namelist()

    def read_file(self, filename: str) -> str:
        try:
            if isinstance(self.root, SevenZipFile):
                texts = self.root.read([filename])
                self.root.reset()
                with texts[filename] as buffer:
                    file_bytes = buffer.getvalue()
            else:
                file_bytes = self.root.read(filename)

            try:
                text = file_bytes.decode(encoding="utf-8")
            except UnicodeDecodeError:
                text = file_bytes.decode(encoding="utf-8", errors="ignore")

            return text.replace("\x00", "\\00")

        except KeyError as err:
            raise KeyError("Not found.") from err
        except AttributeError as err:
            raise RuntimeError(f"Missing attribute: '{err}'.") from err
        except ValueError as err:
            raise RuntimeError(err) from err
        except CrcError as err:
            raise CrcError("Decompression error.") from err

    @staticmethod
    def find_archives(directory_path: Union[str, Path]) -> Generator[Path, None, None]:
        """Find all supported archive files in the given directory."""
        SUPPORTED_EXTENSIONS = ('.zip', '.rar', '.7z')
        directory = Path(directory_path)
        
        if directory.is_file() and directory.suffix.lower() in SUPPORTED_EXTENSIONS:
            yield directory
        elif directory.is_dir():
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = Path(root) / file
                    if file_path.suffix.lower() in SUPPORTED_EXTENSIONS:
                        yield file_path

    @classmethod
    def process_archives(
        cls,
        directory_path: Union[str, Path],
        output_file: Union[str, Path],
        password: str | None = None,
        file_extension: str | None = None,
        append: bool = True
    ) -> None:
        """Process all archives in directory and write contents to output file."""
        mode = 'a' if append else 'w'
        
        with open(output_file, mode, encoding='utf-8') as outfile:
            for archive_path in cls.find_archives(directory_path):
                try:
                    if archive_path.suffix.lower() == '.zip':
                        archive = ZipFile(archive_path)
                    elif archive_path.suffix.lower() == '.rar':
                        archive = RarFile(archive_path)
                    else:  # .7z
                        archive = SevenZipFile(archive_path)

                    wrapper = cls(archive, password=password)
                    
                    try:
                        outfile.write(f"\n=== Contents of {archive_path.name} ===\n")
                        
                        for filename in wrapper.namelist():
                            if not wrapper._next(filename).is_dir():
                                if file_extension and not filename.endswith(file_extension):
                                    continue
                                    
                                try:
                                    content = wrapper.read_file(filename)
                                    outfile.write(f"\n--- {filename} ---\n")
                                    outfile.write(content)
                                    outfile.write("\n")
                                except Exception as e:
                                    outfile.write(f"Error reading {filename}: {str(e)}\n")
                                    
                    finally:
                        wrapper.close()
                        
                except Exception as e:
                    outfile.write(f"Error processing {archive_path}: {str(e)}\n")