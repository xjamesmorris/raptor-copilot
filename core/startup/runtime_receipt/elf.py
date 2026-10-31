"""Bounded native ELF inspection using only descriptor reads."""

from __future__ import annotations

import errno
import os
import struct
from dataclasses import dataclass

from .collector_types import (
    DEFAULT_ELF_LIMITS,
    CollectionDisposition,
    CollectionFailure,
    CollectionReasonCode,
    CollectorElfClass,
    ElfInspection,
    ElfInterpreterAbsent,
    ElfInterpreterPresent,
    ElfLimits,
    EvidenceSubject,
    collection_failure,
    errno_class,
)
from .schema import AbsolutePath, Endianness, FormatId, Sha1


def _missing_pread(fd: int, size: int, offset: int) -> bytes:
    raise OSError(errno.ENOSYS, "pread unavailable")


_PREAD = getattr(os, "pread", _missing_pread)

_ELF_MAGIC = b"\x7fELF"
_EV_CURRENT = 1
_PN_XNUM = 0xFFFF
_PT_INTERP = 3
_PT_NOTE = 4
_NT_GNU_BUILD_ID = 3
_EM_X86_64 = 62
_ET_EXEC = 2
_ET_DYN = 3


@dataclass(frozen=True, slots=True)
class _ProgramHeader:
    segment_type: int
    offset: int
    file_size: int


class _ElfParseError(ValueError):
    def __init__(self, failure: CollectionFailure) -> None:
        super().__init__(failure.reason_codes[0].value)
        self.failure = failure


def _fail(
    disposition: CollectionDisposition,
    reason: CollectionReasonCode,
    *,
    stage: str,
    details: dict[str, object] | None = None,
) -> None:
    merged: dict[str, object] = {"stage": stage}
    if details:
        merged.update(details)
    raise _ElfParseError(
        collection_failure(
            disposition,
            reason,
            subject=EvidenceSubject.ELF,
            details=merged,
        )
    )


def _read_exact(fd: int, size: int, offset: int, file_size: int, stage: str) -> bytes:
    if size < 0 or offset < 0 or offset > file_size or size > file_size - offset:
        _fail(
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.ELF_BOUNDS_INVALID,
            stage=stage,
        )
    data = _PREAD(fd, size, offset)
    if len(data) != size:
        _fail(
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.ELF_BOUNDS_INVALID,
            stage=stage,
            details={"bytes": len(data)},
        )
    return data


def _parse_header(
    fd: int,
    file_size: int,
    limits: ElfLimits,
) -> tuple[
    CollectorElfClass,
    Endianness,
    int,
    int,
    int,
    tuple[_ProgramHeader, ...],
]:
    ident = _read_exact(fd, 16, 0, file_size, "elf_ident")
    if ident[:4] != _ELF_MAGIC or ident[6] != _EV_CURRENT:
        _fail(
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.ELF_INVALID,
            stage="elf_ident",
        )
    if ident[4] == 1:
        elf_class = CollectorElfClass.ELF32
        header_size = 52
        header_format = "HHIIIIIHHHHHH"
        program_header_size = 32
        program_header_format = "IIIIIIII"
    elif ident[4] == 2:
        elf_class = CollectorElfClass.ELF64
        header_size = 64
        header_format = "HHIQQQIHHHHHH"
        program_header_size = 56
        program_header_format = "IIQQQQQQ"
    else:
        _fail(
            CollectionDisposition.UNSUPPORTED_PLATFORM,
            CollectionReasonCode.ELF_LAYOUT_UNSUPPORTED,
            stage="elf_class",
        )
    if ident[5] == 1:
        endianness = Endianness.LITTLE
        prefix = "<"
    elif ident[5] == 2:
        endianness = Endianness.BIG
        prefix = ">"
    else:
        _fail(
            CollectionDisposition.UNSUPPORTED_PLATFORM,
            CollectionReasonCode.ELF_LAYOUT_UNSUPPORTED,
            stage="elf_data",
        )

    header = _read_exact(fd, header_size, 0, file_size, "elf_header")
    values = struct.unpack(prefix + header_format, header[16:])
    elf_type = values[0]
    machine = values[1]
    version = values[2]
    program_header_offset = values[4]
    elf_header_size = values[7]
    program_header_entry_size = values[8]
    program_header_count = values[9]
    if version != _EV_CURRENT or elf_header_size != header_size:
        _fail(
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.ELF_INVALID,
            stage="elf_header",
        )
    if program_header_count == _PN_XNUM:
        _fail(
            CollectionDisposition.UNSUPPORTED_PLATFORM,
            CollectionReasonCode.ELF_LAYOUT_UNSUPPORTED,
            stage="elf_program_headers",
        )
    if program_header_count > limits.program_headers:
        _fail(
            CollectionDisposition.LIMIT_EXCEEDED,
            CollectionReasonCode.ENTRY_LIMIT_EXCEEDED,
            stage="elf_program_headers",
            details={"count": program_header_count, "limit": limits.program_headers},
        )
    if program_header_entry_size < program_header_size:
        _fail(
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.ELF_INVALID,
            stage="elf_program_headers",
        )
    if program_header_entry_size > program_header_size:
        _fail(
            CollectionDisposition.UNSUPPORTED_PLATFORM,
            CollectionReasonCode.ELF_LAYOUT_UNSUPPORTED,
            stage="elf_program_headers",
        )
    table_size = program_header_entry_size * program_header_count
    if table_size > limits.program_header_table_bytes:
        _fail(
            CollectionDisposition.LIMIT_EXCEEDED,
            CollectionReasonCode.SIZE_LIMIT_EXCEEDED,
            stage="elf_program_headers",
            details={
                "bytes": table_size,
                "limit": limits.program_header_table_bytes,
            },
        )
    table = _read_exact(
        fd,
        table_size,
        program_header_offset,
        file_size,
        "elf_program_headers",
    )
    headers: list[_ProgramHeader] = []
    unpacker = struct.Struct(prefix + program_header_format)
    for index in range(program_header_count):
        start = index * program_header_entry_size
        values = unpacker.unpack(table[start : start + program_header_entry_size])
        if elf_class is CollectorElfClass.ELF32:
            segment_type = values[0]
            segment_offset = values[1]
            segment_file_size = values[4]
        else:
            segment_type = values[0]
            segment_offset = values[2]
            segment_file_size = values[5]
        if segment_offset > file_size or segment_file_size > file_size - segment_offset:
            _fail(
                CollectionDisposition.MALFORMED_INPUT,
                CollectionReasonCode.ELF_BOUNDS_INVALID,
                stage="elf_segment",
            )
        headers.append(
            _ProgramHeader(
                segment_type=segment_type,
                offset=segment_offset,
                file_size=segment_file_size,
            )
        )
    return (
        elf_class,
        endianness,
        ident[7],
        elf_type,
        machine,
        tuple(headers),
    )


def _parse_interpreter(
    fd: int,
    file_size: int,
    headers: tuple[_ProgramHeader, ...],
    limits: ElfLimits,
) -> ElfInterpreterPresent | ElfInterpreterAbsent:
    segments = tuple(header for header in headers if header.segment_type == _PT_INTERP)
    if not segments:
        return ElfInterpreterAbsent()
    if len(segments) != 1:
        _fail(
            CollectionDisposition.AMBIGUOUS,
            CollectionReasonCode.ELF_INTERPRETER_AMBIGUOUS,
            stage="elf_interpreter",
            details={"count": len(segments)},
        )
    segment = segments[0]
    if not 2 <= segment.file_size <= limits.interpreter_bytes:
        _fail(
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.ELF_INTERPRETER_PATH_INVALID,
            stage="elf_interpreter",
            details={"bytes": segment.file_size},
        )
    raw = _read_exact(
        fd,
        segment.file_size,
        segment.offset,
        file_size,
        "elf_interpreter",
    )
    if not raw.endswith(b"\0") or b"\0" in raw[:-1]:
        _fail(
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.ELF_INTERPRETER_PATH_INVALID,
            stage="elf_interpreter",
        )
    try:
        path = AbsolutePath(raw[:-1].decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ValueError):
        _fail(
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.ELF_INTERPRETER_PATH_INVALID,
            stage="elf_interpreter",
        )
    return ElfInterpreterPresent(
        path=path,
        offset=segment.offset,
        size_bytes=segment.file_size,
    )


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _parse_build_id(
    fd: int,
    file_size: int,
    headers: tuple[_ProgramHeader, ...],
    limits: ElfLimits,
    endianness: Endianness,
) -> Sha1 | None:
    prefix = "<" if endianness is Endianness.LITTLE else ">"
    total_note_bytes = 0
    note_count = 0
    build_ids: list[bytes] = []
    for header in headers:
        if header.segment_type != _PT_NOTE:
            continue
        total_note_bytes += header.file_size
        if total_note_bytes > limits.note_bytes:
            _fail(
                CollectionDisposition.LIMIT_EXCEEDED,
                CollectionReasonCode.SIZE_LIMIT_EXCEEDED,
                stage="elf_notes",
                details={"bytes": total_note_bytes, "limit": limits.note_bytes},
            )
        raw = _read_exact(
            fd,
            header.file_size,
            header.offset,
            file_size,
            "elf_notes",
        )
        cursor = 0
        while cursor < len(raw):
            if len(raw) - cursor < 12:
                _fail(
                    CollectionDisposition.MALFORMED_INPUT,
                    CollectionReasonCode.ELF_NOTE_MALFORMED,
                    stage="elf_notes",
                )
            name_size, description_size, note_type = struct.unpack(
                prefix + "III", raw[cursor : cursor + 12]
            )
            cursor += 12
            note_count += 1
            if note_count > limits.note_count:
                _fail(
                    CollectionDisposition.LIMIT_EXCEEDED,
                    CollectionReasonCode.ENTRY_LIMIT_EXCEEDED,
                    stage="elf_notes",
                    details={"count": note_count, "limit": limits.note_count},
                )
            name_end = cursor + name_size
            description_start = cursor + _align4(name_size)
            description_end = description_start + description_size
            next_cursor = description_start + _align4(description_size)
            if (
                name_end > len(raw)
                or description_end > len(raw)
                or next_cursor > len(raw)
            ):
                _fail(
                    CollectionDisposition.MALFORMED_INPUT,
                    CollectionReasonCode.ELF_NOTE_MALFORMED,
                    stage="elf_notes",
                )
            name = raw[cursor:name_end]
            description = raw[description_start:description_end]
            cursor = next_cursor
            if note_type == _NT_GNU_BUILD_ID and name.rstrip(b"\0") == b"GNU":
                if len(description) != 20:
                    _fail(
                        CollectionDisposition.UNSUPPORTED_PLATFORM,
                        CollectionReasonCode.ELF_BUILD_ID_UNSUPPORTED,
                        stage="elf_notes",
                        details={"bytes": len(description)},
                    )
                build_ids.append(description)
    if not build_ids:
        return None
    if any(value != build_ids[0] for value in build_ids[1:]):
        _fail(
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.ELF_NOTE_MALFORMED,
            stage="elf_notes",
        )
    return Sha1(build_ids[0].hex())


def _inspect(
    fd: int,
    *,
    file_size: int,
    limits: ElfLimits,
) -> ElfInspection:
    (
        elf_class,
        endianness,
        osabi,
        elf_type,
        machine,
        headers,
    ) = _parse_header(fd, file_size, limits)
    interpreter = _parse_interpreter(fd, file_size, headers, limits)
    build_id = _parse_build_id(fd, file_size, headers, limits, endianness)
    format_id: FormatId | None = None
    if (
        elf_class is CollectorElfClass.ELF64
        and endianness is Endianness.LITTLE
        and machine == _EM_X86_64
    ):
        if elf_type == _ET_EXEC:
            format_id = FormatId.ELF64_X86_64_EXEC
        elif elf_type == _ET_DYN:
            format_id = FormatId.ELF64_X86_64_DYN
    return ElfInspection(
        elf_class=elf_class,
        endianness=endianness,
        osabi=osabi,
        elf_type=elf_type,
        machine=machine,
        program_header_count=len(headers),
        interpreter=interpreter,
        build_id_sha1=build_id,
        format_id=format_id,
    )


def inspect_elf(
    fd: int,
    *,
    file_size: int,
    limits: ElfLimits = DEFAULT_ELF_LIMITS,
) -> ElfInspection | CollectionFailure:
    """Inspect a stable-size ELF descriptor without invoking external tools."""

    if (
        type(fd) is not int
        or type(file_size) is not int
        or not isinstance(limits, ElfLimits)
    ):
        raise TypeError("invalid ELF inspection argument type")
    if fd < 0 or file_size < 0:
        return collection_failure(
            CollectionDisposition.INVALID_REQUEST,
            CollectionReasonCode.INVALID_PATH,
            subject=EvidenceSubject.ELF,
            details={"stage": "elf_request"},
        )
    if getattr(os, "pread", None) is None:
        return collection_failure(
            CollectionDisposition.UNSUPPORTED_PLATFORM,
            CollectionReasonCode.OS_PRIMITIVE_UNAVAILABLE,
            subject=EvidenceSubject.ELF,
            details={"stage": "elf_request"},
        )
    try:
        return _inspect(fd, file_size=file_size, limits=limits)
    except _ElfParseError as exc:
        return exc.failure
    except OSError as exc:
        return collection_failure(
            CollectionDisposition.UNAVAILABLE,
            CollectionReasonCode.IO_ERROR,
            subject=EvidenceSubject.ELF,
            details={
                "stage": "elf_read",
                "errno_class": errno_class(exc.errno),
            },
        )
    except (UnicodeError, ValueError, struct.error, OverflowError):
        return collection_failure(
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.ELF_INVALID,
            subject=EvidenceSubject.ELF,
            details={"stage": "elf_parse"},
        )


def parse_elf_interpreter(
    fd: int,
    *,
    file_size: int,
    limits: ElfLimits = DEFAULT_ELF_LIMITS,
) -> ElfInterpreterPresent | ElfInterpreterAbsent | CollectionFailure:
    """Return the single bounded PT_INTERP observation, if present."""

    result = inspect_elf(fd, file_size=file_size, limits=limits)
    if isinstance(result, CollectionFailure):
        return result
    return result.interpreter


__all__ = [
    "inspect_elf",
    "parse_elf_interpreter",
]
