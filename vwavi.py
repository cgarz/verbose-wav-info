#!/usr/bin/env python3

from argparse import ArgumentParser
from enum import Flag, auto
from pprint import pp
import os, sys, pickle

# References:
#     https://wavefilegem.com/how_wave_files_work.html
#         http://www-mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/Docs/riffmci.pdf
#         http://www-mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/Docs/RIFFNEW.pdf
#         https://docs.microsoft.com/en-us/previous-versions/windows/hardware/design/dn653308(v=vs.85)
#         http://www-mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/WAVE.html
#     https://en.wikipedia.org/wiki/WAV
#     https://github.com/Zuzu-Typ/PyWave
#     https://www.recordingblogs.com/wiki/list-chunk-of-a-wave-file
#     https://www.recordingblogs.com/wiki/associated-data-list-chunk-of-a-wave-file
#     https://sites.google.com/site/musicgapi/technical-documents/wav-file-format
#     https://www.aelius.com/njh/wavemetatools/doc/riffmci.pdf
#     https://github.com/MediaArea/MediaInfoLib/blob/v20.09/Source/MediaInfo/Multiple/File_Riff_Elements.cpp#L2265
#     https://exiftool.org/TagNames/RIFF.html
#     http://www-mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/Docs/MMREG.H

# TODO: optionally display the description and name values from the chunk dict. or switch to just making them comments.
#       maybe just always add them to the wavs_info dict. then optionally show when printing with an argument.

RIFF_CHUNK_ID = b'RIFF'
WAVE_FORMAT_CODE = b'WAVE'

SAMPLE_FORMATS = {
    0x0001: 'Integer linear PCM / Uncompressed',
    0x0002: 'Microsoft Adaptive differential PCM (MS ADPCM)',
    0x0003: 'IEEE 754 floating point PCM',
    0x0006: 'ITU-T G.711 A-law',
    0x0007: 'ITU-T G.711 µ-law',
    0x0011: 'Interactive Multimedia Association adaptive differential PCM (IMA ADPCM)',
    0x0050: 'MPEG-1 Audio (MP2)',
    0x0055: 'MPEG Layer-III (MP3)',
    0xFFFE: 'WAVE_FORMAT_EXTENSIBLE'
}
GUID_SAMPLE_FORMATS = {f'{k:08X}-0000-0010-8000-00AA00389B71': v for k, v in SAMPLE_FORMATS.items() if k != 0xFFFE}

MPEGLAYER3_IDS = {
    0: 'Unknown',
    1: 'MPEG',
    2: 'Constant Frame Size'
}

MPEGLAYER3_FLAGS = {
    0: 'PADDING_ISO',
    1: 'PADDING_ON',
    2: 'PADDING_OFF'
}

WAVE_CHUNKS = {
    b'data': {
        'parser':  'parse_data_chunk',
        'printer': 'print_data_chunk',
        'description': 'contains the audio samples'
    },
    b'fact': {
        'parser':  'parse_fact_chunk',
        'printer': 'print_fact_chunk',
        'description': 'indicates how many sample frames are in the data chunk'
    },
    b'fmt ': {
        'parser':  'parse_format_chunk',
        'printer': 'print_format_chunk',
        'name':    'Format chunk',
        'description': 'specifies the encoding format of the data chunk samples'
    },
    b'LIST': {
        'description': 'contains a list or ordered sequence of subchunks, data type is determined by the subchunk id.',
        'types': {
            b'INFO': (list_info := {
                'parser':  'parse_info_chunk',
                'printer': 'print_info_chunk',
                'description': 'stores various metadata fields such as copyright info or title.'
            })
        }
    },
    b'INFO': list_info.copy()
}

INFO_IDS = {
    b'IARL': 'Archival Location',
    b'IART': 'Director',
    b'ICMS': 'Commissioned By',
    b'ICMT': 'Comment',
    b'ICOP': 'Copyright',
    b'ICRD': 'Recorded_Date',
    b'IENG': 'Encoded By',
    b'IGNR': 'Genre',
    b'IKEY': 'Keywords',
    b'IMED': 'Original Source Medium',
    b'INAM': 'Title',
    b'IPRD': 'Original Source Form Name',
    b'ISBJ': 'Subject',
    b'ISFT': 'Encoded Application',
    b'ISRC': 'Original Source Form Distributed By',
    b'ISRF': 'Original Source Form',
    b'ITCH': 'Encoded By',
    b'TCOD': 'Start Timecode',
    b'TCDO': 'End Timecode',
    b'IPRT': 'Track Number (UNOFFICIAL TAG)'
}


class Errors(Flag):
    NONE = 0
    FILE_NOT_FOUND = auto()
    NOT_RIFF_FILE = auto()
    NOT_WAVE_FILE = auto()
    PROCESSED_SIZE_MISMATCH = auto()
    INVALID_EXTENSION_SIZE = auto()
    UNKNOWN_EXTENSION_DATA = auto()
    MISSING_PADDING = auto()
    TRUNCATED = auto()
    DATA_BEYOND_RIFF = auto()
    CONCATENATED_WAV = auto()
    NO_FORMAT_CHUNK = auto()
    NO_DATA_CHUNK = auto()
    NO_FACT_CHUNK = auto()
    BYTE_RATE_MISMATCH = auto()
    BLOCK_ALIGN_MISMATCH = auto()
    FMT_AFTER_DATA = auto()
    INVALID_DATA_SAMPLE_COUNT = auto()


class ChannelMask(Flag):
    FRONT_LEFT = auto()
    FRONT_RIGHT = auto()
    FRONT_CENTER = auto()
    LOW_FREQUENCY = auto()
    BACK_LEFT = auto()
    BACK_RIGHT = auto()
    FRONT_LEFT_CENTER = auto()
    FRONT_RIGHT_CENTER = auto()
    BACK_CENTER = auto()
    SIDE_LEFT = auto()
    SIDE_RIGHT = auto()
    TOP_CENTER = auto()
    TOP_FRONT_LEFT = auto()
    TOP_FRONT_CENTER = auto()
    TOP_FRONT_RIGHT = auto()
    TOP_BACK_LEFT = auto()
    TOP_BACK_CENTER = auto()
    TOP_BACK_RIGHT = auto()
    RESERVED = 2**31


VALID_CHANNEL_BITS = sum(c.value for c in ChannelMask)


# # Just display the long form speaker identifiers instead. More verbose anyway.
# CHANNEL_IDS = dict(zip(
#     [c.name for c in ChannelMask],
#     'FL FR FC LFE BL BR FLC FRC BC SL SR TC TFL TFC TFR TBL TBC TBR'.split()
# ))

# Box drawing characters from https://www.compart.com/en/unicode/block/U+2500
SEP_LENGTH = 40
SEP_MAIN = '═' * (SEP_LENGTH-1)
SEP_TOP = '╔' + SEP_MAIN
SEP_BOT = '╚' + SEP_MAIN
SEP_CHUNK = '╟' + '─' * (SEP_LENGTH-1)
SEP_SIDE = '║ '
SEP_SIDE_HEX = '┊'


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def bytes_to_le_uint(bytes_):
    return int.from_bytes(bytes_, byteorder='little', signed=False)


def read_le_uint(file, length):
    return bytes_to_le_uint(file.read(length))


def read_be_uint(file, length):
    return int.from_bytes(file.read(length), byteorder='big', signed=False)


def read_le_sint(file, length):
    return int.from_bytes(file.read(length), byteorder='little', signed=True)


def functionify_wave_chunks(chunk_dict):
    # Convert the function name strings in the global chunk dict to actual functions since it's declared before them.
    # TODO: Look into other ways to do this. This way seems weird. Even though it's effective.
    for chunk_id, chunk_values in chunk_dict.items():
        if 'parser' in chunk_values:
            chunk_dict[chunk_id]['parser'] = eval(chunk_values['parser'])
        if 'printer' in chunk_values:
            chunk_dict[chunk_id]['printer'] = eval(chunk_values['printer'])
        if 'types' in chunk_values:
            functionify_wave_chunks(chunk_dict[chunk_id]['types'])


def hexdump(bytes_):
    printable_chars_map = ''.join(chr(c) if len(repr(chr(c))) == 3 else '⍰' for c in range(256))

    pad = ' ' * len(SEP_SIDE_HEX)
    print(f'{SEP_SIDE}_I  _0_1_2_3 _4_5_6_7 _8_9_A_B _C_D_E_F {pad}0123456789ABCDEF')
    for pos in range(0, len(bytes_), 16):
        bytes_chunk = bytes_[pos:pos+16]
        hex_line = ' '.join(bytes_chunk.hex()[i:i+8].upper() for i in range(0, len(bytes_chunk.hex()), 8))
        printable = ''.join(printable_chars_map[x] for x in bytes_chunk)
        print(f"{SEP_SIDE}{pos:02X}: {hex_line:<35s} {SEP_SIDE_HEX}{printable:<16}{SEP_SIDE_HEX}")


def size_humanize(size_bytes, more_style=False):
    unit_labels = ('KiB', 'MiB', 'GiB')

    if size_bytes < 1024:
        if more_style:
            return f'...Plus {size_bytes} {"byte" if size_bytes == 1 else "bytes"}'
        else:
            return f'{size_bytes} {"byte" if size_bytes == 1 else "bytes"}'

    size = size_bytes / 1024
    for unit_label in unit_labels:
        if size < 1024 - .00005:  # 5 * 10 ** -(precision+1)
            break
        if unit_label != unit_labels[-1]:
            size /= 1024
    size = f'{size:.4f}'.rstrip("0").rstrip(".")

    if more_style:
        return f'...Plus {size_bytes:,} more bytes ({size} {unit_label})'
    else:
        return f'{size_bytes:,} bytes ({size} {unit_label})'


def offset_humanize(offset):
    return f'{offset:,} (0x{offset:02X})'


def parse_data_chunk(wav_file, chunk_info):
    # TODO: maybe do something with at least uncompressed lpcm
    wav_file.seek(chunk_info['true_size'], os.SEEK_CUR)


def parse_fact_chunk(wav_file, chunk_info):
    chunk_info['sample_frame_count'] = read_le_uint(wav_file, 4)


def parse_format_chunk(wav_file, chunk_info):
    chunk_info.update({
        'format_code': (f_code := read_le_uint(wav_file, 2)),
        'format_name': SAMPLE_FORMATS.get(f_code, 'Unknown'),
        'channel_count': read_le_uint(wav_file, 2),
        'sample_rate':   read_le_uint(wav_file, 4),
        'byte_rate':     read_le_uint(wav_file, 4),
        'block_align':   read_le_uint(wav_file, 2),
        'bit_depth':     read_le_uint(wav_file, 2)
    })

    if chunk_info['true_size'] >= 18:
        chunk_info['extension_size'] = read_le_uint(wav_file, 2)

        if wav_file.tell() + chunk_info['extension_size'] != chunk_info['true_data_end_offset']:
            chunk_info['error_bitmask'] |= Errors.INVALID_EXTENSION_SIZE

        if chunk_info['extension_size'] == 0:
            return

        if chunk_info['format_code'] == 0x0002 and chunk_info['extension_size'] >= 32:  # MS ADPCM
            chunk_info.update({
                'samples_per_block': read_le_uint(wav_file, 2),
                'coefficient_count': (c_count := read_le_uint(wav_file, 2)),
                'coefficients': tuple((read_le_sint(wav_file, 2), read_le_sint(wav_file, 2)) for _ in range(c_count))
            })

        elif chunk_info['format_code'] == 0x0011 and chunk_info['extension_size'] >= 2:  # IMA ADPCM
            chunk_info['samples_per_block'] = read_le_uint(wav_file, 2)

        elif chunk_info['format_code'] == 0x0055 and chunk_info['extension_size'] >= 12:  # MP3
            chunk_info.update({
                'mp3_id': f'{(m_id := read_le_uint(wav_file, 2))}({MPEGLAYER3_IDS[m_id]})',
                'mp3_flags': f'{(m_flags := read_le_uint(wav_file, 4))}({MPEGLAYER3_FLAGS[m_flags]})',
                'block_size': read_le_uint(wav_file, 2),
                'frames_per_block': read_le_uint(wav_file, 2),
                'codec_delay': read_le_uint(wav_file, 2)
            })

        elif chunk_info['format_code'] == 0xFFFE and chunk_info['extension_size'] >= 22:  # WAVE_FORMAT_EXTENSIBLE
            chunk_info.update({
                'valid_bits': read_le_uint(wav_file,  2),
                'channel_bitmask': (c_mask := ChannelMask(read_le_uint(wav_file,  4) & VALID_CHANNEL_BITS)),
                'channels': ', '.join(c.name for c in ChannelMask if c in c_mask),
                'GUID': (guid := '{:08X}-{:04X}-{:04X}-{:04X}-{:012X}'.format(
                    read_le_uint(wav_file, 4), read_le_uint(wav_file, 2), read_le_uint(wav_file, 2),
                    read_be_uint(wav_file, 2), read_be_uint(wav_file, 6))),
                'GUID_name': GUID_SAMPLE_FORMATS.get(guid, 'Unknown')
            })

        else:
            chunk_info['error_bitmask'] |= Errors.UNKNOWN_EXTENSION_DATA
            if chunk_info['true_data_end_offset'] <= chunk_info['data_start_offset'] + chunk_info['true_size']:
                wav_file.seek(chunk_info['true_data_end_offset'], os.SEEK_SET)


def parse_info_chunk(wav_file, chunk_info):
    chunk_info['info_strings'] = {}
    end_pos = chunk_info['true_data_end_offset'] - 4
    while wav_file.tell() < end_pos:
        info_id = wav_file.read(4)
        info_size = read_le_uint(wav_file, 4)
        info_text = wav_file.read(info_size)
        # Size includes terminator. So since apparently it can be non null, trim last byte regardless. Then nulls.
        chunk_info['info_strings'][info_id] = info_text[:-1].rstrip(b'\x00')
        if info_size % 2 != 0 and (wav_file.tell() - chunk_info['data_start_offset'] < chunk_info['true_size']):
            padding = wav_file.read(1)
            # if padding and padding != b'\x00':
            #     # TODO: find out more about what padding can/should be
            #     # apparently padding isn't always 0 when inside an info chunk.
            #     wav_file.seek(-1, os.SEEK_CUR)


def parse_unknown_chunk(wav_file, chunk_info):
    seek_amount = chunk_info['true_size'] - 4 if 'type' in chunk_info else chunk_info['true_size']
    wav_file.seek(seek_amount, os.SEEK_CUR)


def chunks_parser(wav_file, info):
    while True:
        chunk_id = wav_file.read(4)
        if not chunk_id:
            break
        elif wav_file.tell() > info['data_end_offset']:
            wav_file.seek(-len(chunk_id), os.SEEK_CUR)
            info['error_bitmask'] |= Errors.DATA_BEYOND_RIFF
            break

        chunk_info = {
            'size': (size := read_le_uint(wav_file, 4)),
            'true_size': -1,
            'data_start_offset': (data_offset := wav_file.tell()),
            'data_end_offset': data_offset + size,
            'true_data_end_offset': data_offset + size,
            'error_bitmask': Errors.NONE
        }

        if chunk_info['data_end_offset'] > info['file_size']:
            chunk_info.update({
                'true_size': (t_size := size - (chunk_info['data_end_offset'] - info['file_size'])),
                'true_data_end_offset': data_offset + t_size
            })
            if (missing_bytes := chunk_info['data_end_offset'] - chunk_info['true_data_end_offset']) >= 1:
                if missing_bytes > 1 or chunk_info['true_size'] % 2 == 0:
                    chunk_info['error_bitmask'] |= Errors.TRUNCATED
        else:
            chunk_info['true_size'] = size

        chunk_parser = parse_unknown_chunk
        if chunk_id in WAVE_CHUNKS:
            if 'types' in WAVE_CHUNKS[chunk_id]:
                chunk_info['type'] = wav_file.read(4)
                if chunk_info['type'] in WAVE_CHUNKS[chunk_id]['types']:
                    chunk_parser = WAVE_CHUNKS[chunk_id]['types'][chunk_info['type']]['parser']
            else:
                chunk_parser = WAVE_CHUNKS[chunk_id]['parser']

        chunk_parser(wav_file, chunk_info)

        if Errors.TRUNCATED not in chunk_info['error_bitmask']:
            if (bytes_read := wav_file.tell() - chunk_info['data_start_offset']) != chunk_info['true_size']:
                chunk_info['error_bitmask'] |= Errors.PROCESSED_SIZE_MISMATCH
                wav_file.seek(chunk_info['true_size'] - bytes_read, os.SEEK_CUR)

            if chunk_info['true_size'] % 2 != 0:
                padding = wav_file.read(1)
                if padding == b'\x00':
                    chunk_info['true_data_end_offset'] += 1
                else:
                    chunk_info['error_bitmask'] |= Errors.MISSING_PADDING
                    if padding:
                        # Probably not needed. Chunks shouldn't start at odd bytes. But then again RIFF padding should
                        # always be a null byte so this should never be reached anyway, unless file is naughty or broken
                        wav_file.seek(-1, os.SEEK_CUR)

        info['chunks'][chunk_id] = chunk_info
    return info


def parse_wav(wav_file):
    info = {
        'path': wav_file.name,
        'file_size': os.path.getsize(wav_file.name),
    }

    if wav_file.read(4) == RIFF_CHUNK_ID and (rs_bytes := wav_file.read(4)):
        info.update({
            'riff_size': (r_size := bytes_to_le_uint(rs_bytes)),
            'data_start_offset': (data_offset := wav_file.tell()),
            'data_end_offset': data_offset + r_size
        })
    else:
        info['error_bitmask'] = Errors.NOT_RIFF_FILE
        return info

    info['type'] = wav_file.read(4)
    if not info['type'] == WAVE_FORMAT_CODE:
        info['error_bitmask'] = Errors.NOT_WAVE_FILE
        return info

    info.update({
        'sample_count': -1,
        'duration': 'unknown',
        'error_bitmask': Errors.CONCATENATED_WAV if wav_file.tell() > 12 else Errors.NONE,
        'chunks': {}
    })
    chunks_parser(wav_file, info)
    post_process_validate(info)

    if Errors.DATA_BEYOND_RIFF in info['error_bitmask']:
        if wav_file.read(4) == RIFF_CHUNK_ID and wav_file.read(4) and wav_file.read(4) == WAVE_FORMAT_CODE:
            wav_file.seek(-12, os.SEEK_CUR)
            info['concatenated_wav'] = parse_wav(wav_file)

    return info


def post_process_validate(info):
    if b'fmt ' not in info['chunks']:
        info['error_bitmask'] |= Errors.NO_FORMAT_CHUNK
        return

    fmt = info['chunks'][b'fmt ']
    if fmt['format_code'] == 1 or ('GUID' in fmt and fmt['GUID'] == '00000001-0000-0010-8000-00AA00389B71'):
        if b'data' in info['chunks']:
            info['sample_count'] = info['chunks'][b'data']['size'] // fmt['block_align'] * fmt['channel_count']
            if Errors.TRUNCATED not in info['chunks'][b'data']['error_bitmask']:
                if info['chunks'][b'data']['size'] % fmt['block_align'] != 0:
                    info['chunks'][b'data']['error_bitmask'] |= Errors.INVALID_DATA_SAMPLE_COUNT
        if fmt['byte_rate'] != fmt['block_align'] * fmt['sample_rate']:
            fmt['error_bitmask'] |= Errors.BYTE_RATE_MISMATCH
        #  ( int + 7 ) & (-8) = round up to the next multiple of 8
        if fmt['block_align'] != ( ( (fmt['bit_depth'] + 7) & (-8) ) / 8 ) * fmt['channel_count']:
            fmt['error_bitmask'] |= Errors.BLOCK_ALIGN_MISMATCH
    else:
        if b'fact' in info['chunks']:
            info['sample_count'] = info['chunks'][b'fact']['sample_frame_count'] * fmt['channel_count']
        else:
            info['error_bitmask'] |= Errors.NO_FACT_CHUNK

    if b'data' in info['chunks']:
        indexes = {key: idx for idx, key in enumerate(info['chunks'])}
        if indexes[b'fmt '] > indexes[b'data']:
            info['error_bitmask'] |= Errors.FMT_AFTER_DATA
    else:
        info['error_bitmask'] |= Errors.NO_DATA_CHUNK

    if info['sample_count'] != -1:
        secs = (info['sample_count'] / fmt['channel_count']) / fmt['sample_rate']
        if secs < 1:
            info['duration'] = f'{secs*1000:.3f} ms'
            return

        if secs < 60:
            info['duration'] = f'0:{secs:06.3f}'
            return

        mins, secs = divmod(secs, 60)
        if mins < 60:
            info['duration'] = f'{mins:.0f}:{secs:06.3f}'
            return

        hours, mins = divmod(mins, 60)
        info['duration'] = f'{hours:.0f}:{mins:02.0f}:{secs:06.3f}'


def pretty_printer(msg):
    label_max = max(len(label) for label, _ in msg)

    for line in msg:
        label, data = line
        print(f'{SEP_SIDE}{label:.<{label_max}}: {data}')


def print_data_chunk(_):
    return []


def print_fact_chunk(values):
    return [['Sample frame count', f'{values["sample_frame_count"]:,}']]


def print_format_chunk(values):
    msg = [
        ['Format code',   f'{values["format_code"]}'],
        ['Format name',   f'{values["format_name"]}'],
        ['Channel count', f'{values["channel_count"]}'],
        ['Sample rate',   f'{values["sample_rate"]:,} Hz']
    ]
    if values['sample_rate'] > 1000:
        msg[-1][-1] += f' ({str(values["sample_rate"] / 1000).rstrip("0").rstrip(".")} kHz)'

    msg += [
        ['Byte rate',   f'{size_humanize(values["byte_rate"])} / second'],
        ['Block align', f'{size_humanize(values["block_align"])} per frame'],
        ['Bit depth',   f'{values["bit_depth"]}']
    ]

    if 'extension_size' in values:
        msg += [['Extension size', f'{size_humanize(values["extension_size"])}']]
    else:
        return msg

    values_left = len(values) - (list(values.keys()).index('extension_size') + 1)
    if values['format_code'] == 0x0002 and values_left == 3:  # MS ADPCM
        msg += [
            ['Samples per block', f'{values["samples_per_block"]}'],
            ['Coefficient count', f'{values["coefficient_count"]}'],
            ['Coefficients',      f'{values["coefficients"]}']
        ]
        return msg

    elif values['format_code'] == 0x0011 and values_left == 1:  # IMA ADPCM
        msg += [('Samples per block', f'{values["samples_per_block"]}')]
        return msg

    elif values['format_code'] == 0x0055 and values_left == 5:  # MP3
        msg += [
            ['MP3 ids',          f'{values["mp3_id"]}'],
            ['MP3 flags',        f'{values["mp3_flags"]}'],
            ['Block size',       f'{values["block_size"]}'],
            ['Frames per block', f'{values["frames_per_block"]}'],
            ['Codec delay',      f'{values["codec_delay"]}']
        ]
        return msg

    elif values['format_code'] == 0xFFFE and values_left == 5:  # WAVE_FORMAT_EXTENSIBLE
        ch_bmask = f'{values["channel_bitmask"].value:032b}'
        msg += [
            ['Valid bits',       f'{values["valid_bits"]}'],
            ['Channel bitmask',  f'{" ".join(ch_bmask[i:i+4] for i in range(0, len(ch_bmask), 4))}'],  # nibble blobs
            ['Channels',         f'{values["channels"]}'],
            ['GUID string',      f'{values["GUID"]}'],
            ['GUID format name', f'{values["GUID_name"]}']
        ]

    return msg


def print_info_chunk(values):
    msg = []
    for info_id, info_text in values['info_strings'].items():
        try:
            info_text = info_text.decode()
        except UnicodeDecodeError:
            info_text = repr(info_text)[1:]

        if info_id in INFO_IDS:
            info_id = INFO_IDS[info_id]
        else:
            info_id = f'Unknown {repr(info_id)[1:]} tag'

        msg += [[info_id, info_text]]
    return msg


def chunks_printer(info):
    for chunk_name, chunk_values in info['chunks'].items():
        msg = []
        print(f'{SEP_CHUNK}')
        msg += [['Chunk Name', f'{repr(chunk_name)[1:]}']]
        if 'type' in chunk_values:
            msg[-1][-1] += f' (Type: {repr(chunk_values["type"])[1:]})'
        msg += [
            ['Size', f'{size_humanize(chunk_values["size"])}'],
            ['Data start', f'{offset_humanize(chunk_values["data_start_offset"])}'],
            ['Data end', f'{offset_humanize(chunk_values["data_end_offset"])}']
        ]

        if chunk_values['data_end_offset'] != chunk_values['true_data_end_offset']:
            msg[-1][-1] += f' (True end: {offset_humanize(chunk_values["true_data_end_offset"])})'

        chunk_printer = None
        try:
            chunk_printer = WAVE_CHUNKS[chunk_name]['types'][chunk_values['type']]['printer']
        except KeyError:
            try:
                chunk_printer = WAVE_CHUNKS[chunk_name]['printer']
            except KeyError:
                pass

        if chunk_printer is not None:
            msg += [['Known chunk', 'Yes']]
            msg += chunk_printer(chunk_values)
        else:
            msg += [['Known chunk', 'No']]

        if chunk_values['error_bitmask'] != Errors.NONE:
            msg.append(
                ['Errors', ", ".join(e.name for e in Errors if e in chunk_values["error_bitmask"] and e.value != 0)]
            )
        pretty_printer(msg)

        if chunk_printer is None and chunk_values['true_size'] > 1:
            read_amount = min(256, chunk_values['true_size'])
            msg = 'First 256 bytes of chunk data' if read_amount == 256 else 'Chunk data hexdump'
            print(f'{SEP_SIDE}\n{SEP_SIDE}{msg}:')
            with open(info['path'], 'rb') as f:
                f.seek(chunk_values['data_start_offset'], os.SEEK_SET)
                hexdump(f.read(read_amount))
                if (remaining := chunk_values['true_size'] - 256) > 0:
                    print(f'{SEP_SIDE}{size_humanize(remaining, more_style=True)}')


def print_wav(info):
    if Errors.FILE_NOT_FOUND in info['error_bitmask']:
        print('Unable to find a file at the path:', info['path'], sep='\n')
        return

    msg = []
    if Errors.CONCATENATED_WAV not in info['error_bitmask']:
        print(f'{SEP_TOP}')
        msg += [
            ['File path', f'{info["path"]}'],
            ['File size', f'{size_humanize(info["file_size"])}']
        ]

    if Errors.NOT_RIFF_FILE in info['error_bitmask']:
        msg += [['Errors', f'{", ".join(e.name for e in Errors if e in info["error_bitmask"] and e.value != 0)}']]
        pretty_printer(msg)
        print(f'{SEP_BOT}')
        return

    msg += [
        ['RIFF size',  f'{size_humanize(info["riff_size"])}'],
        ['RIFF type',  f'{repr(info["type"])[1:]}'],
        ['RIFF data start', f'{offset_humanize(info["data_start_offset"])}'],
        ['RIFF data end',   f'{offset_humanize(info["data_end_offset"])}']
    ]

    if info['data_end_offset'] > info['file_size']:
        msg[-1][-1] += f' (True end: {offset_humanize(info["file_size"])})'

    if info['sample_count'] >= 0:
        msg += [['Sample count', f'{info["sample_count"]:,}']]
        if b'fmt ' in info['chunks'] and info['chunks'][b'fmt ']['channel_count'] > 1:
            msg[-1][-1] += f' ({info["sample_count"] // info["chunks"][b"fmt "]["channel_count"]:,} frames)'
        msg += [['Duration', f'{info["duration"]}']]

    msg += [
        ['Chunk count', f'{len(info["chunks"]):,}'],
        ['Chunk list',  f'{", ".join(repr(chunk)[1:] for chunk in info["chunks"].keys())}']
    ]

    if info['error_bitmask'] != Errors.NONE:
        msg += [['Errors', f'{", ".join(e.name for e in Errors if e in info["error_bitmask"] and e.value != 0)}']]

    pretty_printer(msg)
    chunks_printer(info)

    if 'concatenated_wav' in info:
        print(f'{SEP_CHUNK}')
        print(f'{SEP_SIDE}Another wav was concatenated to the file:\n{SEP_SIDE}')
        print_wav(info['concatenated_wav'])
    elif Errors.DATA_BEYOND_RIFF in info['error_bitmask']:
        print(f'{SEP_CHUNK}')
        print(f'{SEP_SIDE}Extra data after RIFF block:')
        with open(info['path'], 'rb') as f:
            f.seek(info['data_end_offset'], os.SEEK_SET)
            hexdump(f.read(256))
        if (remaining := info['file_size'] - info['data_end_offset'] - 256) > 0:
            print(f'{SEP_SIDE}{size_humanize(remaining, more_style=True)}')

    if Errors.CONCATENATED_WAV not in info['error_bitmask']:
        print(f'{SEP_BOT}')


def main():
    parser = ArgumentParser(description='A tool to get detailed WAV file info')
    parser.add_argument('--raw', action='store_true', help='pprint the wavs_info object directly without processing')
    parser.add_argument('--no-border', action='store_true', help='Disable RIFF and chunk borders')
    parser.add_argument('--pickle', action='store_true', help='Change output format to a python pickle object')
    parser.add_argument('wav_paths', nargs='+', metavar='WAV_FILE_OR_FOLDER',
                        help='Path to wav file(s) or wav containing folder(s) (recursive *.WAV search)')
    args = parser.parse_args()

    if args.no_border:
        global SEP_TOP, SEP_BOT, SEP_CHUNK, SEP_SIDE
        SEP_TOP, SEP_BOT, SEP_CHUNK, SEP_SIDE = '', '', '', ''

    wav_files = []
    wavs_info = []
    dir_msg_printed = False
    for wav_path in args.wav_paths:
        if os.path.isfile(wav_path):
            wav_files.append(wav_path)
        elif os.path.isdir(wav_path):
            if not dir_msg_printed:
                eprint('Path is a directory, searching *.WAV.', end='', flush=True)
                dir_msg_printed = True
            wav_files += [
                os.path.join(root, file)
                for root, _, files in os.walk(wav_path)
                for file in files
                if file.upper().endswith('.WAV')
            ]
        else:
            wavs_info.append({'path': wav_path, 'error_bitmask': Errors.FILE_NOT_FOUND})
    if dir_msg_printed:
        eprint('..done')
    wav_files.sort()

    total = len(wav_files)
    if total > 1:
        count_width = len(str(total))
        msg_format_string = 'Processing wav: {i:{w}d} / {t}'
        padding = len(msg_format_string.format(i=0, w=count_width, t=total))

    for idx, wav_file in enumerate(wav_files):
        if total > 1:
            eprint(msg_format_string.format(i=idx, w=count_width, t=total), end='\r', flush=True)
        with open(wav_file, 'rb') as f:
            info = parse_wav(f)
        wavs_info.append(info)

    if total > 1:
        msg = f'{total} {"file" if total == 1 else "files"} processed.'
        eprint(msg.ljust(padding))

    if args.raw:
        pp(wavs_info)
    elif args.pickle:
        print(pickle.dumps(wavs_info, protocol=4))
    else:
        for wav in wavs_info:
            print_wav(wav)


functionify_wave_chunks(WAVE_CHUNKS)
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Got KeyboardInterrupt, quitting...')
        exit(0)
