from collections import namedtuple
import struct

__all__ = [ 'MsdsManagedPasswordBlob', 'decode_msds_managed_pw_blob' ]


MsdsManagedPasswordBlobHeader = namedtuple('MsdsManagedPasswordBlobHeader', 'version reserved length current_password_offset previous_password_offset query_password_interval_offset unchanged_password_interval_offset')

MsdsManagedPasswordBlob = namedtuple('MsdsManagedPasswordBlob', 'version current_password previous_password query_password_interval unchanged_password_interval')

def offset_length_slice(slice_obj, offset, length):
    return slice_obj[offset : (offset + length)]

def get_null_terminated_tchar_view(view, offset):

    length = 0
    while not (view[offset + length] == 0 and view[offset + length + 1] == 0):
        length = length + 2

    return offset_length_slice(view, offset, length)


def decode_msds_managed_pw_blob(blob_bytes):

    blob_view = memoryview(blob_bytes)

    msds_pw_blob_struct = struct.Struct('<HHIHHHH')
    blob_header = MsdsManagedPasswordBlobHeader._make(
        msds_pw_blob_struct.unpack(blob_view[: msds_pw_blob_struct.size])
    )

    current_password_bytes = get_null_terminated_tchar_view(
        blob_view,
        blob_header.current_password_offset
    ).tobytes()

    previous_password_bytes = get_null_terminated_tchar_view(
        blob_view,
        blob_header.previous_password_offset
    ).tobytes()

    query_password_interval_value = struct.unpack(
        '<Q',
        offset_length_slice(blob_view, blob_header.query_password_interval_offset, 8)
    )

    unchanged_password_interval_value = struct.unpack(
        '<Q',
        offset_length_slice(blob_view, blob_header.unchanged_password_interval_offset, 8)
    )

    msds_pw_blob = MsdsManagedPasswordBlob(
        version = blob_header.version,
        current_password = current_password_bytes.decode('utf_16_le', errors = 'replace'),
        previous_password = previous_password_bytes.decode('utf_16_le', errors = 'replace'),
        query_password_interval = query_password_interval_value[0] * 100, # convert 100-nanoseconds interval to nanoseconds
        unchanged_password_interval = unchanged_password_interval_value[0] * 100
    )

    return msds_pw_blob

