#!/usr/bin/env python3

import struct # Struct is our friend
import uuid   # Format the GUID

f = open('C:\\Windows\\bootstat.dat', 'rb')

eventLevels = { 0:'BSD_EVENT_LEVEL_SUCCESS',
                1:'BSD_EVENT_LEVEL_INFORMATION',
                2:'BSD_EVENT_LEVEL_WARNING',
                3:'BSD_EVENT_LEVEL_ERROR'
}

eventCodes = {  0:'BSD_EVENT_END_OF_LOG',
                1:'BSD_EVENT_INITIALIZED',
                49:'BSD_OSLOADER_EVENT_LAUNCH_OS',
                80:'BSD_BOOT_LOADER_LOG_ENTRY'
}

applicationTypes = {1:'BCD_APPLICATION_TYPE_FIRMWARE_BOOT_MANAGER',
                    2:'BCD_APPLICATION_TYPE_WINDOWS_BOOT_MANAGER',
                    3:'BCD_APPLICATION_TYPE_WINDOWS_BOOT_LOADER',
                    4:'BCD_APPLICATION_TYPE_WINDOWS_RESUME_APPLICATION',
                    5:'BCD_APPLICATION_TYPE_WINDOWS_MEMORY_TESTER'}

# Format time into a human readable string
def format_time(b):
    return '%s-%02d-%02d %02d:%02d:%02d' % (b[1]*256+b[0], b[2], b[4], b[6], b[8], b[10])

header_size = 0x800
f.seek(header_size)
version, = struct.unpack('I', f.read(4))
print('Version:', version)

boot_log_start, = struct.unpack('I', f.read(4))
print('BootLogStart: 0x%04x' % boot_log_start)

boot_log_size, = struct.unpack('I', f.read(4))
print('BootLogSize: 0x%04x' % boot_log_size)

next_boot_log_entry, = struct.unpack('I', f.read(4))
print('NextBootLogEntry: 0x%04x' % next_boot_log_entry)

first_boot_log_entry, = struct.unpack('I', f.read(4))
print('FirstBootLogEntry: 0x%04x' % first_boot_log_entry)

overlap = True

# Check if the log is partially overwritten
if first_boot_log_entry > next_boot_log_entry:
    overlap = False
    print('Log partially overwritten due to its circular nature.')

current_pos = header_size + first_boot_log_entry

# Loop over records
boot_offsets = []
while(True):
    # Get the record start offset
    record_start = current_pos
    print('\n#########################################################')
    print('RecordStart: 0x%04x' % record_start)

    f.seek(current_pos)
    timestamp, = struct.unpack('Q', f.read(8))
    print('Timestamp:', timestamp)
    
    # Move to the GUID position
    f.seek(current_pos + 8)

    # Decode GUID:
    #   [----4 bytes----|----4 bytes-----|----------8 bytes------------]
    #   +--------------------------------------------------------------+
    #   | little-endian | little-endian  |         big-endian          |
    #   | unsigned long | unsigned short |       unsigned short        |
    #   +--------------------------------------------------------------+

    guid_hex = '%0.2X' % struct.unpack('<L', f.read(4))
    for i in range(0, 2):
        guid_hex += '%0.2X' % struct.unpack('<H', f.read(2))
    for i in range(0, 4):
        guid_hex += '%0.2X' % struct.unpack('>H', f.read(2))

    # Format the GUID
    guid = uuid.UUID(hex=guid_hex.strip())
    print('GUID: ', guid)
    current_pos += 16

    # Unpack some more data
    entry_size, = struct.unpack('I', f.read(4))
    print('EntrySize: %s' % entry_size)
    current_pos += 4

    level, = struct.unpack('I', f.read(4))
    print('Level: %s' % eventLevels[level])
    current_pos += 4

    app_type, = struct.unpack('I', f.read(4))
    print('ApplicationType: %s' % applicationTypes[app_type])
    current_pos += 4

    event_code, = struct.unpack('I', f.read(4))
    print('EventCode: %s' % eventCodes[event_code])
    current_pos += 4

    # Look for a boot entry id and time
    if (app_type == 3) and (event_code == 1):
        boot_date_time = f.read(16)
        time = format_time(boot_date_time)
        f.seek(f.tell()+8)
        last_boot_id, = struct.unpack('I', f.read(4))

        print('Boot entry found:')
        print('\tDateTime: ', time)
        print('\tLastBootID: ', last_boot_id)
        boot_offsets.append([record_start, time, last_boot_id, timestamp])

    current_pos = record_start + entry_size

    # No more records
    if overlap: 
        if current_pos >= (next_boot_log_entry + header_size):
            break

    # Check if the next entry doesn't fit
    if (current_pos + 28) > (boot_log_size + header_size):
        current_pos = header_size + boot_log_start
        overlap = True

    next_entry_size, = struct.unpack('I', f.read(4))

    # Check if the next record is empty
    if next_entry_size == 0:
        current_pos = header_size + boot_log_start
        overlap = True

print('\nOffset DateTime            LastBootId TimeStamp')
print('------ --------            ---------- ---------')
for record in boot_offsets:
    print('0x%04x %s          %d %d' % (record[0], record[1], record[2], record[3]))
