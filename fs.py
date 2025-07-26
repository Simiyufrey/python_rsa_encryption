
import os
import string


drives = [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]


print(drives)


skip_dirs = [
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData",
    r"C:\Users\Default",
    r"C:\$Recycle.Bin",
    r"C:\System Volume Information"
]

def should_skip(path):
    return any(path.startswith(skip) for skip in skip_dirs)


# Walk through each drive
# for drive in drives:
#     print(f"Scanning {drive} ...")
#     for root, dirs, files in os.walk(drive):
#         if should_skip(root):
#             dirs[:] = []
#             continue
#         for name in files:
#             file_path = os.path.join(root, name)
#             print(file_path)


def fast_scan(path):
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                if entry.is_dir(follow_symlinks=False):
                    if not should_skip(entry.path):
                        fast_scan(entry.path)
                else:
                    print(entry.path)
    except PermissionError:
        pass  # Skip directories you cannot access


for drive in drives:

    fast_scan(drive)