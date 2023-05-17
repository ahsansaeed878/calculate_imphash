import os
import glob
import pefile

output_file = "imphash.txt"  # Name of the output file

with open(output_file, "w") as file:
    for file_path in glob.glob("**/*.exe", recursive=True):
        try:
            pe = pefile.PE(file_path)
            imphash = pe.get_imphash()
            file.write("File: {}\n".format(file_path))
            file.write("ImpHash: {}\n".format(imphash))
            file.write("-------------------------------------\n")
        except pefile.PEFormatError:
            file.write("Error: Invalid PE file format.\n")
        except Exception as e:
            file.write("Error: {}\n".format(str(e)))