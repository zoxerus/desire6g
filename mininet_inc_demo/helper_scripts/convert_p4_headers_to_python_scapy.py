import sys
import re

def p4_to_scapy(p4_filename, scapy_filename):
    with open(p4_filename, 'r') as p4_file:
        lines = p4_file.readlines()

    class_name = None
    fields = []

    for line in lines:
        line = line.strip()
        if line.startswith('header '):
            # Extract class name, remove '_t', uppercase
            header_match = re.match(r'header\s+(\w+)_t', line)
            if header_match:
                class_name = header_match.group(1).upper()
        elif line.startswith('bit<'):
            # Extract bit size and field name
            field_match = re.match(r'bit<(\d+)>\s+(\w+);', line)
            if field_match:
                bit_size = int(field_match.group(1))
                field_name = field_match.group(2)
                fields.append((field_name, bit_size))

    with open(scapy_filename, 'w') as scapy_file:
        scapy_file.write(f'class {class_name}:\n')
        scapy_file.write(f'    name = "{class_name}"\n')
        scapy_file.write('    field_desc = [\n')
        for field_name, bit_size in fields:
            scapy_file.write(f'        BitField(name=\'{field_name}\', size={bit_size}),\n')
        scapy_file.write('    ]\n')

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <input_p4_file> <output_scapy_file>")
        sys.exit(1)
    p4_to_scapy(sys.argv[1], sys.argv[2])
