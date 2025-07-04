#!/bin/bash
source ~/.bashrc
# get path to this sh file and change to it's directory so it can be called
# from any folder.
SCRIPT_PATH="${BASH_SOURCE[0]:-$0}";
cd "$( dirname -- "$SCRIPT_PATH"; )";

rm ./p4out/*


FOLDER="./p4src"
EXTENSION="p4"

compile_p4_files() {
    local filename="$1"
    echo "Compiling file: $filename"
    p4c --target bmv2 --arch v1model --std p4-16 --output ./p4out $filename
}

# Loop through all files with the given extension in the specified folder
for file in "$FOLDER"/*."$EXTENSION"; do
    # Check if file exists (in case there are no matches)
    [ -e "$file" ] || continue
    compile_p4_files "$file"
done