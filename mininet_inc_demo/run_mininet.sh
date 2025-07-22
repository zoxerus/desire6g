#!/bin/bash
source ~/.bashrc
# get path to this file and change to it's directory so it can be called
# from any folder.
SCRIPT_PATH="${BASH_SOURCE[0]:-$0}";
cd "$( dirname -- "$SCRIPT_PATH"; )";

# compile the p4 files before starting
sudo ./p4app/compile.sh

# path to the switch control CLI in order to set the flow rules and other
# control parameters of the switch.
#PATH_CLI="../../../behavioral-model-main/targets/simple_switch/simple_switch_CLI"
PATH_CLI="/usr/bin/simple_switch_CLI"

# path to the executable switch file, in order to start the switch.
#PATH_BEHAVIORAL="../../../behavioral-model-main/targets/simple_switch/simple_switch"
PATH_BEHAVIORAL="/usr/bin/simple_switch"

# path to the network and collector siwtches
PATH_NETSW="./p4app/p4out/inc_switch.json"


# clear the mininet cash
sudo mn -c


# Enable Job Control. This allows the script to use 'fg'.
set -m

# start the relevant mininet in the background
echo -e "\n\nStarting Mininet\n\n"
sudo python3 $(pwd)/mininet/mynet.py --behavioral-exe "$PATH_BEHAVIORAL" --json-net "$PATH_NETSW" --json-collector "./p4app/p4out/dpac.json" &
sleep 2


# a delay to wait for the mininet process, and for the switches to start
echo -e "\n\nWaiting for 5 seconds for mininet to start and switches to run...\n\n"
sleep 5

SOURCE_COMMANDS_DIR="./cli_commands"
OUTPUT_COMMANDS_DIR="./cli_commands/output"
PREFIX="switch"
SUFFIX=".sh"

echo "Searching for files in '${SOURCE_COMMANDS_DIR}' with prefix '${PREFIX}'..."

for file in "${SOURCE_COMMANDS_DIR}/${PREFIX}"*"${SUFFIX}"
do
  # This is a safety check to ensure we only process actual files
  # and skip if no files match the pattern.
  if [ -f "$file" ]; then
    echo -e "Processing file: $file"
    # Extract the number by removing the prefix from the filename string.
    # This is called "Parameter Expansion". ${variable#pattern} removes
    # the 'pattern' from the beginning of the 'variable'.
    filename_only=$(basename "$file")
    dest_file="${OUTPUT_COMMANDS_DIR}/${filename_only}"

    temp="${filename_only#$PREFIX}"
    number="${temp%$SUFFIX}"

    # Use grep to filter the file:
    # -v : Invert match, i.e., select non-matching lines.
    # -e : Allows specifying multiple patterns.
    # '^$' : Matches empty lines (start of line followed immediately by end of line).
    # '^#' : Matches lines that start with a '#' symbol.
    # The '>' redirects the filtered output to the new destination file.
    grep -v -e '^$' -e '^#' "$file" > "$dest_file"

    echo -e "\n\n\nRunning Commands in $filename_only: \n"
    python3 $PATH_CLI --thrift-port 909$number < $dest_file

  fi
done

echo -e "Done Running CLI Commands\n\n\n\n\n"

# Using fg to bring back the mininet CLI to the foreground
fg %1
