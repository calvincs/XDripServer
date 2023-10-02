#!/bin/bash

# Directory to hold the virtual environment
VENV_DIR="drip-venv"

# Check if the virtual environment already exists
if [ -d "$VENV_DIR" ]; then
  echo "Virtual environment already exists."
else
  echo "Creating virtual environment..."
  
  # Ensure that Python 3 and venv are installed
  command -v python3 >/dev/null 2>&1 || { echo >&2 "Python 3 required but not installed. Aborting."; exit 1; }
  python3 -m venv $VENV_DIR || { echo >&2 "Failed to create virtual environment. Aborting."; exit 1; }

  echo "Virtual environment created successfully."
fi

echo "Activating virtual environment..."
source $VENV_DIR/bin/activate

echo "Updating pip..."
pip install --upgrade pip || { echo >&2 "Failed to update pip. Aborting."; exit 1; }

echo "Installing packages from requirements.txt..."
if [ -f "requirements.txt" ]; then
  pip install -r requirements.txt || { echo >&2 "Failed to install packages from requirements.txt. Aborting."; exit 1; }
else
  echo "requirements.txt not found. Skipping installation."
fi

## WARNING!
# Export the DRIP_SECRET environment variable, this is for testing/demo ONLY
# - You should NOT load in your env variable via a file like this!

echo "Warning: You should not use the run.sh script to load the 'DRIP_SECRET' variable in production"
export DRIP_SECRET="example_secret_key"
export GRPC_VERBOSITY=debug

# Ensure proto files are compiled
echo "Compiling proto files..."
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. grpc_drip_server.proto

echo "Running main.py with virtual Python instance..."
python main.py
