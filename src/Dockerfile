# Use the latest Ubuntu image
FROM ubuntu:latest

# Install required dependencies
RUN apt-get update && apt-get install -y \
    g++ \
    make \
    cmake \
    libssl-dev \ 
    pkg-config \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy source files
COPY . /app

# Compile with OpenSSL 1.1.1 and C++17
RUN g++ -std=c++17 -O2 -Wno-deprecated-declarations \
    -I include \
    -o fileserver \
    src/main.cpp src/shell.cpp src/fs_utils.cpp src/encrypted_fs.cpp src/crypto_utils.cpp \
    src/user_metadata.cpp src/shared_metadata.cpp src/sharing_key_manager.cpp src/utils.cpp \
    -lssl -lcrypto

# Set default command (change as needed)
CMD ["/bin/bash"]