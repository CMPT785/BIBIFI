FROM debian:latest
WORKDIR /app
COPY . /app

# Debug: List all files in /app before setting permissions
RUN echo "Listing files in /app before chmod:" && ls -l /app

RUN apt-get update && apt-get install -y g++ make

RUN g++ -std=c++17 -O2 -I include -o fileserver src/main.cpp src/shell.cpp src/fs_utils.cpp
RUN g++ -std=c++17 -O2 -I include -o test_runner src/tests.cpp src/fs_utils.cpp

# Debug: Check if entrypoint.sh exists in the container
RUN echo "Checking if entrypoint.sh exists:" && ls -l /app/entrypoint.sh || echo "entrypoint.sh NOT FOUND!"

# Ensure entrypoint.sh has executable permissions
RUN chmod +x /app/entrypoint.sh

# Debug: List all files in /app after setting permissions
RUN echo "Listing files in /app after chmod:" && ls -l /app

ENTRYPOINT ["/app/entrypoint.sh"]
