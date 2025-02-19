FROM gcc:latest
WORKDIR /app
COPY . /app
RUN g++ -std=c++17 -O2 -I include -o fileserver src/main.cpp src/shell.cpp src/fs_utils.cpp
RUN echo "admin" > admin_keyfile
CMD ["./fileserver", "admin_keyfile"]