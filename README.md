[Canvas Project Description](https://canvas.sfu.ca/courses/88624/pages/bibifi-build-it-break-it-fix-it)

To create executable and run locally in UNIX systems, run:

Navigate to Github Repo

g++ -std=c++17 -O2 -I include -o bin/fileserver src/main.cpp src/shell.cpp src/fs_utils.cpp

cd bin

echo "admin" > admin_keyfile

./fileserver admin_keyfile


in the bin directory, create a file called "admin_keyfile"
in the file, it should say "admin" inside (no quotes)

OR just run this

echo "admin" > admin_keyfile


To use with Docker:

docker build -t fileserver-image .

docker run -it --rm fileserver-image

OR to run in back ground

docker run -d fileserver-image



