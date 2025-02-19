[Canvas Project Description](https://canvas.sfu.ca/courses/88624/pages/bibifi-build-it-break-it-fix-it)


Pre-requisite:

- Create an `admin_keyfile` in the `bin/` directory:
    
    ```bash
    cd bin/
    echo 'admin' > admin_keyfile
    ```
    
Run Code:

- To run the executable in a docker container:

    ```bash
    docker build -t fileserver-image .
    docker run -d fileserver-image
    docker run -it --rm fileserver-image
    ```

- To run as a standalone application:

    ```bash
    echo 'admin' > bin/admin_keyfile
    g++ -std=c++17 -O2 -I include -o bin/fileserver src/main.cpp src/shell.cpp src/fs_utils.cpp
    cd bin
    ./fileserver admin_keyfile
    ```



