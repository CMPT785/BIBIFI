[Canvas Project Description](https://canvas.sfu.ca/courses/88624/pages/bibifi-build-it-break-it-fix-it)

**Scan Status** <a href="https://scan.coverity.com/projects/cmpt785-bibifi-9f823095-7380-471a-87cd-be9e3801708f"> 
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/31394/badge.svg"/>
</a>

**Pre-requisites**:

- Create an `admin_keyfile` in the `bin/` directory:
    
    ```bash
    cd bin/
    echo 'admin' > admin_keyfile
    ```
> Note: A file has been created for you in this repository for convenience.
    
Run Code:

- To run the executable in a docker container:

    ```bash
    docker build -t fileserver-image .
    docker run -it --rm fileserver-image
    ```
    
- To run as a standalone application:

    ```bash
    g++ -std=c++17 -O2 -I include -o bin/fileserver src/main.cpp src/shell.cpp src/fs_utils.cpp
    cd bin
    ```

After these steps, you need to run 
    ```bash
     ./fileserver {user}_keyfile
     ```
     For example if you want to login as admin, run 
     ```bash
      ./fileserver admin_keyfile
      ```

For Unit test

```bash 
docker run --rm fileserver-image test

```