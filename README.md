[Canvas Project Description](https://canvas.sfu.ca/courses/88624/pages/bibifi-build-it-break-it-fix-it)

[![Scan and publish](https://github.com/CMPT785/BIBIFI/actions/workflows/scan_and_pub.yml/badge.svg)](https://github.com/CMPT785/BIBIFI/actions/workflows/scan_and_pub.yml)
    
**Run Code**:

- To run the executable in a docker container:

    ```bash
    docker build -t fileserver-image .
    docker run -it --rm fileserver-image
    ```
    
- To run as a standalone application (needs latest ubuntu):

    ```bash
     ./fileserver {user}_keyfile
    ```

**More commands**:
| Command Description | |
| -- | -- |
| `cd <directory>` | Changes directory, supporting . and .. for navigation. Prevents unauthorized access outside personal and shared directories. |
| `pwd` | Displays the current directory. |
| `ls` | Lists directory contents, distinguishing files `(f ->)` and directories `(d ->)`. | 
| `cat <filename>` | Displays the decrypted contents of a file. Returns an error if the file does not exist. |
| `share <filename> <username>` | Shares a file with another user, placing a read-only copy in their `shared/` directory. |
| `mkdir <directory_name>` | Creates a new directory. Errors if the directory already exists. |
| `mkfile <filename> <contents>` | Creates or updates a file. Updates propagate to shared copies.
| `exit` | Terminates the session. |
| `changepass <old_pass> <new_pass>` | To change the temporary password for any user |
