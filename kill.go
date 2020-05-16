// killprocess project main.go
package main

import (
    "bytes"
    "fmt"
    "io"
    "io/ioutil"
    "log"
    "os"
    "path/filepath"
    "strconv"
    "strings"
)

var args []string

func findAndKillProcess(path string, info os.FileInfo, err error) error {
    if err != nil {
      log.Println(err)
        return nil
    }
    // We are only interested in files with a path looking like /proc/<pid>/status.
    if strings.Count(path, "/") == 3 {
        if strings.Contains(path, "/status") {

            // Let's extract the middle part of the path with the <pid> and
            // convert the <pid> into an integer. Log an error if it fails.
            pid, err := strconv.Atoi(path[6:strings.LastIndex(path, "/")])
            if err != nil {
                log.Println(err)
                return nil
            }
            // The status file contains the name of the process in its first line.
            // The line looks like "Name: theProcess".
            f, err := ioutil.ReadFile(path)
            if err != nil {
                log.Println(err)
                return nil
            }
            // Extract the process name from within the first line in the buffer
            name := string(f[6:bytes.IndexByte(f, '\n')])
            if name == args[1] {
                fmt.Printf("PID: %d, Name: %s will be killed.\n", pid, name)
                proc, err := os.FindProcess(pid)
                if err != nil {
                    log.Println(err)
                }
                // Kill the process
                proc.Kill()
                return io.EOF
            }
        }
    }
    return nil
}

// main is the entry point of any go application
func main() {
    args = os.Args
    if len(args) != 2 {
        log.Fatalln("Usage: killprocess <processname>")
    }
    fmt.Printf("trying to kill process \"%s\"\n", args[1])

    err := filepath.Walk("/proc", findAndKillProcess)
    if err != nil {
        if err == io.EOF {
            // Not an error, just a signal when we are done
            err = nil
        } else {
            log.Fatal(err)
        }
    }
}