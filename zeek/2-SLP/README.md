# Execute
To execute the custom scripts, run the following command from: 
```sh
zeek -C -r assignment_lecture10.pcap <folder>/<script>.zeek
```

# The Logs
The logs are excluded from being uploaded on GitHub, except for the "relevant" ones: for each type of
specific scan, usually we generate a specific log. That log needs then to be excluded in the .gitignore
in order to be uploaded.

## Difference
"Normal" logs should be every time eliminated, as they are very heavy. They are still stored in "0_normal-scan".
To check the difference between the logs generated between every scan and the "original" ones, run this command:
 
```sh
diff <(grep -v '^#' a/conn.log | cut -f1,3- | sort) <(grep -v '^#' b/conn.log | cut -f1,3- | sort)
```
