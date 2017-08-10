tool to send http GET requests to a server requesting files 10.txt, ..., 10000000.txt
run as e.g.
`./benchmark localhost 4242 | grep -v 'HUBI' | grep -v "Message Hash" | grep -v "New Hash Chain Value"`

to get a csv output, where the first column is the file size and the other columns are the time in seconds from sending the request to receiving the full response
