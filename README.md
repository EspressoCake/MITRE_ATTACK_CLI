## MITRE ATT&CK CLI Search

#### Why:
There's flux between URLs for MITRE ATT&CK as different versions roll out (version 12.1 at time of writing). As such, the official repository for MITRE is a single-source of truth.

#### How:
This will attempt to look for a file of your choosing that should be the most current JSON file from their repo. If not, it is downloaded.

#### Compiliation:
```sh
go build -o 'CSATT&CK' main.go
```

#### Usage:
```sh
Usage of ./CSATT&CK:
  -file string
    	Location to JSON file to parse. (default "attack.json")
  -search string
    	Needle to search. Case-insensitive.
```

#### Sample Output:
```sh
operator$: ./CSATT\&CK -search 'dll.*hijack'
File attack.json not found. Downloading.
27191604 bytes written to attack.json

Name: DLL Search Order Hijacking
URL:  https://attack.mitre.org/techniques/T1574/001

Name: DLL Search Order Hijacking
URL:  https://attack.mitre.org/techniques/T1038

Name: DLL Search Order Hijacking Mitigation
URL:  https://attack.mitre.org/mitigations/T1038
```

#### To-Do:
- [ ] Hash validation to check for changes in remote `JSON`
  - [ ] Redownload if delta determined