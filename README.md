# sid2str.py

# SID Converter
A Python script to convert Security Identifiers (SIDs) from hexadecimal format to the standard string representation.

# Description
This tool converts Windows Security Identifiers (SIDs) from their raw hexadecimal representation to the human-readable string format (S-R-I-S1-S2-...). SIDs are used in Windows security to uniquely identify users, groups, and other security principals.

# Usage

```bash
python sid2str.py <hex_sid_string>
```

```bash
# Convert a Hex SID string
python sid2str.py 0105000000000005150000005b7bb0f398aa2245ad4a1ca451040000
```

# Expected Output
```
S-1-5-21-4088429403-1159899800-2753317549-1105
```

# SID Format Explanation
The standard SID format is: S-R-I-S1-S2-...

S: Prefix indicating a Security Identifier

R: Revision level (usually 1)

I: Identifier authority (48-bit value)

S1, S2, ...: Sub-authorities (variable number of 32-bit values)

# Common SID Examples
S-1-5-32-544: Built-in Administrators group

S-1-5-18: Local System account

S-1-5-11: Authenticated Users


# Integration with other tools
```bash
# Using with echo
echo "01020000000000052000000020020000" | xargs python sid2str.py

# Using in batch processing
for hex_sid in $(cat sid_list.txt); do
    python sid2str.py $hex_sid
done
```

# References
- [SID Components - Microsoft](https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-components)
- [Well-Known SIDs - Microsoft](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)

