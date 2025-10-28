import sys

"""
    Convert a SID (Security Identifier) from hexadecimal string format 
    to the standard string representation (S-R-I-S...).
    
    Args:
        hexstr (str): Hexadecimal string representation of a SID
        
    Returns:
        str: Standard string representation of the SID (S-R-I-S...)
        
"""

def sid2str(hexstr):
    
    try:
        # Convert hex string to bytes
        b = bytes.fromhex(hexstr)
        
        # Check minimum length: revision(1) + subcount(1) + ident_auth(6) = 8 bytes
        if len(b) < 8:
            raise ValueError(f"SID data too short: expected at least 8 bytes, got {len(b)} bytes")

        # First byte is the revision number
        rev = b[0]
        
        # Second byte is the number of sub-authorities
        subcnt = b[1]
        
        # Verify the data length matches the expected structure
        expected_length = 8 + (subcnt * 4)  # header(8) + sub-authorities(subcnt * 4)
        if len(b) < expected_length:
            raise ValueError(f"SID data incomplete: expected {expected_length} bytes for {subcnt} sub-authorities, but got {len(b)} bytes")
        
        # Next 6 bytes represent the identifier authority (big-endian)
        ident_auth = int.from_bytes(b[2:8], byteorder='big')
        
        # Parse sub-authorities (each is 4 bytes, little-endian)
        subs = []
        i = 8  # Start index for sub-authorities
        for _ in range(subcnt):
            subs.append(int.from_bytes(b[i:i+4], byteorder='little'))
            i += 4

        # Build the standard SID string format: S-R-I-S1-S2-...
        sid = f"S-{rev}-{ident_auth}" + ''.join(f"-{s}" for s in subs)
        return sid
        
    except ValueError as e:
        # Re-raise with more context for hex conversion errors
        if "non-hexadecimal number found" in str(e):
            raise ValueError(f"Invalid hexadecimal string: '{hexstr}'") from e
        elif "odd-length string" in str(e):
            raise ValueError(f"Hexadecimal string has odd length: '{hexstr}'") from e
        else:
            raise ValueError(f"Invalid SID format: {e}") from e
    except Exception as e:
        # Catch any other unexpected errors
        raise ValueError(f"Unexpected error processing SID: {e}") from e


def main():
    """
    Main function to handle command line execution with proper error handling.
    """
    try:
        # Check if argument was provided
        if len(sys.argv) < 2:
            print("Usage: python sid2str.py <hex_sid>")
            print("Example: python sid2str.py 01020000000000052000000020020000")
            sys.exit(1)
            
        hex_sid = sys.argv[1]
        
        # Validate input is not empty
        if not hex_sid.strip():
            print("Error: Empty input string")
            sys.exit(1)
            
        # Convert and print the SID
        result = sid2str(hex_sid)
        print(result)
        
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()