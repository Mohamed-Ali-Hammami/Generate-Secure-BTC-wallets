import hashlib
import ecdsa
import base58
import bech32

address = "bc1qqnyt9pdsdx9uue6cwyjgcwxnl2les7lvu8t0ve"

# Decode the Bech32 address
decoded_address = bech32.decode('bc', address)
hrp, data = decoded_address

# Convert the data to a 5-bit binary string
bin_str = ""
for i in range(len(data)):
    bin_str += "{0:05b}".format(data[i])

# Convert the binary string to a hex string
hex_str = hex(int(bin_str, 2))[2:]

# Pad the hex string with leading zeros to 64 characters
hex_str = hex_str.zfill(64)

# Convert the hex string to a byte array
byte_array = bytearray.fromhex(hex_str)

# Generate a new private key
private_key = int.from_bytes(byte_array, byteorder="big")

# Get the corresponding public key
public_key = ecdsa.SigningKey.from_secret_exponent(private_key, curve=ecdsa.SECP256k1).verifying_key

# Get the uncompressed bytes of the public key
public_key_bytes = public_key.to_string("uncompressed")

# Hash the public key bytes with SHA-256
sha256_hash = hashlib.sha256(public_key_bytes)

# Hash the SHA-256 hash with RIPEMD-160
ripemd160_hash = hashlib.new("ripemd160")
ripemd160_hash.update(sha256_hash.digest())

# Add version byte to the RIPEMD-160 hash (0x00 for Bitcoin Mainnet)
version_ripemd160_hash = b"\x00" + ripemd160_hash.digest()

# Hash the versioned RIPEMD-160 hash twice with SHA-256
double_sha256_hash = hashlib.sha256(hashlib.sha256(version_ripemd160_hash).digest())

# Take the first 4 bytes of the double SHA-256 hash as the checksum
checksum = double_sha256_hash.digest()[:4]

# Concatenate the versioned RIPEMD-160 hash and the checksum
binary_address = version_ripemd160_hash + checksum

# Encode the binary address into base58
address = base58.b58encode(binary_address)

address_bytes = ripemd160_hash.digest()

# encode the address in Bech32 format using SegWit (P2WPKH) script type
encoded_address = bech32.encode('bc', 0, address_bytes)


print("Bitcoin Address (Bech32): ", encoded_address)
print("Private Key: ", hex(private_key))
print("Public Key: ", public_key_bytes.hex())
print("Bitcoin Address: ", address.decode('utf-8'))
