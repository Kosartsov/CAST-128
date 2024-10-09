from Crypto.Cipher import CAST
from Crypto.Random import get_random_bytes

def cast_encrypt(key, data):
	cipher = CAST.new(key, CAST.MODE_ECB)
	encrypted_data = cipher.encrypt(data)
	return encrypted_data

def cast_decrypt(key, encrypted_data):
	cipher = CAST.new(key, CAST.MODE_ECB)
	decrypted_data = cipher.decrypt(encrypted_data)
	return decrypted_data

# Example usage
if __name__ == "__main__":
	# Generate a 16-byte random key (128-bit key)
	key = get_random_bytes(16)

	# Data to be encrypted
	original_data = b'This is the original data to be encrypted using CAST-128.'

	# Encrypt the data using the CAST-128 algorithm
	encrypted_data = cast_encrypt(key, original_data)

	# Decrypt the data using the same key
	decrypted_data = cast_decrypt(key, encrypted_data)

	print("Original Data:", original_data)
	print("Encrypted Data:", encrypted_data)
	print("Decrypted Data:", decrypted_data)
