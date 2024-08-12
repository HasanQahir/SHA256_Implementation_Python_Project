import hash_functions as hash

#? SHA-256 following pseudocode explanation on wikipedia
#_  https://en.wikipedia.org/wiki/SHA-2#Pseudocode


original_message = input("Enter some text to be hashed:  ")
hashed_message = hash.SHA256_hashing(original_message)
print(f"The original message was {original_message} with length {len(original_message)}")
print(f"After hashing, it became {hashed_message} with length {len(hashed_message)}")
