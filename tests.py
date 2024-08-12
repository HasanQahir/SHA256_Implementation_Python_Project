import hash_functions as hash

test_var_pad = hash.padding("Hello World!")
print(len(test_var_pad)) #512


test_var_chunks = hash.chunks_512bits(test_var_pad)
print(len(test_var_chunks[0])) #512 bits each


test_var_arr = hash.create_msg_sch_arr(test_var_chunks[0])
print(len(test_var_arr[0])) #32 per entry


test_var_rot = hash.rrotate(test_var_arr[0], 12)
print(len(test_var_rot)) #32


test_var_shift= hash.rshift(test_var_arr[1], 12)
print(len(test_var_shift)) #32


test_var_xor = hash.xor(test_var_rot, test_var_shift)
print(f"0:  {test_var_rot}\n1:  {test_var_shift}\n2:  {test_var_xor}")
