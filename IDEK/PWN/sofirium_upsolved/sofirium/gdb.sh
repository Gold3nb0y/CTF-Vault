target remote localhost:1234
# ONLY IF KASLR IF OFF
add-symbol-file chall.ko (0xffffffffc0000000)
