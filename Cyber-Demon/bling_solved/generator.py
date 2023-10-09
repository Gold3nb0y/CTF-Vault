#!/usr/bin/env python3
import base64
import random
import subprocess

letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
################################################# REQUIRED CODE ################################################
include  = base64.b64decode("I2luY2x1ZGUgPHN0ZGlvLmg+CiNpbmNsdWRlIDx1bmlzdGQuaD4KI2luY2x1ZGUgPHN0cmluZy5oPgoK").decode()
art = base64.b64decode("""aW50IGFydCh2b2lkKSB7CgljaGFyICphcnQgPSAiICAgICAgICBcCgkJICAgICAgICAgICAgICBcblwKICAgICAgICAgICAgICAgICAgICAgIHwgICAgICAgICAgICAgXG5cCiAgICAgICAgICAgICAg
ICAgICAgICAgIHwgICAgICAgICAgIFxuXAogICAgICAgICAgICAgICAgICAgfCB8ICAgICAgICAgICAgICBcblwKICAgICAgIOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggHzioIDi
oIBv4qCAL+KggHzioIDioIDioIDioIDioIDioIDioIDioIAgXG5cCiAgICAgIOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggC9cXOKggOKggOKggOKggOKggOKg
gOKggOKggOKggOKggCBcblwKICAgICAg4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCAL1xc4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCAIFxuXAogICAg
ICDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIAgXG5cCiAgICAgIOKggOKggOKggOKggOKg
gOKggOKggOKjgOKjgOKjoOKjpOKjpOKjpOKjpOKjpOKjpOKjpOKjpOKjhOKjgOKjgOKggOKggOKggOKggOKggOKggOKggOKggCBcblwKICAgICAg4qCA4qCA4qKA4qOk4qO04qO+4qO/4qO/4qG/4qC/
4qC/4qC/4qCf4qCb4qCb4qC74qC/4qC/4qC/4qK/4qO/4qO/4qO34qOm4qOk4qGA4qCA4qCA4qCAIFxuXAogICAgICDiooDio7zio7/iob/ioJvioInioIHioIDioIDioIDioIDioIDioIDioIDioIDi
oIDioIDioIDioIDioIDioIDioIjioInioJvior/io7/io6fioYDioIAgXG5cCiAgICAgIOKiuOKhn+KggeKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKg
gOKggOKggOKggOKggOKgiOKiu+Khh+KggCBcblwKICAgICAg4qCI4qK74qOm4qGA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qKA4qO0
4qGf4qCB4qCAIFxuXAogICAgICDioIDioIDioIjioJvioLPioqbio6Tio4Tio4Dio4DioYDioIDioIDioIDioIDioIDioIDiooDio4Dio4Dio6Dio6TiobTioJ7ioJvioIHioIDioIDioIAgXG5cCiAg
ICAgIOKggOKggOKggOKggOKggOKggOKggOKgiOKgieKgmeKgm+Kgm+Kgm+Kgm+Kgm+Kgm+Kgm+Kgm+Kgi+KgieKgieKggOKggOKggOKggOKggOKggOKggOKggCBcblwKICAgICAg4qCA4qCA4qCA4qCA
4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCAICBcbiI7Cgl3cml0ZSgxLCBhcnQsIHN0cmxlbihhcnQpKTsKfQo=""").decode()

vuln = base64.b64decode("CmludCB2dWxuKHZvaWQpIHsJCgljaGFyIGJ1ZltzaXplMV0gPSB7MH07CgkKCXJlYWQoMCwgYnVmLCBzaXplMik7CglwcmludGYoYnVmKTsKCXJldHVybiAwOwp9Cg==").decode()
vuln = vuln.replace("size1", str(random.randrange(5, 100)))
vuln = vuln.replace("size2", str(random.randrange(5, 150)))

init = base64.b64decode("dm9pZCBpbml0KHZvaWQpIHsKCXNldHZidWYoc3RkaW4sTlVMTCxfSU9OQkYsMCk7CglzZXR2YnVmKHN0ZG91dCxOVUxMLF9JT05CRiwwKTsKCXNldHZidWYoc3RkZXJyLE5VTEwsX0lPTkJGLDApOwp9Cg==").decode()
main = base64.b64decode("aW50IG1haW4odm9pZCkgewoJaW5pdCgpOwoJYXJ0KCk7Cgl3aGlsZSgxKSB7CgkJcHJpbnRmKCI+PiAiKTsKCQl2dWxuKCk7CgkJcHV0cygiIik7Cgl9Cn0K").decode()

################################################# RANDOM JUNK CODE ################################################
p1 = base64.b64decode("ICBpbnQgdDEgPSAwLCB0MiA9IDEsIG5leHRUZXJtID0gMCwgbiA9IDEzMzc7CgogIG5leHRUZXJtID0gdDEgKyB0MjsKCiAgd2hpbGUgKG5leHRUZXJtIDw9IG4pIHsKICAgIHQxID0gdDI7CiAgICB0MiA9IG5leHRUZXJtOwogICAgbmV4dFRlcm0gPSB0MSArIHQyOwogIH0KCiAgcmV0dXJuIDA7Cg==").decode()
p2 = base64.b64decode("ICAgIGludCBpLCB6OwogICAgZm9yKGk9MTsgaTw9MTAwOyArK2kpCiAgICB7CiAgICAgICAgaWYgKGkgJSAzID09IDApCiAgICAgICAgICAgIHogPSAxOwogICAgICAgIGlmIChpICUgNSA9PSAwKQogICAgICAgICAgICB6ID0gMjsKICAgICAgICBpZiAoKGkgJSAzICE9IDApICYmIChpICUgNSAhPSAwKSkKICAgICAgICAgICAgeiA9IDM7CiAgICB9CgogICAgcmV0dXJuIDA7Cg==").decode()
p3 = base64.b64decode("CWludCBhID0gMDsKCWludCBiID0gMDsKCWludCBjID0gMDsKCXdoaWxlIChjIDwgMHgyMDApIHsKCQlhID0gYV5iOwoJCWIgPSBiPj4xOwoJCWMgKz0gMTsKCX0K").decode()
p4 = base64.b64decode("CWNoYXIgKmJbMTBdOwoKCWJbMV0gPSAiSCI7CgliWzNdID0gIkUiOwoJYls0XSA9ICJMIjsKCWJbNV0gPSAiTyI7CgliWzZdID0gIsKkIjsKCglpZiAoYls3XSA9PSAxNDQpIHsKCQlpbnQgeiA9IDA7CgkJeiA+PiAzOwoJfQoJaWYgKGJbMF0gIT0gYlszXSAmJiBiWzhdID4gMHgzMDAwKSB7CgkJY2hhciBhID0gMTsKCX0K").decode()
p5 = base64.b64decode("CV9fYXNtX18oIm1vdiBlYXgsIGVheCBcblx0IgogICAgICAgICJ4Y2hnIGVheCwgZWJ4XG5cdCIKICAgICAgICAic2hyIGVheCwgNVxuXHQiCiAgICAgICAgInBvcCByYXhcblx0IgogICAgICAgICJwb3AgcnNwXG5cdCIKICAgICAgICAieG9yIHJheCwgcjEyXG5cdCIKICAgICAgICAieGNoZyByYnAsIHJzcFxuXHQiKTsK").decode()
p6 = base64.b64decode("CWFzbSgiYWRkIGVieCwgZWR4XG5cdCBpbmMgZWN4XG5cdCBwb3AgcmF4XG5cciBzaHIgZWF4LCAzXG5cdGNtcCBCWVRFIFBUUiBbcmF4XSxhbCIpOwo=").decode()
p7 = base64.b64decode("CWFzbSgic2hyIHJicCwgNFxuXHR4b3IgcmJwLCAweDEzMzdcblx0eGNoZyByZHgsIHJicFxuXHRyZXQiKTsK").decode()
junk = [p1, p2, p3, p4, p5, p6]

####### helper functions
def generate_func(code):
    base = "int "
    base += "".join(random.choices(letters, k=random.randrange(4, 50)))
    base += "(void) {\n"
    base += code
    base += "\n}"
    return base

def randf():
    return generate_func(random.choice(junk))

#### Assemble
code = include
code += randf()
code += art
code += randf()
code += randf()
code += vuln
code += randf()
code += init
code += randf()
code += main
code += randf()

#### Write
bin_name = "/tmp/"+"".join(random.choices(letters, k=random.randrange(10, 20)))
with open(bin_name+".c", "w") as f:
    f.write(code)
    f.close()

#### Compile, clean, run
env = {"PATH": "/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin"}
subprocess.run(["gcc", bin_name+".c", "-o", bin_name, "-g", "-O0", "-fstack-protector-all","-Wl,-z,relro,-z,now", "-masm=intel", "-w", "-Wl,--rpath=/home/user/assets/glibc/", "-Wl,--dynamic-linker=/home/user/assets/glibc/ld-2.31.so"], env=env)


try:
    subprocess.run([bin_name], timeout=600)
except:
    print("Too slow!")
    pass

subprocess.run(["rm", bin_name])