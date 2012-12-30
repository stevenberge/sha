CFLAGS = -fno-builtin-exit -fno-builtin-printf -fno-builtin-memcpy -fno-builtin-scanf -fno-builtin-strlen -fno-builtin-memset
all:sha1 sha256 sha512
sha1:sha1.o
	gcc  -o $@  $^ 
sha256:sha256.o
	gcc  -o $@  $^
sha512:sha512.o
	gcc  -o $@  $^
clean:
	rm *.o
