all: hkdf

clean:
	rm -f hkdf

hkdf: hkdf.cc
	clang++ -std=c++17 -I /usr/local/Cellar/openssl@3/3.0.1/include -L /usr/local/Cellar/openssl@3/3.0.1/lib -ohkdf hkdf.cc -lcrypto
