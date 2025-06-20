Largely conforms to MISRA C 2025 guidelines.

### Example
```
./set_wolfssl_up.sh
cd example
../gen_rsa_2048_h.sh first
../gen_rsa_2048_h.sh second
gcc ../src/*.c example.c -I../wolfssl-5.8.0/include -L../wolfssl-5.8.0/lib -lwolfssl -o example
LD_LIBRARY_PATH=../wolfssl-5.8.0/lib ./example
```
