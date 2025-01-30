apt install -y libmodsecurity-dev swig python3-dev
rm -rf build modsecurity.py modsecurity_wrap.* _modsecurity.*
swig -python -I/usr/include -o modsecurity_wrap.c modsecurity.i
python3 setup.py build_ext --inplace
