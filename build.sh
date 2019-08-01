g++ -fPIC -std=c++11 LuaOpenPGP.cpp OpenPGPManager.cpp -shared -o bin/LuaOpenPGP.so -I/usr/include/lua5.2 -L/usr/local/lib/ -lOpenPGP -L/usr/lib/x86_64-linux-gnu -llua5.2 -v
cp -v bin/LuaOpenPGP.so /usr/local/lib/lua/5.2/
