cd ./src/emp/emp-tool
rm -rf CMakeCache.txt
cmake .
make -j4
sudo make install

cd ../emp-ot
rm -rf CMakeCache.txt
cmake .
make -j4
sudo make install

cd ../emp-sh2pc
rm -rf CMakeCache.txt
cmake .
make -j4
sudo make install