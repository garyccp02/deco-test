cd ./rustls/src/emp/emp-sh2pc/

rm -rf ./2pc_hmac/*.txt

echo "#include \"emp-sh2pc/semihonest.h\"" >| ./emp-sh2pc/emp-sh2pc.h
echo "#include \"emp-sh2pc/sh_party.h\"" >> ./emp-sh2pc/emp-sh2pc.h
echo "#include \"emp-sh2pc/sh_gen.h\"" >> ./emp-sh2pc/emp-sh2pc.h
echo "#include \"emp-sh2pc/sh_eva.h\"" >> ./emp-sh2pc/emp-sh2pc.h
echo "namespace emp {" >> ./emp-sh2pc/emp-sh2pc.h
echo "const static char * IP = \"$1\";" >> ./emp-sh2pc/emp-sh2pc.h
echo "}" >> ./emp-sh2pc/emp-sh2pc.h

make

exit 0