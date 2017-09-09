#!/bin/bash
make
./proj3 -r sample-A.dmp -s | sort > my.out
echo "A-s diff:"
sort sample-A-s.out > A-s.sort
diff -u A-s.sort my.out
./proj3 -r sample-A.dmp -t | sort > my.out
echo "A-t diff:"
sort sample-A-t.out > A-t.sort
diff -u A-t.out my.out
./proj3 -r sample-A.dmp -p > my.out
echo "A-p diff:"
diff -u sample-A-p.out my.out
./proj3 -r sample-B.dmp -s | sort > my.out
echo "B-s diff:"
sort sample-B-s.out > B-s.sort
diff -u B-s.sort my.out
./proj3 -r sample-B.dmp -p > my.out
echo "B-p diff:"
diff -u sample-B-p.out my.out
./proj3 -r sample-B.dmp -t |sort > my.out
echo "B-t diff:"
sort sample-B-t.out > B-t.sort
diff -u B-t.sort my.out
./proj3 -r sample-C.dmp -s | sort > my.out
echo "C-s diff:"
sort sample-C-s.out > C-s.sort
diff -u C-s.sort my.out
./proj3 -r sample-C.dmp -t | sort > my.out
echo "C-t diff:"
sort sample-C-t.out > C-t.sort
diff -u C-t.sort my.out
./proj3 -r sample-C.dmp -p > my.out
echo "C-p diff:"
diff -u sample-C-p.out my.out
./proj3 -r sample-D.dmp -s | sort > my.out
echo "D-s diff:"
sort sample-D-s.out > D-s.sort
diff -u C-t.sort my.out
./proj3 -r sample-D.dmp -t > my.out
echo "D-t diff:"
diff -u sample-D-t.out my.out
./proj3 -r sample-D.dmp -p > my.out
echo "D-p diff:"
diff -u sample-D-p.out my.out
./proj3 -r sample-E.dmp -s > my.out
echo "E-s diff:"
diff -u sample-E-s.out my.out
./proj3 -r sample-E.dmp -t > my.out
echo "E-t diff:"
diff -u sample-E-t.out my.out
./proj3 -r sample-E.dmp -p > my.out
echo "E-p diff:"
diff -u sample-E-p.out my.out
./proj3 -r sample-F1.dmp -s > my.out
echo "F1-s diff:"
diff -u sample-F1-s.out my.out
diff -u sample-F1-i.out my.out
./proj3 -r sample-F1.dmp -t > my.out
echo "F1-t diff:"
diff -u sample-F1-t.out my.out
./proj3 -r sample-F1.dmp -p > my.out
echo "F1-p diff:"
diff -u sample-F1-p.out my.out
./proj3 -r sample-F2.dmp -s > my.out
echo "F2-s diff:"
diff -u sample-F2-s.out my.out
./proj3 -r sample-F2.dmp -t > my.out
echo "F2-t diff:"
diff -u sample-F2-t.out my.out
./proj3 -r sample-F2.dmp -p > my.out
echo "F2-p diff:"
diff -u sample-F2-p.out my.out
./proj3 -r sample-F3.dmp -s > my.out
echo "F3-s diff:"
diff -u sample-F3-s.out my.out
./proj3 -r sample-F3.dmp -t > my.out
echo "F3-t diff:"
diff -u sample-F3-t.out my.out
./proj3 -r sample-F3.dmp -p > my.out
echo "F3-p diff:"
diff -u sample-F3-p.out my.out
./proj3 -r sample-G.dmp -s > my.out
echo "G-s diff:"
diff -u sample-G-s.out my.out
./proj3 -r sample-G.dmp -t > my.out
echo "G-t diff:"
diff -u sample-G-t.out my.out
./proj3 -r sample-G.dmp -p > my.out
echo "G-p diff:"
diff -u sample-G-p.out my.out
make distclean
