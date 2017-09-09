CXX=g++ -std=c++11
CFLAGS=-Wall -Werror -g
LDFLAGS=$(CFLAGS)

TARGETS=proj2

all: $(TARGETS)

proj2: proj2.cpp
	$(CXX) $(CFLAGS) -o $@ $<

%.o: %.cpp
	$(CXX) $(CFLAGS) -c $<

clean:
	rm -f *.o
	rm -f my.out

distclean: clean
	rm -f $(TARGETS)
