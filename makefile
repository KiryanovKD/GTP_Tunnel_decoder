include /usr/local/etc/PcapPlusPlus.mk

# All Target
all:
	g++ $(PCAPPP_INCLUDES) -c -o gtp_decoder.o gtp_decoder.cpp
	g++ $(PCAPPP_LIBS_DIR) -o gtp_decoder gtp_decoder.o $(PCAPPP_LIBS)

# Clean Target
clean:
	rm gtp_decoder.o
	rm gtp_decoder