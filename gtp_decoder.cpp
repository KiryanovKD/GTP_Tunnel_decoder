#include "stdlib.h"
#include "Packet.h"
#include "EthLayer.h"
#include "PayloadLayer.h"
#include "PcapFileDevice.h"
#include <fstream>
#include <iostream>
#include <string>
#include <getopt.h>


static struct option GTP_decoder_options[] =
{
	{"input-file",  required_argument, 0, 'i'},
	{"output-file", required_argument, 0, 'w'},
	{"version", no_argument, 0, 'v'},
    {0, 0, 0, 0}
};

void parse_file(std::string readPacketsFromPcapFileName, std::string savePacketsToFileName){
	// open a pcap file for reading
    pcpp::PcapFileReaderDevice reader(readPacketsFromPcapFileName.c_str());
    if (!reader.open())
    {
        printf("Error opening the pcap file\n");
        return;
    }
    pcpp::PcapFileWriterDevice writer(savePacketsToFileName.c_str());
	writer.open();

    pcpp::RawPacket rawPacket;

    u_int8_t magic_bin = 0b00010000;

    u_int8_t data[4000];

   
    while(reader.getNextPacket(rawPacket))
   	{
    	pcpp::Packet parsedPacket(&rawPacket);
    	pcpp::Packet resultPacket(100);

    	if((*parsedPacket.getLastLayer()->getData() & magic_bin) == 0)
   			continue;

        pcpp::Layer *Eth = parsedPacket.detachLayer(pcpp::Ethernet);


    	if(*(Eth->getData()+Eth->getDataLen()-2) != 0x81 || *(Eth->getData()+Eth->getDataLen()-1) != 0x00)
        	continue;

        *(Eth->getData()+Eth->getDataLen()-2) = 0x08;


        
       // u_int8_t *data = new u_int8_t[(int)parsedPacket.getLastLayer()->getDataLen()];
        parsedPacket.getLastLayer()->copyData(data);


 		//printf("%s\n", );

        int ipv4_start = 0;
 		for(ipv4_start = 0; ipv4_start < (int)parsedPacket.getLastLayer()->getDataLen()-1; ipv4_start++){
 			if(data[ipv4_start] == 0x45 && data[ipv4_start+1] == 0x00){
 				pcpp::PayloadLayer newPayload(&data[ipv4_start], ((int)parsedPacket.getLastLayer()->getHeaderLen()-ipv4_start), true);
        		resultPacket.addLayer(Eth);
        		resultPacket.addLayer(&newPayload);
        		break;
 			}
 		}
 		if(ipv4_start > (int)parsedPacket.getLastLayer()->getDataLen()-2)
 			continue;

       // delete[] data;
        //delete Eth;

       // data = NULL;
       // Eth = NULL;
		writer.writePacket(*(resultPacket.getRawPacket()));

	}


    // close the file
    reader.close();
    writer.close();

}

int main(int argc, char* argv[])
{


	std::string readPacketsFromPcapFileName = "";
	std::string savePacketsToFileName = "";

	int optionIndex = 0;
	char opt = 0;

	while((opt = getopt_long (argc, argv, "i:w:v", GTP_decoder_options, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
				break;
			case 'i':
				readPacketsFromPcapFileName = optarg;
				break;
			case 'w':
				savePacketsToFileName = optarg;
				break;
			case 'v':

				break;
			default:
				break;
		}
	}

	parse_file(readPacketsFromPcapFileName, savePacketsToFileName);


	return 0;
}