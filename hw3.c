#include<pcap.h>
#include<time.h>
#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<arpa/inet.h>

struct info{
	int num;
	char ip[200];
};
struct info count[1000];
int t=0;

void pcap_callback(u_char* arg,const struct pcap_pkthdr* pkthdr,const u_char* packet){

	int *id=(int *)arg,i;
	char tmp[200];
	memset(tmp,0,sizeof(tmp));
	
	printf("id: %d\n",++(*id));
	printf("Recieved time: %s",ctime((const time_t*)&pkthdr->ts.tv_sec));
	printf("MAC Address From: ");
	for(i=0;i<6;i++)printf("%02x ",packet[i]);
	printf("\n");
	printf("MAC Address To: ");
	for(i=6;i<12;i++)printf("%02x ",packet[i]);
	printf("\n");

	int type1=packet[12],type2=packet[13];
	if(type1==8&&type2==0){		// IP
		printf("Type: IP\n");
		
		printf("Source IP Address: ");		//ADDRESS	
		for(i=26;i<29;i++)printf("%d.",packet[i]);
		printf("%d\n",packet[29]);
		printf("Destination IP Address: ");
		for(i=30;i<33;i++)printf("%d.",packet[i]);
		printf("%d\n",packet[33]);
		
		printf("Protocol: ");		// PROTOCOL
		if(packet[23]==6)printf("TCP\n");
		else if(packet[23]==17)printf("UTP\n");
		else printf("Else\n");

		if(packet[23]==6||packet[23]==17){
			printf("Source port: %d\n",packet[34]*256+packet[35]);
			printf("Destination port: %d\n",packet[36]*256+packet[37]);}
			sprintf(tmp,"[%d.%d.%d.%d] to [%d.%d.%d.%d]",packet[26],packet[27],packet[28],packet[29],packet[30],packet[31],packet[32],packet[33]);
		
		
		int flag=1;
		for(i=0;i<t;i++){
			if(strcmp(count[i].ip,tmp)==0&&strlen(tmp)){
				flag=0;
				count[i].num++;
				break;
			}
		}
		if(flag&&strlen(tmp)){
			count[t].num=1;
			strcpy(count[t].ip,tmp);
			t++;
		}


	}
	printf("\n\n");
}

int main(int argc,char *argv[]){
	
	char errBuf[PCAP_ERRBUF_SIZE],*devStr,filename[100]="";
	memset(count,0,sizeof(count));
	devStr=pcap_lookupdev(errBuf);

	if(devStr){
		printf("Success: device: %s\n",devStr);
	}
	else{
		printf("Error: %s\n",errBuf);
		exit(1);
	}

	pcap_t *device=pcap_open_live(devStr,65535,1,0,errBuf);
	if(argc==3){
		if(strcmp(argv[1],"-r")==0){
			strcpy(filename,argv[2]);
			device=pcap_open_offline(filename,errBuf);
			if(!device){
				fprintf(stderr,"filename: %s\n",filename);
				fprintf(stderr,"pcap_open_offline(): %s\n",errBuf);
				exit(1);
			}
			printf("Open: %s\n",filename);
		}
		else{
			printf("Usage: \nsudo ./a.out -r pcapfile\n");
			return 0;
		}
	}

	int id=0,i;
	pcap_loop(device,-1,pcap_callback,(u_char*)&id);
	printf("-----------------------------------------------\n");
	for(i=0;i<t;i++)
		printf("%s  %d\n",count[i].ip,count[i].num);
	pcap_close(device);
	
return 0;
}
