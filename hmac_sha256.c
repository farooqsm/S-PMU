#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h> 
#include <net/if.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

/* IEEE C37.118.2 data frame */ 
char sync_word1=0xAA;		/* Synchronization word 2 bytes  */
char sync_word2=0x82;       /* (1000 0010 => 1: security, 000: data frame, 0010: fixed for this standard) */

char frame_size1=0x00;		/* Total number of bytes in the frame, including CHK (2 bytes) 100 bytes */
char frame_size2=0x64;

char sa1=0x02; /* 0x02: AES-GCM256*/
               /* Encryption algorithms used AES128-GCM 0x01, AES256-GCM 0x02: IDcode to digital fields */
char sa2=0x03; /* 0x03: HMAC-SHA256 */
                  /* authentication algorithm used HMAC-SHA256 0x03 , None 0x00, HMAC-SHA256-80 0x01, HMAC-SHA256-128 0x02, 
                  AES-GMAC-64 0x04, AES-GMAC-128 0x05: From Sync to digital fields*/

char TimeofPresentKey1=0x5B;  /* hexadecimal timestamp/epoch */
char TimeofPresentKey2=0xFC;  /* Tuesday, November 27, 2018 4:48:00 PM */
char TimeofPresentKey3=0x5D;
char TimeofPresentKey4=0xA2;

char TimeofNextKey1=0xFC;
char TimeofNextKey2=0xA1; /* 60 minutes for time of next key */

char iv; /* no iv in HMAC-SHA256 */

char PMUID1=0x00;		/* PMU ID number 2 bytes*/
char PMUID2=0x3C;

char soc1=0x5E;			/* Seconds of century */
char soc2=0x00;
char soc3=0xB7;
char soc4=0x47;

char Time_quality_flag=0x00;	/* fraction of seconds 4 bytes*/
char fraction_of_seconds1=0x08;
char fraction_of_seconds2=0xd9;
char fraction_of_seconds3=0xa0;

char stat1=0x00; 		/* STAT 2 bytes*/
char stat2=0x00;

char phasors1=0x42;		/* phasors 24 bytes*/
char phasors2=0xc8;
char phasors3=0x27;
char phasors4=0xb9;
char phasors5=0xbf;
char phasors6=0xc8;
char phasors7=0x9e;
char phasors8=0xc2;

char phasors9=0x42;
char phasors10=0xc7;
char phasors11=0xe4;
char phasors12=0x79;
char phasors13=0x40;
char phasors14=0x27;
char phasors15=0xad;
char phasors16=0x27;

char phasors17=0x42;
char phasors18=0xc8;
char phasors19=0x05;
char phasors20=0x11;
char phasors21=0x3f;
char phasors22=0x06;
char phasors23=0xbe;
char phasors24=0xb0;

char freq_deviation1=0x00;	/* Frequency deviation nominal 2 bytes */
char freq_deviation2=0x00;

char rocof1=0x00;		/* rate of change of frequency 2 bytes*/
char rocof2=0x00;

char dsw1=0x00;			/* digital status word 2 bytes */
char dsw2=0x00;

//char signature[32]={};
char chksum1=0x1a;		/* check sum 2 bytes */ 		
char chksum2=0x9c;

int main(int argc, char *argv[])
{
    
    int j=0;
    unsigned char Data[100];
    unsigned char key[32]= { 
						0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66, 0x5f, 0x8a, 0xe6, 0xd1,
            0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69, 0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f 
			   };

    unsigned char *hash,hash_string[64];
    double begin,end,time_gen;
    /* The fields are input to HMAC-SHA256 algorithm to generate 32 bytes of HMAC value* 
    unsigned char signature_data[50]=
   				{
					  0x02, 0x03, 0x5B, 0xFC, 0x5D, 0xA2, 0xFC, 0xA1, 0x00, 0x3C, 
					  0x5E, 0x00, 0xB7, 0x47, 0x00, 0x08, 0xd9, 0xa0, 0x00, 0x00, 
            0x42, 0xc8, 0x27, 0xb9, 0xbf, 0xc8, 0x9e, 0xc2, 0x42, 0xc7, 
            0xe4, 0x79, 0x40, 0x27, 0xad, 0x27, 0x42, 0xc8, 0x05, 0x11,
            0x3f, 0x06, 0xbe, 0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
				}; 
    for ( j=0; j<50; j++)
    {
	       sprintf( &(Data[j * 2]) , "%02x", signature_data[j]); 
        //printf(" %s",Data); 
    }
	
    begin = clock();
    hash = HMAC(EVP_sha256(), key, strlen((char *)key), Data, strlen((char *) Data), NULL, NULL);
    end = clock();
    time_gen= (double)(end - begin) / CLOCKS_PER_SEC;
    printf("\n mac generation time =%lf\n",time_gen*1000);

    for (j = 0; j < 32 ; j++)
	  sprintf(&(hash_string[j * 2]), "%02x", hash[j]);
    printf("\n \n Hash value: %s \n", hash_string);
    return 0;
}
