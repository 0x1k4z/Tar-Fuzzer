#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>


#include "help.h"


void generateHeader(tar_t* header) {

    memset(header, 0, sizeof(tar_t)); // reset buffer

    char random_name[60];
    int random_number;

    random_number = rand() % 100; // generate a random number between 0 and 99

    sprintf(random_name, "%d.txt", random_number); // format the random number as a string and store it in random_name
    strncpy(header->name, random_name, sizeof(header->name));
    strncpy(header->mode, "0644", sizeof(header->mode));
    strncpy(header->uid, "1001", sizeof(header->uid));
    strncpy(header->gid, "1001", sizeof(header->gid));
    snprintf(header->size, 12, "%011o", 0);
    snprintf(header->mtime, 12, "%011o", (unsigned int)time(NULL));
    snprintf(header->chksum, 8, "%07o", calculate_checksum(header));
    header->typeflag = '0';
    strncpy(header->linkname, "", sizeof(header->linkname));
    strncpy(header->magic, "ustar", sizeof(header->magic));
    strncpy(header->version, "00", sizeof(header->version));
    strncpy(header->uname, "root", sizeof(header->uname));
    strncpy(header->gname, "root", sizeof(header->gname));
    strncpy(header->devmajor, "", sizeof(header->devmajor));
    strncpy(header->devminor, "", sizeof(header->devminor));
    strncpy(header->prefix, "", sizeof(header->prefix));
    strncpy(header->padding, "", sizeof(header->padding));

}

void generateTar(tar_t* header, char* data, size_t dataSize, char* endBytes, size_t endSize, int append) {

    FILE *fp;
    char const openType[3] = "wb";
    if (append == 1){strcpy(openType, "ab");}
    
    fp = fopen(ARCHIVE_NAME, openType);
    if (fp != NULL) {
        
        // Write header
        fwrite(header, sizeof(tar_t), 1, fp);

        // Write data
        fwrite(data, dataSize, 1, fp);
        
        // Write the end bytes
        fwrite(endBytes, endSize, 1, fp);

    }else{
        printf("Error: cannot open file %s\n", ARCHIVE_NAME);
    }
    fclose(fp);
}


/**
 * This is the function given in help.c
 * 
 * 
 * @brief Computes the checksum for a tar header and encode it on the header
 * @param entry The tar header
 * @return the value of the checksum
 */
unsigned int calculate_checksum(tar_t* entry) {
    // use spaces for the checksum bytes while calculating the checksum
    memset(entry->chksum, ' ', 8);

    // sum of entire metadata
    unsigned int check = 0;
    unsigned char* raw = (unsigned char*) entry;
    for(int i = 0; i < 512; i++) {
        check += raw[i];
    }

    snprintf(entry->chksum, sizeof(entry->chksum), "%06o0", check);

    entry->chksum[6] = '\0';
    entry->chksum[7] = ' ';
    return check;
}
