#ifndef HELP_H
#define HELP_H


typedef struct tar_t
{                              /* byte offset */
    char name[100];               /*   0 */
    char mode[8];                 /* 100 */
    char uid[8];                  /* 108 */
    char gid[8];                  /* 116 */
    char size[12];                /* 124 */
    char mtime[12];               /* 136 */
    char chksum[8];               /* 148 */
    char typeflag;                /* 156 */
    char linkname[100];           /* 157 */
    char magic[6];                /* 257 */
    char version[2];              /* 263 */
    char uname[32];               /* 265 */
    char gname[32];               /* 297 */
    char devmajor[8];             /* 329 */
    char devminor[8];             /* 337 */
    char prefix[155];             /* 345 */
    char padding[12];             /* 500 */
} tar_t ;

#define ARCHIVE_NAME "archive.tar" 

#define END_OF_ARCHIVE 2 * 512

unsigned int calculate_checksum(tar_t* entry);
void generateHeader(tar_t* header);
void generateTar(tar_t* header, char* data, size_t dataSize, char* endBytes, size_t endSize, int append);
#endif /* HELP_H */