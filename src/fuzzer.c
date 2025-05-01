#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "help.h"

// count number of tests.
static int testNumber = 0;

// count number of crash files.
static int crash = 0;

static tar_t header;

void generateCrasherArchive(){
    char crashingFileName[100];
    snprintf(crashingFileName, 100, "success_archive%d.tar", crash);
    rename(ARCHIVE_NAME, crashingFileName);
}

int testExtractor(const char* extractor) {
    // Increment number of tests done.
    testNumber++;
    
    int rv = 0;
    char cmd[51];
    strncpy(cmd, extractor, 25);
    cmd[26] = '\0';
    strncat(cmd, " archive.tar", 25);
    char buf[33];
    FILE *fp;

    if ((fp = popen(cmd, "r")) == NULL) {
        printf("Error opening pipe!\n");
        return -1;
    }

    if(fgets(buf, 33, fp) == NULL) {
        printf("No output\n");
        goto finally;
    }

    if(strncmp(buf, "*** The program has crashed ***\n", 33)) {
        printf("Not the crash message\n");
        goto finally;
    } else {
        printf("Crash message\n");
        rv = 1;
        generateCrasherArchive();
        crash++;
        goto finally;
    }
    finally:
    if(pclose(fp) == -1) {
        printf("Command not found\n");
        rv = -1;
    }
    return rv;
}

void testNameField(const char* extractor) {
    printf("\nFuzzing on Name Field\n");

    char testNames[][110] = {
        "", // Empty name
        "hello.txt",  // Regular file name.
        "../../test", // File name with wrong directory
        "dir1/file2.txt", // File name with directory
        "file3_with_long_name_that_exceeds_100_characters_and_causes_buffer_overflow______________________.txt", // Long file name
        "file4_\\x00.txt", // File name with null byte
        "file5_\\\\.txt", // File name with escape characters
        "file6_\\123.txt", // File name with octal escape sequence
        "file7_\\xff.txt", // File name with hex escape sequence
        "file8_\\uD83D\\uDE00.txt", // File name with Unicode escape sequence
        "ðð@ßðđđßđŋßŋßŋħðßæ«¶«.txt", // File name with non ASCII characters.
    };

    int numTestNames = sizeof(testNames) / sizeof(testNames[0]);

    char testInput[] = "This should be crashed!";
    size_t testInputSize = strlen(testInput);

    generateHeader(&header); // generate standard headers

    for (int i = 0; i < numTestNames; i++) {
        snprintf(header.size, 12, "%011lo", testInputSize); 
        snprintf(header.name, 100, "%s", testNames[i]);
        calculate_checksum(&header);
        generateTar(&header, testInput, testInputSize, "", 0, 0); // test file with the testInput
        testExtractor(extractor);
    }

}

void testModeField(const char * extractor){
    generateHeader(&header); // generate standard headers
    char str[6];

    for (char c1 = '0'; c1 <= '7'; c1++) {
        for (char c2 = '0'; c2 <= '7'; c2++) {
            for (char c3 = '0'; c3 <= '7'; c3++) {
                for (char c4 = '0'; c4 <= '7'; c4++) {
                    for (char c5 = '0'; c5 <= '7'; c5++) {
                        str[0] = c1;
                        str[1] = c2;
                        str[2] = c3;
                        str[3] = c4;
                        str[4] = c5;
                        str[5] = '\0';
                        strncpy(header.mode, str, sizeof(header.mode));
                        calculate_checksum(&header);
                        generateTar(&header, "", 0, "", 0, 0); // test file without the testInput

                        if (testExtractor(extractor) == 1){
                            goto finally;
                        }
                    }
                }
            }
        }
    }
    finally:
    printf(header.mode);
}

void testSizeField(const char* extractor) {

    printf("\n---------------------------------------------------\n");
    printf("\nSize Field Fuzzing\n");

    int dataSize = 0;

    char testInput[] = "This should be crashed!";
    size_t testInputSize = strlen(testInput);

    generateHeader(&header);
    snprintf(header.size, 12, "%011lo", dataSize);
    calculate_checksum(&header);
    generateTar(&header, testInput, testInputSize, "", 0, 0);
    testExtractor(extractor);
    printf("\n---------------------------------------------------\n");
}

void testMtimeField(const char* extractor,char data[],size_t dataSize){
    generateHeader(&header); // generate standard headers
    time_t now = time(NULL);
    long long pastTime = now - (long long)(1000LL * 365 * 24 * 60 * 60); // 1000 years in seconds

    snprintf(header.mtime, 12, "%o", (int) pastTime );
    testTar(extractor,data,dataSize);

    long long futurTime = now + (long long)(1000LL * 365 * 24 * 60 * 60); // 1000 years in seconds

    generateHeader(&header); // generate standard headers
    snprintf(header.mtime, 12, "%o", (int) futurTime );
    testTar(extractor,data,dataSize);
}

void testEndBytes(const char* extractor) {
    printf("\n---------------------------------------------------\n");
    printf("\nEndbyte fuzzing\n");

    // Test cases for end bytes
    int endBytesSize[] = {1, END_OF_ARCHIVE - 1, 511, 513, 1023};
    int sizeOfArray = sizeof(endBytesSize) / sizeof(int);

    char endBytes[END_OF_ARCHIVE * 3]; // max length of endBytes in endBytesSize[]
    memset(endBytes, 0, END_OF_ARCHIVE * 3); // set endBytes[i] to zero

    char testInput[] = "This should be crashed!";
    size_t testInputSize = strlen(testInput);

    printf("\nGenerating contentless tar\n");
    for (int i = 0; i < sizeOfArray; i++) {
        generateHeader(&header); // generate standard headers
        calculate_checksum(&header);
        generateTar(&header, "", 0, endBytes, endBytesSize[i], 0); // test file without the testInput
        testExtractor(extractor);
    }

    printf("\nGenerating tar with content\n");
    for (int i = 0; i < sizeOfArray; i++) {
        generateHeader(&header); // generate standard headers
        snprintf(header.size, 12, "%011lo", testInputSize); // set header.size with testInputSize
        calculate_checksum(&header);
        generateTar(&header, testInput, testInputSize, endBytes, endBytesSize[i], 0); // test file with the testInput
        testExtractor(extractor);
    }

    printf("\n---------------------------------------------------\n");
}

void testChecksumField(const char* extractor) {
    generateHeader(&header); // generate standard headers
    int randomNumber = rand() % 2097152;
    snprintf((&header)->chksum, 8, "%o", randomNumber);
    generateTar(&header, "", 0, "", 0, 0); // test file without the testInput
    testExtractor(extractor);
}

void testTypeFlagField(const char* extractor){
    generateHeader(&header); // generate standard headers
    
    // Set the typeflag field to ASCII characters, non-ASCII characters, and numbers 0 to 9
    //for (int i = 0; i <= 255; i++) {
    //    if ((i >= 0 && i <= 127) || (i >= 128 && i <= 255) || (i >= 48 && i <= 57)) {
    //        header.typeflag = (char)i;
    //        testTar(extractor,data,0);        
    //    }
    // }

    generateHeader(&header); // generate standard headers
    //sprintf(header.mode, "%07o", 040755);
    sprintf(header.name, "%s", "file.txt");
    header.typeflag = '\5';
    calculate_checksum(&header);
    generateTar(&header, "", 0, "", 0, 0);

    testExtractor(extractor);
}

void testVersionField(const char* extractor){
    generateHeader(&header); // generate standard headers
    char str[3];

    for (char c1 = '0'; c1 <= '9'; c1++) {
        for (char c2 = '0'; c2 <= '9'; c2++) {
            str[0] = c1;
            str[1] = c2;
            str[2] = '\0';
            strncpy(header.version, str, sizeof(header.version));
            calculate_checksum(&header);
            generateTar(&header, "", 0, "", 0, 0); // test file without the testInput

            if (testExtractor(extractor) == 1){
                goto finally;
            }
        }
    }
    finally:
    printf(header.version);
}

void testTar(const char* extractor,char data[],size_t dataSize){
    if (dataSize > 0) {
        snprintf(header.size, 12, "%011lo", dataSize); 
    }

    calculate_checksum(&header);
    generateTar(&header,data,dataSize , "", 0, 0);
    testExtractor(extractor);
    generateHeader(&header); // generate standard headers

}

void testField(const char* extractor,char* fieldName, int size, char data[],size_t dataSize){
    generateHeader(&header); // generate standard headers

    memset(fieldName, '1', size); // Set incorrect value
    testTar(extractor,data,dataSize);

    strncpy(fieldName, "", size); // empty
    testTar(extractor,data,dataSize);

    snprintf(fieldName, size, "ustar%s", "\x00"); // Add null byte in magic value
    testTar(extractor,data,dataSize);

    snprintf(fieldName, size, "us*ar"); // Set malformed magic value
    testTar(extractor,data,dataSize);

    memset(fieldName, '\x7F', size); // set field to ASCII code 127 (DEL)
    testTar(extractor,data,dataSize);

    strncpy(fieldName, "AB\x1F\x7FCD",size); // set field to "AB" + ASCII code 31 (Unit Separator) + ASCII code 127 (DEL) + "CD"
    testTar(extractor,data,dataSize);

    strcpy(fieldName, "123456789"); // set field to "123456789" which is longer than 6 bytes
    testTar(extractor,data,dataSize);

    char magicField[6] = {'A', 'B', 'C', 'D', 'E', 'F'};
    memcpy(fieldName, magicField, sizeof(magicField)); // set field without null-termination
    testTar(extractor,data,dataSize);

    strncpy(fieldName, "????",size); // set field to a string with non-ASCII characters
    testTar(extractor,data,dataSize);

    strncpy(fieldName, "ßßßß",size); // set field to a string with non-ASCII characters
    testTar(extractor,data,dataSize);

    strncpy(fieldName, "ABC@DEF",size); // set field to a string with invalid characters, such as "@" 
    testTar(extractor,data,dataSize);

    strncpy(fieldName, "AB\x80CD",size); // set field to a string with mixed character encodings, such as ASCII and UTF-8
    testTar(extractor,data,dataSize);

    strncpy(fieldName, "AB\nCD",size); // set field to a string with control characters, such as newline (\n)
    testTar(extractor,data,dataSize);

    strncpy(fieldName, "This_is_a_very_long_prefix_that_exceeds_the_maximum_allowed_size_of_155_bytes_which_may_crash_the_extractor", size);
    testTar(extractor,data,dataSize);

    strncpy(fieldName, "This_is_an_invalid_prefix_with_null_byte_at_the_end_\0", size);
    testTar(extractor,data,dataSize);

    strncpy(fieldName, "-1000000000",size); // Setting an invalid negative value in the size field
    testTar(extractor,data,dataSize);

    strncpy(fieldName, "1.4beta",size); // Setting an invalid or unexpected value in the field
    testTar(extractor,data,dataSize);

    strncpy(fieldName, "This is a non-ASCII character: \u00A9",size); // Setting an invalid or unexpected value in the field
    testTar(extractor,data,dataSize);
}

void testFolderAndFiles(const char* extractor){
    char testInput[] = "This should be crashed!";
    size_t testInputSize = strlen(testInput);
    
    // Tests with empty file.
    generateHeader(&header); // generate standard headers
    sprintf(header.name, "%s", "test_file.txt");
    sprintf(header.size, "%011o", testInputSize);
    calculate_checksum(&header);
    generateTar(&header, "", 0, "", 0, 0);
    testExtractor(extractor);

    // Tests with file with content.
    generateHeader(&header); // generate standard headers
    sprintf(header.name, "%s", "test_file.txt");
    sprintf(header.size, "%011o", testInputSize);
    calculate_checksum(&header);
    generateTar(&header, testInput, testInputSize, "", 0, 0);
    testExtractor(extractor);

    // Tests empty folder and empty file in same directory.
    generateHeader(&header); // generate standard headers
    sprintf(header.mode, "%07o", 040755);
    sprintf(header.name, "%s", "empty_folder/");
    header.typeflag = '5';
    calculate_checksum(&header);
    generateTar(&header, "", 0, "", 0, 0);

    generateHeader(&header); // generate standard headers
    sprintf(header.name, "%s", "test_file.txt");
    sprintf(header.size, "%011o", testInputSize);
    calculate_checksum(&header);
    generateTar(&header, "", 0, "", 0, 1);

    testExtractor(extractor);

    // Tests empty folder and file with content in same directory.
    generateHeader(&header); // generate standard headers
    sprintf(header.mode, "%07o", 040755);
    sprintf(header.name, "%s", "empty_folder/");
    header.typeflag = '5';
    calculate_checksum(&header);
    generateTar(&header, "", 0, "", 0, 0);

    generateHeader(&header); // generate standard headers
    sprintf(header.name, "%s", "test_file.txt");
    sprintf(header.size, "%011o", testInputSize);
    calculate_checksum(&header);
    generateTar(&header, testInput, testInputSize, "", 0, 1);

    testExtractor(extractor);

    // Tests with folder containing empty folder and file with content.
    generateHeader(&header); // generate standard headers
    sprintf(header.mode, "%07o", 040755);
    sprintf(header.name, "%s", "folder/");
    header.typeflag = '5';
    calculate_checksum(&header);
    generateTar(&header, "", 0, "", 0, 0); // test file with the testInput

    generateHeader(&header); // generate standard headers
    sprintf(header.mode, "%07o", 040755);
    sprintf(header.name, "%s", "folder/empty_folder/");
    header.typeflag = '5';
    calculate_checksum(&header);
    generateTar(&header, "", 0, "", 0, 1);

    generateHeader(&header); // generate standard headers
    sprintf(header.name, "%s", "folder/test_file.txt");
    sprintf(header.size, "%011o", testInputSize);
    calculate_checksum(&header);
    generateTar(&header, testInput, testInputSize, "", 0, 1);
    
    testExtractor(extractor);
}

int main(int argc, char const *argv[]){
    if (argc != 2) {
        printf("Specify the path to the tar extractor.");
        return -1;
    }

    // Initialize random generator
    srand(time(NULL));

    const char* extractor = argv[1];
    char testInput[] = "This should be crashed!";
    size_t testInputSize = strlen(testInput);
    testField(extractor,header.magic,sizeof(header.magic),"",0);
    testField(extractor,header.magic,sizeof(header.magic),testInput,testInputSize);
    testField(extractor,header.uname,32,"",0);
    testField(extractor,header.uname,32,testInput,testInputSize);
    testField(extractor,header.gname,32,"",0);
    testField(extractor,header.gname,32,testInput,testInputSize);
    testField(extractor,header.mode,sizeof(header.mode),"",0);
    testField(extractor,header.mode,sizeof(header.mode),testInput,testInputSize);
    testField(extractor,header.linkname,sizeof(header.linkname),"",0);
    testField(extractor,header.linkname,sizeof(header.linkname),testInput,testInputSize);
    
    testNameField(extractor);
    testEndBytes(extractor);
    testSizeField(extractor);
    testChecksumField(extractor);
    testVersionField(extractor);
    //testModeField(extractor);
    //testTypeFlagField(extractor);
    testMtimeField(extractor, "", 0);
    
    testFolderAndFiles(extractor);

    printf("Number of test made : %d\n", testNumber);
    printf("Number of crashes found: %d\n", crash);
    system("rm -f *.txt");
    system("rm -f " ARCHIVE_NAME);

    return 0;
}