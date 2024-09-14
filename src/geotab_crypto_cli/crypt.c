#include "crypt.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "geotab_crypto.h"
#include "geotab_crypto_errors.h"

#define MAX_BUFFER_SIZE 1024

void printUsage(const char *progName) {
    fprintf(stderr, "Usage: %s [-h] -k <key> | -f <key_file> [-o <output_file>] [<input_file>]\n", progName);
}

void cleanUpResources(FILE *in, FILE *out, uint8_t *key) {
  // Cleanup
  if (in != stdin) fclose(in);
  if (out != stdout) fclose(out);
  if(key) free(key);
}

int main(int argc, char *argv[]) {
    int opt;
    uint8_t *key = NULL;
    char *keyFile = NULL;
    char *outputFile = NULL;
    char *inputFile = NULL;
    struct crypt_context context; 

    // Process input and output
    FILE *in = stdin;
    FILE *out = stdout;

    if(argc == 1) {
        printUsage(argv[0]);
        exit(EXIT_FAILURE);
    }

    while ((opt = getopt(argc, argv, "hk:f:o:")) != -1) {
        switch (opt) {
            case 'h':
                printUsage(argv[0]);
                exit(EXIT_SUCCESS);
            case 'k':
                context.lengthKey = strlen(optarg);
                if(context.lengthKey < 1 || context.lengthKey > 256) {
                    fprintf(stderr, "Key must be between 1 and 256 characters long\n");
                    exit(EXIT_FAILURE);
                }
                key = (uint8_t*)malloc(context.lengthKey);
                strncpy(key, optarg, context.lengthKey);
                context.key = key;
                break;
            case 'f':
                keyFile = optarg;
                break;
            case 'o':
                outputFile = optarg;
                break;
            default:
                fprintf(stderr, "%c is not a valid parameter", opt);
                printUsage(argv[0]);
                cleanUpResources(in, out, key);
                exit(EXIT_FAILURE);
        }
    }

    if ((key && keyFile) || (!key && !keyFile)) {
        fprintf(stderr, "Error: Either -k <key> or -f <key_file> must be provided, but not both.\n");
        printUsage(argv[0]);
        cleanUpResources(in, out, key);
        exit(EXIT_FAILURE);
    }

    
    // If there are still parameters without name, its the input file
    if (optind < argc) {
        inputFile = argv[optind];
    }

    // Read key from file if -f option
    if (keyFile) {
        // If here, key is NULL, no need to free it if error
        FILE *kf = fopen(keyFile, "r");
        if (!kf) {
            fclose(kf);
            fprintf(stderr, "Error opening key file");
            exit(EXIT_FAILURE);
        }
        fseek(kf, 0, SEEK_END);
        context.lengthKey = ftell(kf);
        fseek(kf, 0, SEEK_SET);
        key = (char *)malloc(context.lengthKey + 1);
        if (!key) {
            fclose(kf);
            fprintf(stderr, "Error allocating memory for key");
            exit(EXIT_FAILURE);
        }
        fread(key, 1, context.lengthKey, kf);
        key[context.lengthKey] = '\0';
        fclose(kf);

        if(context.lengthKey < 1 || context.lengthKey > 256) {
            fprintf(stderr, "Key must be between 1 and 256 characters long\n");
            exit(EXIT_FAILURE);
        }
        context.key = key;        
    }

    if (inputFile) {
        in = fopen(inputFile, "r");
        if (!in) {
            perror("Error opening input file");
            cleanUpResources(in, out, key);
            exit(EXIT_FAILURE);
        }

    }

    if (outputFile && strcmp(outputFile, "-") != 0) {
        out = fopen(outputFile, "w");
        if (!out) {
            perror("Error opening output file");
            cleanUpResources(in, out, key);
            exit(EXIT_FAILURE);
        }
    }

    char buffer[MAX_BUFFER_SIZE];
    char crypt[MAX_BUFFER_SIZE];
    size_t n;
    size_t bytesRead = 0;
    int ret;

    char auxBuffer[128];
    while(!feof(in) && bytesRead < MAX_BUFFER_SIZE) {
        if(in != stdin)
            n = fread(buffer+bytesRead, 1, sizeof(buffer)-bytesRead, in);
        else
            n = fread(buffer+bytesRead, 1, 1, in);
        bytesRead += n;
        ret = crypt_buffer(&context, crypt, buffer, bytesRead);
        if(ret != GEOTAB_CRYPTO_SUCCESS) {
            cleanUpResources(in, out, key);
            exit(ret);
        }
        putc('\n', out);
        fwrite(crypt, 1, bytesRead, out);
        putc('\n', out);
        fflush(out);
    }

    // while ((n = fread(buffer+bytesRead, 1, sizeof(buffer)-bytesRead, in)) > 0 && bytesRead < MAX_BUFFER_SIZE) {
    //     bytesRead += n;
    //     fwrite(buffer, 1, n, out);
    // }

    cleanUpResources(in, out, key);

    return 0;
}
