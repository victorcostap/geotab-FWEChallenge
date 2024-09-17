#include "crypt.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "geotab_crypto.h"
#include "geotab_crypto_errors.h"

int main(int argc, char *argv[]) {
  int opt;
  uint8_t *key = NULL;
  char *keyFile = NULL;
  char *outputFile = NULL;
  char *inputFile = NULL;
  struct crypt_context context;

  // Input and output. Unless specified stdin and stdout
  FILE *in = stdin;
  FILE *out = stdout;

  if (argc == 1) {
    printUsage(argv[0]);
    exit(EXIT_FAILURE);
  }

  // Parse arguments
  while ((opt = getopt(argc, argv, "hk:f:o:")) != -1) {
    switch (opt) {
      case 'h':
        printUsage(argv[0]);
        exit(EXIT_SUCCESS);
      case 'k':
        context.lengthKey = strlen(optarg);
        if (context.lengthKey < 1 || context.lengthKey > 256) {
          fprintf(stderr, "Key must be between 1 and 256 characters long\n");
          exit(EXIT_FAILURE);
        }
        key = (uint8_t *)malloc(context.lengthKey);
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
        fprintf(stderr, "%c is not a valid parameter\n", opt);
        printUsage(argv[0]);
        cleanUpResources(in, out, key);
        exit(EXIT_FAILURE);
    }
  }

  if ((key && keyFile) || (!key && !keyFile)) {
    fprintf(stderr,
            "Error: Either -k <key> or -f <key_file> must be provided, but not "
            "both.\n");
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
    readKeyFromFile(keyFile, &context);
  }

  if (inputFile) {
    in = fopen(inputFile, "r");
    if (!in) {
      fprintf(stderr, "Error opening input file\n");
      cleanUpResources(in, out, key);
      exit(EXIT_FAILURE);
    }
  }

  if (outputFile && strcmp(outputFile, "-") != 0) {
    out = fopen(outputFile, "w");
    if (!out) {
      fprintf(stderr, "Error opening output file\n");
      cleanUpResources(in, out, key);
      exit(EXIT_FAILURE);
    }
  }

  processInput(in, out, &context, key);
  cleanUpResources(in, out, key);

  return 0;
}

void printUsage(const char *progName) {
  fprintf(stderr,
          "Usage: %s [-h] -k <key> | -f <key_file> [-o <output_file>] "
          "[<input_file>]\n",
          progName);
}

void cleanUpResources(FILE *in, FILE *out, uint8_t *key) {
  if (in != stdin) fclose(in);
  if (out != stdout) fclose(out);
  if (key) free(key);
}

inline void getKeyLength(FILE *kf, struct crypt_context *context) {
  fseek(kf, 0, SEEK_END);
  context->lengthKey = ftell(kf);
  fseek(kf, 0, SEEK_SET);
}

inline void readKeyFromFile(const char *keyFile, struct crypt_context *context) {
  FILE *kf = fopen(keyFile, "r");
  if (!kf) {
    fprintf(stderr, "Error opening key file\n");
    exit(EXIT_FAILURE);
  }
  getKeyLength(kf, context);
  context->key = (uint8_t *)malloc(context->lengthKey + 1);
  if (!context->key) {
    fclose(kf);
    fprintf(stderr, "Error allocating memory for key\n");
    exit(EXIT_FAILURE);
  }
  fread(context->key, 1, context->lengthKey, kf);
  context->key[context->lengthKey] = '\0';
  fclose(kf);

  if (context->lengthKey < 1 || context->lengthKey > 256) {
    fprintf(stderr, "Key must be between 1 and 256 characters long\n");
    exit(EXIT_FAILURE);
  }
}

inline void processInput(FILE *in, FILE *out, struct crypt_context *context,
                  uint8_t *key) {
  int inChar;  // note: int, not char, required to handle EOF
  char outChar;
  int ret;
  context->index = 0;

  inChar = getc(in);
  while (inChar != EOF) {
    ret = crypt_buffer(context, &outChar, (char *)&inChar, 1);
    if (ret != GEOTAB_CRYPTO_SUCCESS) {
      fprintf(stderr, "Error while encrypting/decrypting data\n");
      cleanUpResources(in, out, key);
      exit(ret);
    }
    putc(outChar, out);
    fflush(out);
    inChar = getc(in);
  }
}
