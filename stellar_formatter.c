#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "stellar/formatter.h"
#include "stellar/parser.h"

#define MAX_ENVELOPE_SIZE 131072
#define MAX_CAPTION_SIZE 21
#define MAX_VALUE_SIZE 105
#define MAX_OUTPUT_SIZE 131072

#define ENVELOPE_TYPE_TX 0
#define ENVELOPE_TYPE_AUTH 1

static bool is_string_empty(const char *str) {
  return str == NULL || str[0] == '\0';
}

bool format(uint8_t *data, size_t data_size, uint8_t type) {
  envelope_t envelope;
  char caption[MAX_CAPTION_SIZE];
  char value[MAX_VALUE_SIZE];
  uint8_t signing_key[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  char output[4096] = {0};

  memset(&envelope, 0, sizeof(envelope_t));

  if (type == ENVELOPE_TYPE_TX) {
    if (!parse_transaction_envelope(data, data_size, &envelope)) {
      return false;
    }
  } else {
    if (!parse_soroban_authorization_envelope(data, data_size, &envelope)) {
      return false;
    }
  }

  formatter_data_t fdata = {.raw_data = data,
                            .raw_data_len = data_size,
                            .envelope = &envelope,
                            .signing_key = signing_key,
                            .caption = caption,
                            .value = value,
                            .value_len = MAX_VALUE_SIZE,
                            .caption_len = MAX_CAPTION_SIZE,
                            .display_sequence = true};

  bool data_exists = true;
  bool is_op_header = false;
  reset_formatter();
  while (true) {
    if (!get_next_data(&fdata, true, &data_exists, &is_op_header)) {
      return false;
    }
    if (!data_exists) {
      break;
    }
    char temp[1024] = {0};
    sprintf(temp, "%s;%s%s\n", fdata.caption,
            is_string_empty(fdata.value) ? "" : " ", fdata.value);
    strlcat(output, temp, sizeof(output));
  }

  printf("%s", output);

  return true;
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "Usage: %s [-t|-a] <base64_data>\n", argv[0]);
    return 1;
  }

  uint8_t type;
  if (strcmp(argv[1], "-t") == 0) {
    type = ENVELOPE_TYPE_TX;
  } else if (strcmp(argv[1], "-a") == 0) {
    type = ENVELOPE_TYPE_AUTH;
  } else {
    fprintf(stderr, "Invalid option: %s\n", argv[1]);
    fprintf(stderr, "Usage: %s [-t|-a] <base64_data>\n", argv[0]);
    return 1;
  }

  const char *base64_data = argv[2];
  size_t base64_len = strlen(base64_data);
  uint8_t decoded_data[MAX_ENVELOPE_SIZE];
  size_t len =
      EVP_DecodeBlock(decoded_data, (const uint8_t *)base64_data, base64_len);

  bool success = format(decoded_data, len, type);

  if (!success) {
    fprintf(stderr, "Failed to format transaction/soroban auth.\n");
  }
  return success ? 0 : 1;
}