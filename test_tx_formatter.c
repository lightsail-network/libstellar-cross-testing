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

static bool is_string_empty(const char *str) {
  return str == NULL || str[0] == '\0';
}

bool format_tx(uint8_t *data, size_t data_size) {
  envelope_t envelope;
  char caption[MAX_CAPTION_SIZE];
  char value[MAX_VALUE_SIZE];
  uint8_t signing_key[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  char output[4096] = {0};

  memset(&envelope, 0, sizeof(envelope_t));

  if (!parse_transaction_envelope(data, data_size, &envelope)) {
    return false;
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
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <base64_data>\n", argv[0]);
    return 1;
  }

  const char *base64_data = argv[1];
  size_t base64_len = strlen(base64_data);
  uint8_t decoded_data[MAX_ENVELOPE_SIZE];
  size_t len =
      EVP_DecodeBlock(decoded_data, (const uint8_t *)base64_data, base64_len);

  bool success = format_tx(decoded_data, len);

  if (!success) {
    fprintf(stderr, "Failed to format transaction\n");
  }
  return success ? 0 : 1;
}