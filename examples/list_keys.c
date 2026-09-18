#include "../include/enigma.h"
#include <stdio.h>

const char *enigma_key_type_str(enigma_key_type type) {
  switch (type) {
  case enigma_key_type_aes:
    return "AES";
  case enigma_key_type_rsa:
    return "RSA";
  case enigma_key_type_ec:
    return "EC";
  case enigma_key_type_hmac:
    return "HMAC";
  }
  return "<?>";
}

const char *enigma_key_usage_str(enigma_key_usage usage) {
  switch (usage) {
  case enigma_key_usage_encrypt:
    return "ENCRYPT";
  case enigma_key_usage_sign:
    return "SIGN";
  case enigma_key_usage_derive:
    return "DERIVE";
  }
  return "<?>";
}

int main(void) {

  int exit = 0;
  enigma_device *device;
  enigma_error error = {0};

  enigma_result res = enigma_open(&device, &error);
  if (res != ENIGMA_OK) {
    printf("Could not open device (%02x) - %s\n", res, error.message);
    return 1;
  }

  enigma_key_list *key_list;
  res = enigma_list_keys(device, NULL, NULL, NULL, NULL, &key_list, &error);
  if (res != ENIGMA_OK) {
    printf("Could not list keys (%02x) - %s\n", res, error.message);
    exit = 1;
    goto cleanup;
  }

  for (uint32_t i = 0; i < key_list->count; i++) {
    enigma_key_meta key = key_list->keys[i];
    printf("KEY 0x%08X\n", key.id);
    printf("  Type: %s\n", enigma_key_type_str(key.type));
    printf("  Usage: %s\n", enigma_key_usage_str(key.usage));
    printf("  Size: %d\n", key.size);
    printf("  Label: %s\n\n", key.label);
  }

cleanup:
  enigma_key_list_free(key_list);
  res = enigma_close(device, &error);
  if (res != ENIGMA_OK) {
    printf("Could not close device (%02x) - %s\n", res, error.message);
    return 1;
  }

  return exit;
}
