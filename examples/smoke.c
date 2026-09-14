#include "../include/enigma.h"
#include <stdio.h>
#include <string.h>

#define KEY_ID 0x4B4D1001

int main(void) {

  int exit = 0;
  enigma_device *device;
  enigma_error error = {0};

  enigma_result res = enigma_open(&device, &error);
  if (res != ENIGMA_OK) {
    printf("Could not open device (%02x) - %s\n", res, error.message);
    return 1;
  }

  res = enigma_authenticate(device, "password", &error);
  if (res != ENIGMA_OK) {
    printf("Could not open device (%02x) - %s\n", res, error.message);
    exit = 1;
    goto cleanup;
  }

  uint8_t buffer[512];
  size_t pk_len = 0;
  res = enigma_export_public_key(device, KEY_ID, buffer, sizeof(buffer),
                                 &pk_len, &error);
  if (res != ENIGMA_OK) {
    printf("Could not export public key (%02x) - %s\n", res, error.message);
    exit = 1;
    goto cleanup;
  }
  printf("Exported public key\n");

  // no error handling; don't just copy this
  FILE *file = fopen("public-key.der", "wb");
  fwrite(buffer, 1, pk_len, file);
  fclose(file);

  const char *message = "This is the message to sign!";
  uint8_t signature[512];
  size_t sign_len = 0;
  res = enigma_sign(device, KEY_ID, (uint8_t *)message, strlen(message),
                    signature, sizeof(signature), &sign_len, &error);
  if (res != ENIGMA_OK) {
    printf("Could not sign message (%02x) - %s\n", res, error.message);
    exit = 1;
    goto cleanup;
  }
  printf("Signed message\n");

  // no error handling; don't just copy this
  file = fopen("signature.bin", "wb");
  fwrite(signature, 1, sign_len, file);
  fclose(file);

cleanup:
  res = enigma_lock(device, &error);
  if (res != ENIGMA_OK) {
    printf("Could not lock device (%02x) - %s\n", res, error.message);
    enigma_close(device, &error);
    return 1;
  }

  res = enigma_close(device, &error);
  if (res != ENIGMA_OK) {
    printf("Could not close device (%02x) - %s\n", res, error.message);
    return 1;
  }

  return exit;
}
