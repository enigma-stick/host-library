#include "../include/enigma.h"
#include <stdio.h>
#include <string.h>

#define KEY_ID 0x4B4D1000

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

  const char *plaintext = "This is the message to encrypt!";
  uint8_t ciphertext[512];
  size_t cipher_len = 0;
  res = enigma_encrypt(device, KEY_ID, (uint8_t *)plaintext, strlen(plaintext),
                       ciphertext, sizeof(ciphertext), &cipher_len, &error);
  if (res != ENIGMA_OK) {
    printf("Could not encrypt message (%02x) - %s\n", res, error.message);
    exit = 1;
    goto cleanup;
  }
  printf("Encrypted message: %lu\n", cipher_len);

  for (size_t i = 0; i < cipher_len; i++) {
    printf("%02X ", ciphertext[i]);
  }
  printf("\n");

  uint8_t decrypt_res[512];
  size_t decrypt_len = 0;
  res = enigma_decrypt(device, KEY_ID, ciphertext, cipher_len, decrypt_res,
                       sizeof(decrypt_res), &decrypt_len, &error);
  if (res != ENIGMA_OK) {
    printf("Could not decrypt message (%02x) - %s\n", res, error.message);
    exit = 1;
    goto cleanup;
  }
  decrypt_res[decrypt_len] = '\0';
  printf("Decrypted message: %s\n", (char *)decrypt_res);

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
