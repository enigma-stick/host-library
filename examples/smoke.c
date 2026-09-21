#include "../include/enigma.h"
#include <stdio.h>

#define KEY_ID 0x4B4D1003

int main(void) {
  int exit = 0;
  enigma_device *device;
  enigma_error error = {0};
  const enigma_ecdh_result *ecdh_result = NULL;

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

  unsigned char host_ec_pub_der[] = {
      0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
      0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
      0x42, 0x00, 0x04, 0xb9, 0xbd, 0x5d, 0x91, 0x45, 0x14, 0x6d, 0xeb, 0x9f,
      0xd6, 0xb3, 0x17, 0x77, 0xe5, 0x2c, 0xad, 0x06, 0x5e, 0x10, 0x63, 0xb3,
      0xed, 0xec, 0x18, 0x47, 0x4e, 0xd9, 0x2f, 0xc2, 0x00, 0x1f, 0x0b, 0x10,
      0x32, 0xdb, 0x05, 0x20, 0x09, 0x12, 0x84, 0xd4, 0xcd, 0x79, 0xb6, 0xd3,
      0x54, 0x75, 0x0a, 0x05, 0x52, 0xfb, 0x09, 0xc8, 0x5c, 0x47, 0xd7, 0x96,
      0x3c, 0xba, 0xa8, 0x89, 0x70, 0x8b, 0x18};
  unsigned int host_ec_pub_der_len = 91;

  res = enigma_ecdh(device, KEY_ID, enigma_public_key_encoding_der_spki,
                    host_ec_pub_der, host_ec_pub_der_len, "host-ecdh-test",
                    &ecdh_result, &error);
  if (res != ENIGMA_OK) {
    printf("Could not perform ECDH (%02X) - %s\n", res, error.message);
    exit = 1;
    goto cleanup;
  }
  printf("Derived new key via ECDH + HKDF: 0x%08X\n", ecdh_result->key_id);

  printf("Salt: ");
  for (size_t i = 0; i < ecdh_result->salt_len; i++) {
    printf("%02X ", ecdh_result->salt[i]);
  }
  printf("\n");

  printf("Info: %s\n", ecdh_result->info);

cleanup:
  enigma_ecdh_free(ecdh_result);
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
