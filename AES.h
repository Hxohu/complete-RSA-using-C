#pragma once

#ifndef AES_H
#define AES_H
#include <stdint.h>

void aes_key_schedule(uint8_t key[16], uint8_t rk[11][16]);
void aes_encrypt_with_tables(uint8_t pt[16], uint8_t rk[11][16], uint8_t ct[16]);

#endif