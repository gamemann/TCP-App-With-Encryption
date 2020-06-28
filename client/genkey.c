#include <stdio.h>
#include <sodium.h>

int main()
{
    unsigned char key[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
    crypto_aead_chacha20poly1305_ietf_keygen(key);

    FILE *fp = fopen("/etc/test/key.txt", "wb");

    if (fp != NULL)
    {
        fwrite(key, crypto_aead_chacha20poly1305_IETF_KEYBYTES, 1, fp);

        fclose(fp);

        fprintf(stdout, "Generated key.\n");
    }

    return 0;
}