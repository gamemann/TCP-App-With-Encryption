#include <stdio.h>
#include <sodium.h>
#include <getopt.h>

char *path = "/etc/tcpserver/key.txt";

const struct option longopts[] =
{
    {"path", required_argument, NULL, 'p'}
};

void ParseCmdLine(int argc, char *argv[])
{
    int c;

    while ((c = getopt_long(argc, argv, "p:", longopts, NULL) != -1))
    {
        switch (c)
        {
            case 'p':
                path = optarg;

                break;
        }
    }
}

int main(int argc, char *argv[])
{
    // Parse command line.
    ParseCmdLine(argc, argv);

    unsigned char key[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
    crypto_aead_chacha20poly1305_ietf_keygen(key);

    FILE *fp = fopen(path, "wb");

    if (fp != NULL)
    {
        fwrite(key, crypto_aead_chacha20poly1305_IETF_KEYBYTES, 1, fp);

        fclose(fp);

        fprintf(stdout, "Generated key.\n");
    }

    return 0;
}