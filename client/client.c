#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include <errno.h>
#include <unistd.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/socket.h>

#define PORT 3020

int GetKey(unsigned char *key)
{
    FILE *fp = fopen("/etc/test/key.txt", "r");

    if (fp == NULL)
    {
        fprintf(stderr, "Failed to open /etc/test/key.txt: %s\n", strerror(errno));

        return 1;
    }

    // Read key.
    fscanf(fp, "%s", key);
    
    return 0;
}

// Returns socket.
int SetupTCP()
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 1)
    {
        return sock;
    }

    int reuse = 1;

    // Set socket option so we can reuse port.
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0)
    {
        fprintf(stderr, "Error setting socket option :: %s\n", strerror(errno));

        return -1;
    }

    struct sockaddr_in din;

    din.sin_family = AF_INET;
    din.sin_port = htons(PORT);
    din.sin_addr.s_addr = inet_addr("0.0.0.0");
    memset(&din.sin_zero, 0, sizeof(din.sin_zero));

    if (connect(sock, (struct sockaddr *)&din, sizeof(din)) < 0)
    {
        fprintf(stderr, "Error connecting to server :: %s\n", strerror(errno));

        return -1;
    }

    return sock;
}

int EncryptMessage(int sockfd, unsigned char *buff, unsigned char *key, uint64_t *counter)
{
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char hash[crypto_box_SEEDBYTES];
    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    unsigned char ctext[crypto_aead_chacha20poly1305_IETF_ABYTES + 2048];
    unsigned char scounter[sizeof(uint64_t)];
    unsigned long long ctextlen;

    // Generate salt.
    randombytes_buf(salt, sizeof(salt));

    // Copy counter integer to string.
    snprintf(scounter, sizeof(scounter), "%lu", *counter);

    // Generate hash to use as nonce (first 12 bytes).
    if (crypto_pwhash(hash, sizeof(hash), scounter, sizeof(scounter), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0)
    {
        fprintf(stderr, "Error hashing nonce.\n");

        return 1;
    }

    // Copy first 12 bytes of hash to nonce.
    memset(nonce, 0, 12);
    //strcpy(nonce, "12345678901");

    crypto_aead_chacha20poly1305_ietf_encrypt(ctext, &ctextlen, buff, strlen(buff), NULL, 0, NULL, nonce, key);

    // Check to ensure we can decrypt the message before sending.
    unsigned char decrypted[2048];
    unsigned long long dlen;

    if (crypto_aead_chacha20poly1305_ietf_decrypt(decrypted, &dlen, NULL, ctext, ctextlen, NULL, 0, nonce, key) != 0)
    {
        fprintf(stderr, "Encrypted message is forged!\n");

        return 1;
    }

    FILE *fp = fopen("/etc/test/data.txt", "w");

    if (fp != NULL)
    {
        fputs(ctext, fp);

        fclose(fp);
    }

    fprintf(stdout, "Decrypted => %s\n", decrypted);

    // Send message.
    if (write(sockfd, ctext, ctextlen) < 1)
    {
        fprintf(stderr, "Error sending packet on socket :: %s\n", strerror(errno));

        return 1;
    }

    return 0;
}

int main()
{
    if (sodium_init() == -1)
    {
        fprintf(stderr, "Failed to initialize Sodium.\n");

        exit(1);
    }

    unsigned char key[crypto_aead_chacha20poly1305_IETF_KEYBYTES];

    // Get key.
    if (GetKey(key) != 0)
    {
        fprintf(stderr, "Error getting key.\n");

        exit(1);
    }

    // Setup TCP connection.
    int sockfd = SetupTCP();

    if (sockfd < 1)
    {
        fprintf(stderr, "Error getting socket.\n");

        exit(1);
    }

    uint64_t counter = 0;

    for (;;)
    {
        // Get message via stdin.
        unsigned char buffer[2048];

        fprintf(stdout, "Message: ");

        fgets(buffer, sizeof(buffer), stdin);

        // Check for quit (first four bytes).
        if (buffer[0] == 'q' && buffer[1] == 'u' && buffer[2] == 'i' && buffer[3] == 't')
        {
            break;
        }

        // Encrypt and send message.
        if (EncryptMessage(sockfd, buffer, key, &counter) != 0)
        {
            fprintf(stderr, "Error sending packet.\n");

            break;
        }

        // Increase counter for nonce.
        counter++;
    }

    close(sockfd);

    exit(0);
}