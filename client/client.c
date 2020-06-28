#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <inttypes.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/socket.h>

struct config
{
    char *IP;
    char *key;
    uint16_t port;
} cfg;

const struct option longopts[] =
{
    {"dst", required_argument, NULL, 'd'},
    {"port", required_argument, NULL, 'p'},
    {"key", required_argument, NULL, 'k'}
};

void ParseCmdLine(int argc, char *argv[])
{
    int c = 0;

    while ((c = getopt_long(argc, argv, "d:p:", longopts, NULL)) != -1)
    {
        switch (c)
        {
            case 'd':
                cfg.IP = optarg;
                
                break;

            case 'p':
                cfg.port = atoi(optarg);

                break;

            case 'k':
                cfg.key = optarg;

                break;
        }
    }
}

int GetKey(unsigned char *key)
{
    // Open key file.
    FILE *fp = fopen(cfg.key, "rb");

    if (fp == NULL)
    {
        fprintf(stderr, "Failed to open %s: %s\n", cfg.key, strerror(errno));

        return 1;
    }

    // Set file's position to end of file so we can get the position (AKA size).
    fseek(fp, 0L, SEEK_END);

    // Get size of key file.
    size_t sz;

    sz = ftell(fp);

    // Reset position to beginning.
    fseek(fp, 0L, SEEK_SET);

    // Read key.
    fread(key, sz, 1, fp);
    
    return 0;
}

// Returns socket.
int SetupTCP()
{
    // Create socket.
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    // Check to ensure socket is valid.
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
    din.sin_port = htons(cfg.port);
    din.sin_addr.s_addr = inet_addr(cfg.IP);
    memset(&din.sin_zero, 0, sizeof(din.sin_zero));

    // Connect to server.
    if (connect(sock, (struct sockaddr *)&din, sizeof(din)) < 0)
    {
        fprintf(stderr, "Error connecting to server :: %s\n", strerror(errno));

        return -1;
    }

    return sock;
}

int EncryptMessage(int sockfd, unsigned char *buff, unsigned char *key, uint64_t *counter)
{
    unsigned char hash[crypto_generichash_BYTES];
    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    unsigned char ctext[crypto_aead_chacha20poly1305_IETF_ABYTES + 2048];
    unsigned char scounter[sizeof(uint64_t)];
    unsigned long long ctextlen;

    // Size is sizeof(ctext) + sizeof(uint64_t).
    unsigned char toSend[crypto_aead_chacha20poly1305_IETF_ABYTES + 2048 + sizeof(uint64_t)];

    // Copy counter integer to string.
    memcpy(scounter, counter, sizeof(uint64_t));

    // Generate hash to use as nonce (first 12 bytes).
    if (crypto_hash_sha256(hash, scounter, sizeof(scounter)) != 0)
    {
        fprintf(stderr, "Error hashing nonce.\n");

        return 1;
    }

    // Copy first 12 bytes of hash to nonce.
    memcpy(nonce, hash, 12);
    
    // Encrypt the message and store in ctext.
    crypto_aead_chacha20poly1305_ietf_encrypt(ctext, &ctextlen, buff, strlen(buff), NULL, 0, NULL, nonce, key);

    // Check to ensure we can decrypt the message before sending.
    unsigned char decrypted[2048];
    unsigned long long dlen;

    // Attempt to decrypt message using the existing cipher text, nonce/IV, and key before sending to server.
    if (crypto_aead_chacha20poly1305_ietf_decrypt(decrypted, &dlen, NULL, ctext, ctextlen, NULL, 0, nonce, key) != 0)
    {
        fprintf(stderr, "Encrypted message is forged!\n");

        return 1;
    }

    //fprintf(stdout, "Decrypted => %s\n", decrypted);

    // Copy counter to beginning of toSend (8 bytes).
    char *sendCounter = toSend;
    memcpy(sendCounter, counter, sizeof(uint64_t));

    // Copy cipher text to rest of string.
    char *ctextPtr = toSend + sizeof(uint64_t);
    memcpy(ctextPtr, ctext, ctextlen);

    // Send message.
    if (write(sockfd, toSend, ctextlen + sizeof(uint64_t)) < 1)
    {
        fprintf(stderr, "Error sending packet on socket :: %s\n", strerror(errno));

        return 1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    // Initialize Libsodium.
    if (sodium_init() == -1)
    {
        fprintf(stderr, "Failed to initialize Sodium.\n");

        exit(1);
    }

    // Set defaults.
    cfg.IP = "0.0.0.0";
    cfg.port = 3020;
    cfg.key = "/etc/tcpserver/key.txt";

    // Parse command line.
    ParseCmdLine(argc, argv);

    unsigned char key[crypto_aead_chacha20poly1305_IETF_KEYBYTES];

    // Get key.
    if (GetKey(key) != 0)
    {
        fprintf(stderr, "Error getting key.\n");

        exit(1);
    }

    // Setup TCP connection.
    int sockfd = SetupTCP();

    // Check to ensure socket is valid.
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

    // Close socket.
    close(sockfd);

    // Exit program successfully.
    exit(0);
}