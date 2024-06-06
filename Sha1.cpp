#include <string>
#include <vector>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <cstring>
#include <bitset>

// Define the block size for working with files
// Must be multiple 64
#define CHUNK_SIZE 4096

/// \brief Convert uint32 to string with hex form of this number
/// \param [in] a uint32 number to convert
/// \return hex represenation of a
std::string Uint32ToHexForm(std::uint32_t a) noexcept
{
    std::string res(8, 0);
    
    for (int i = 7; i > -1; i -= 2)
    {
        int highByte = a % 16;
        a /= 16;
        
        int lowByte = a % 16;
        a /= 16;

        if (highByte > 9)
            res[i] = 'a' + highByte - 10;
        else
            res[i] = highByte + '0';

        if (lowByte > 9)
            res[i - 1] = 'a' + lowByte - 10;
        else
            res[i - 1] = lowByte + '0';
    }

    return res;
}

/**
    \brief A function for turning a number to the left
    
    The rotation of a number is equivalent to a cyclic shift of that number

    \param [in] digitToRotate the number to be rotated
    \param [in] rotateLen The number to rotate by

    \example Lets rotate 1234 number by 3  
    1234 = 0b00000000000000000000010011010010  
    RightRotate(1234) = 0b00000000000000000010011010010000  

    \return new rotated digit
*/
uint32_t LeftRotate(const uint32_t& digitToRotate, const uint32_t& rotateLen) noexcept
{
    return (digitToRotate << rotateLen) | (digitToRotate >> (sizeof(uint32_t) * 8 - rotateLen));
}

/**
    \brief Function for obtaining padding for the sha1 algorithm

    \param [in] data a pointer to the char, starting for which you need to find the padding. The length of the data must be less than or equal to 64
    \param [in] arrayLen the number of elements in the data arr
    \param [in] dataLen the length of the source data
    \param [out] destination a pointer to the char in which padding should be written. the length of the destination must be 128

    \return returns the length of the padding. 64 if the length of the source data was less than 56, otherwise it will return 128
*/
int DataPaddingSha1(const char* data, const std::size_t& dataLen, const std::size_t& sourceLen, char* destination) noexcept
{
    // Variable to store padding length
    int res;

    // Copy bytes from data to destination
    memcpy(destination, data, dataLen);
    
    // Set first padding bit to 1
    destination[dataLen] = 0b10000000;

    // Data length in bits
    std::uint64_t bitsLength = sourceLen * 8;

    // Check if padding have to be 128 bits
    if (dataLen < 56)
        res = 64;
    else
        res = 128;

    // Handle last 8 bytes in padding
    int i = 0;
    for (; i < 8; ++i)
    {
        // Set 63 - i or 127 - i byte in padding value of right 8 bits from bits length
        destination[res - 1 - i] = bitsLength & 0b11111111;

        // Move 8 right bits from bits length
        bitsLength >>= 8;

        // If bits length equals 0 then break
        if (bitsLength == 0) break;
    }

    // Set 0 byte to all unfilled positions
    memset(destination + dataLen + 1, 0, res - dataLen - i - 2);

    return res;
}

/**
    \brief Sha1 hashing step
    
    The function calculates the sha1 hash sum for a 64 byte block of data

    \param [in] data a pointer to the array to calculate the hash for
    \param [in] offset a shift to indicate the beginning of the data block for which the hash is to be calculated
    \param [in, out] h0 internal state variable 0
    \param [in, out] h1 internal state variable 1
    \param [in, out] h2 internal state variable 2
    \param [in, out] h3 internal state variable 3
    \param [in, out] h4 internal state variable 4
*/
void Sha1Step(const char* data, const std::size_t& offset, std::uint32_t& h0, std::uint32_t& h1, std::uint32_t& h2, std::uint32_t& h3, std::uint32_t& h4) noexcept
{
    // Words array
    std::uint32_t words[80];

    // Join 4 chars from data into 16 uint32_t numbers and save it to words array
    for (int i = 0; i < 64; i += 4)
        words[i >> 2] = (static_cast<std::uint32_t>(static_cast<unsigned char>(data[i + offset])) << 24) | 
            (static_cast<std::uint32_t>(static_cast<unsigned char>(data[i + 1 + offset])) << 16) |
            (static_cast<std::uint32_t>(static_cast<unsigned char>(data[i + 2 + offset])) << 8) | 
            static_cast<std::uint32_t>(static_cast<unsigned char>(data[i + 3 + offset]));

    // Fill last 64 uint32_t numbers
    for (int i = 16; i < 80; ++i)
        words[i] = LeftRotate(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);

    // Temporary variables
    std::uint32_t a = h0, b = h1, c = h2, d = h3, e = h4, t;

    // 20 rounds with f(x, y, z) = (x & y) ^ (!x & z). We call f(b, c, d)
    for (int i = 0; i < 20; ++i)
    {
        t = LeftRotate(a, 5) + ((b & c) ^ (~b & d)) + e + 0x5a827999 + words[i];
        e = d, d = c, c = LeftRotate(b, 30), b = a, a = t;
    }

    // 20 rounds with f(x, y, z) = x ^ y ^ z. We call f(b, c, d)
    for (int i = 20; i < 40; ++i)
    {
        t = LeftRotate(a, 5) + (b ^ c ^ d) + e + 0x6ed9eba1 + words[i];
        e = d, d = c, c = LeftRotate(b, 30), b = a, a = t;
    }

    // 20 rounds with f(x, y, z) = (x & y) ^ (x & z) ^ (y ^ z). We call f(b, c, d)
    for (int i = 40; i < 60; ++i)
    {
        t = LeftRotate(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + 0x8f1bbcdc + words[i];
        e = d, d = c, c = LeftRotate(b, 30), b = a, a = t;
    }

    // 20 rounds with f(x, y, z) = x ^ y ^ z. We call f(b, c, d)
    for (int i = 60; i < 80; ++i)
    {
        t = LeftRotate(a, 5) + (b ^ c ^ d) + e + 0xca62c1d6 + words[i];
        e = d, d = c, c = LeftRotate(b, 30), b = a, a = t;
    }

    // Add temporary variables to hash
    h0 += a, h1 += b, h2 += c, h3 += d, h4 += e;
}

/**
    \brief A function for calculating the hash sum using the sha1 algorithm

    \param [in] data a pointer to the array to calculate the hash for
    \param [in, out] h0 internal state variable 0
    \param [in, out] h1 internal state variable 1
    \param [in, out] h2 internal state variable 2
    \param [in, out] h3 internal state variable 3
    \param [in, out] h4 internal state variable 4
*/
void HashSha1(const char* data, const std::size_t& dataLen, std::uint32_t& h0, std::uint32_t& h1, std::uint32_t& h2, std::uint32_t& h3, std::uint32_t& h4)
{
    // Handle 64 byte chunks
    for (std::size_t i = 0; i < dataLen >> 6; ++i)
        Sha1Step(data, i << 6, h0, h1, h2, h3, h4);

    // Padding source data
    char padding[128];
    int paddingLen = DataPaddingSha1(data + (dataLen & ~0b00111111), dataLen & 0b00111111, dataLen, padding);

    // Calculate hash for padded data
    Sha1Step(padding, 0, h0, h1, h2, h3, h4);

    // If padding length is 128 then calculate hash for last block
    if (paddingLen == 128)
        Sha1Step(padding, 64, h0, h1, h2, h3, h4);
}

/**
    \brief A function for calculating the file hash sum using the sha1 algorithm

    \param [in] file ifstream object with a file to calculate the hash for
    \param [in, out] h0 internal state variable 0
    \param [in, out] h1 internal state variable 1
    \param [in, out] h2 internal state variable 2
    \param [in, out] h3 internal state variable 3
    \param [in, out] h4 internal state variable 4
*/
void HashFileSha1(std::ifstream& file, std::uint32_t& h0, std::uint32_t& h1, std::uint32_t& h2, std::uint32_t& h3, std::uint32_t& h4)
{
    // Save file size
    uint64_t fileSize = file.tellg();
    file.seekg(0);

    // Arrays to read 4kb from file and to save 4 kb to file
    char fileDataChunk[CHUNK_SIZE];

    // Counter for file reading
    std::size_t counter = 0;

    // Checking whether the file is larger than the size of the file processing chunks
    if (fileSize > CHUNK_SIZE)
    {
        // Processing the part of the file that is a multiple of the chunk size
        for(; counter < fileSize - CHUNK_SIZE; counter += CHUNK_SIZE)
        {
            // Read chunk from input file
            file.read(fileDataChunk, CHUNK_SIZE);

            // Calculate hash steps
            for (std::size_t i = 0; i < CHUNK_SIZE; i += 64)
                Sha1Step(fileDataChunk, i, h0, h1, h2, h3, h4);
        }
    }

    // Calculating the remaining bytes in the file
    counter = fileSize - counter;

    // Read last bytes from input file
    file.read(fileDataChunk, counter);

    // Calculate hash for last bytes
    for (uint64_t i = 0; i < counter >> 6; ++i)
        Sha1Step(fileDataChunk, i << 6, h0, h1, h2, h3, h4);

    // Padding source file
    // Move fileDataChunk ptr to last position multiply by 64
    char padding[128];
    int paddingLen = DataPaddingSha1(fileDataChunk + (counter & ~0b00111111), counter & 0b00111111, fileSize, padding);

    // Calculate hash for padded data
    Sha1Step(padding, 0, h0, h1, h2, h3, h4);

    // If padding length is 128 then calculate hash for last block
    if (paddingLen == 128)
        Sha1Step(padding, 64, h0, h1, h2, h3, h4);
}

/**
    \brief A function for calculating the hash sum using the sha1 algorithm

    \param [in] data a pointer to the array to calculate the hash for
    \param [in] dataLen data array length

    \return a string with a sha1 hash sum
*/
std::string Sha1(const char* data, const std::size_t& dataLen) noexcept
{
    // Begin hash values
    std::uint32_t h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;

    // Calculate hash
    HashSha1(data, dataLen, h0, h1, h2, h3, h4);

    // Return calculated hash
    return Uint32ToHexForm(h0) + Uint32ToHexForm(h1) + Uint32ToHexForm(h2) + Uint32ToHexForm(h3) + Uint32ToHexForm(h4);
}

/**
    \brief A function for calculating the hash sum using the sha1 algorithm

    \param [in] str the string to calculate the hash for

    \return a string with a sha1 hash sum
*/
std::string Sha1(const std::string& str) noexcept
{
    return Sha1(str.c_str(), str.length());
}

/**
    \brief A function for calculating the file hash sum using the sha1 algorithm

    \param [in] fileName the string with file name to calculate hash for

    \return a string with a sha1 hash sum
*/
std::string FileSha1(const std::string& fileName) noexcept
{
    // Begin hash values
    std::uint32_t h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;

    // Open file
    std::ifstream file(fileName, std::ios_base::binary | std::ios_base::ate);
    if (!file.is_open()) {std::cerr << "Can not open file: " << fileName << std::endl; return "";}

    // Calculate hash for file
    HashFileSha1(file, h0, h1, h2, h3, h4);

    // Return calculated hash
    return Uint32ToHexForm(h0) + Uint32ToHexForm(h1) + Uint32ToHexForm(h2) + Uint32ToHexForm(h3) + Uint32ToHexForm(h4);
}

int main()
{
    std::cout << Sha1("`1234567890-=qwertyuiop[]asdfghjkl;'zxcvbnm,./~!@#$%^&*()_+QWERTYUIOP{}ASDFGHJKL:|ZXCVBNM<>? And some additional text to more changes and tests") << std::endl;

    std::cout << FileSha1("Sha1.cpp") << std::endl;
}
