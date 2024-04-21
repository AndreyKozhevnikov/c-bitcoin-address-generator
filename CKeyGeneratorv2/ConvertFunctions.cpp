#include "pch.h"
#include <string>
#include "CKeyGen.h"
#include "AddressUtil.h"
#include "sha256.h"
#include "mRipeMd.cpp"
#include <sstream>
#include <iostream>
#include <iomanip> 

using namespace std;


vector<unsigned char> stringToBytes(string input)
{
	vector<unsigned char> bytes;
	for (char c : input) {
		bytes.push_back((c));
	}
	return bytes;
}

vector<char> hexToBytes(const string& hex) {
	vector<char> bytes;
	for (unsigned int i = 0; i < hex.length(); i += 2) {
		string byteString = hex.substr(i, 2);
		char byte = (char)strtol(byteString.c_str(), NULL, 16);
		bytes.push_back(byte);
	}
	return bytes;
}
vector<unsigned char> intToBytes(int paramInt)
{
	vector<unsigned char> arrayOfByte(32);
	for (int i = 0; i < 4; i++)
		arrayOfByte[31 - i] = (paramInt >> (i * 8));
	return arrayOfByte;
}
string bytesToHexString(const vector<uint8_t>& input)
{
	static const char characters[] = "0123456789ABCDEF";

	// Zeroes out the buffer unnecessarily, can't be avoided for string.
	string ret(input.size() * 2, 0);

	// Hack... Against the rules but avoids copying the whole buffer.
	auto buf = const_cast<char*>(ret.data());

	for (const auto& oneInputByte : input)
	{
		*buf++ = characters[oneInputByte >> 4];
		*buf++ = characters[oneInputByte & 0x0F];
	}
	return ret;
}

vector<char> HexToBytes(const string& hex) {
	vector<char> bytes;

	for (unsigned int i = 0; i < hex.length(); i += 2) {
		string byteString = hex.substr(i, 2);
		char byte = (char)strtol(byteString.c_str(), NULL, 16);
		bytes.push_back(byte);
	}

	return bytes;
}

string getCheckSum(string key) {
	vector<char> fullKeybytes = HexToBytes(key);
	string fullKeyBytesStr(fullKeybytes.begin(), fullKeybytes.end());
	string sha1 = sha256hex(fullKeyBytesStr);
	vector<char> sha256bytes = HexToBytes(sha1);
	string sha256Str(sha256bytes.begin(), sha256bytes.end());
	string sha2 = sha256hex(sha256Str);
	string checkSum = sha2.substr(0, 8);
	return checkSum;
}
vector<unsigned char> hexToBytesUnsign(const string& hex) {
	vector< unsigned char> bytes;

	for (unsigned int i = 0; i < hex.length(); i += 2) {
		string byteString = hex.substr(i, 2);
		char byte = (char)strtol(byteString.c_str(), NULL, 16);
		bytes.push_back(byte);
	}

	return bytes;
}

secp256k1::ecpoint getPublicKey(string privateKey) {
	secp256k1::uint256 k(privateKey);
	secp256k1::ecpoint p = secp256k1::multiplyPoint(k, secp256k1::G());
	return p;
}

string get1Address(secp256k1::ecpoint p) {
	string address = Address::fromPublicKey(p, true);
	return address;
}

size_t convert_hex(uint8_t* dest, size_t count, const char* src) {
	char buf[3];
	size_t i;
	for (i = 0; i < count && *src; i++) {
		buf[0] = *src++;
		buf[1] = '\0';
		if (*src) {
			buf[1] = *src++;
			buf[2] = '\0';
		}
		if (sscanf(buf, "%hhx", &dest[i]) != 1)
			break;
	}
	return i;
}
string uint8_to_hex_string(const uint8_t* v, const size_t s) {
	std::stringstream ss;

	ss << std::hex << std::setfill('0');

	for (int i = 0; i < s; i++) {
		ss << std::hex << std::setw(2) << static_cast<int>(v[i]);
	}

	return ss.str();
}
string Ripe160HexToHex(string redeemSha256) {
	uint8_t msg[32];


	uint8_t hash[20];
	convert_hex(msg, 32, redeemSha256.c_str());
	//memcpy(msg, redeemSha256.c_str(), sizeof(msg));
	ripemd160x(msg, 32, hash);

	string hexstr = uint8_to_hex_string(hash, 20);
	//string hexstr = "'uint8_to_hex_string(hash, 20);'test";
	return hexstr;
}

