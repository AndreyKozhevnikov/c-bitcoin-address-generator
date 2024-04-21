#include "pch.h"
#include <string>
#include "CKeyGen.h"
#include "AddressUtil.h"
#include "sha256.h"



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

