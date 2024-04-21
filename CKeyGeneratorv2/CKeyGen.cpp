#include "pch.h"
#include <string>
#include "CKeyGen.h"
#include "sha256.h"
#include "ConvertFunctions.cpp"
#include "base58.h"
#include "secp256k1.h"

using namespace std;


AddressSet CKeyGen::GenerateFromString(string value) {

	vector<uint8_t> bytes = stringToBytes(value);
	string fullKeyBytesStr(bytes.begin(), bytes.end());
	string sha1 = sha256hex(fullKeyBytesStr);
	vector<char> sha256bytes = hexToBytes(sha1);
	vector<unsigned char> bytes2;
	for (char c : sha256bytes) {
		bytes2.push_back((c));
	}

	AddressSet res;
	res = GenerateFromBytes(bytes2);
	return res;
}
AddressSet CKeyGen::GenerateFromInt(int value) {
	vector<uint8_t> bytes = intToBytes(value);
	AddressSet res;
	res = GenerateFromBytes(bytes);
	return res;
}

AddressSet CKeyGen::GenerateFromBytes(vector<uint8_t> bytes) {

	//private
	string hexPrivate = bytesToHexString(bytes);
	string fullKey = "80" + hexPrivate + "01";

	//wif
	string checkSum = getCheckSum(fullKey);
	string wifString = fullKey + checkSum;
	vector<unsigned char> wifBytes = hexToBytesUnsign(wifString);
	string wif = encodeBase58(wifBytes);

	//public
	secp256k1::ecpoint compressed_public_key = getPublicKey(hexPrivate);

	//1adr 
	string address1 = get1Address(compressed_public_key);

	AddressSet res;

	return res;
}