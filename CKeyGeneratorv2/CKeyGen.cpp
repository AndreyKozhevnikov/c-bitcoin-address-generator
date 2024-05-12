#include "pch.h"
#include <string>
#include "CKeyGen.h"
#include "sha256.h"
#include "ConvertFunctions.cpp"
#include "base58.h"
#include "secp256k1.h"
#include "bech32.h"

using namespace std;


AddressSet CKeyGen::GenerateFromHexString(string hexvalue) {


	vector<unsigned char> bytes2 = hexToBytesUnsign(hexvalue);
	AddressSet res;
	res = GenerateFromBytes(bytes2);
	return res;
}

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


	//3 adr "3KJq5p2MtPyV4i6yJRboxNkXCob197MiJj"
	vector<unsigned char> publicKeyBytes;
	decodeBase58(address1, publicKeyBytes);
	string public_key_hash = bytesToHexString(publicKeyBytes).substr(0, 42);
	string redeem_script = "0014" + public_key_hash.substr(2);
	vector<uint8_t> redeem_bytes = hexToBytesUnsign(redeem_script);
	string redeem_bytes_fullStr(redeem_bytes.begin(), redeem_bytes.end());
	string redeemSha256 = sha256hex(redeem_bytes_fullStr);
	string redeemRipe160St = Ripe160HexToHex(redeemSha256);
	string script_hash = "05" + redeemRipe160St;
	checkSum = getCheckSum(script_hash);
	string adr3String = script_hash + checkSum;
	vector<unsigned char> adr3Bytes = hexToBytesUnsign(adr3String);

	string adr3 = encodeBase58(adr3Bytes);


	//adrBC
	string public_key_hash_clean = public_key_hash.substr(2);

	string bstr = bech32::EncodeFromHex(public_key_hash_clean);

	AddressSet res;
	res.WIF = wif;
	res.PrivateKey = hexPrivate;
	res.Addresses[0] = address1;
	res.Addresses[1] = adr3;
	res.Addresses[2] = bstr;
	return res;
}