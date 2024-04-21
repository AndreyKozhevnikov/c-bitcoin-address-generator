#pragma once
#include <string>
#include <vector>
#include "AddressSet.h"
using namespace std;


class CKeyGen {       // The class
public:             // Access specifier
	AddressSet GenerateFromString(string value);
	AddressSet GenerateFromInt(int value);
	AddressSet GenerateFromBytes(vector<uint8_t> bytes);

};