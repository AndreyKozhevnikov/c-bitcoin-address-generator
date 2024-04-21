#include "pch.h"
#include "CppUnitTest.h"
#include <CKeyGen.h>



using namespace std;





using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace CKeyGenTests
{
	TEST_CLASS(CKeyGenTest)
	{
	public:
		//
		TEST_METHOD(TestMethod1)
		{
			unsigned	int test1 = 1155;
			unsigned 	int* test = &test1;

			//int res = crypto::checksum(test);
			Assert::AreEqual(1, 1);
		}
		//TEST_METHOD(TestMethod2)
		//{
		//	Assert::AreEqual(1, 2);
		//}
	/*	TEST_METHOD(TestMethod3)
		{
			int res = myFunction("Test");
			Assert::AreEqual(1, res);
		}
		TEST_METHOD(TestMethod4)
		{
			int res = myFunction("Test");
			Assert::AreEqual(4, res);
		}*/

		////=====================
		TEST_METHOD(TestPriv)
		{
			CKeyGen keyGen;
			string input= "enter credit long demand tortoise harsh frame path rifle news then trigger";
			AddressSet res = keyGen.GenerateFromString(input);
			string expected = "9DDB55473EFFB85D2AF6E24B99ADE223A4E6F932D4933BDD4722B692B744CD23";
			Assert::AreEqual(expected, res.PrivateKey);
		}

		TEST_METHOD(TestWif)
		{
			CKeyGen keyGen;
			string input = "enter credit long demand tortoise harsh frame path rifle news then trigger";
			AddressSet res = keyGen.GenerateFromString(input);
			string expected = "L2WZevbYBAtLKbK76UNVu4sjqyibc3kc2qS6Qxwvpt5dhk35W19E";
			Assert::AreEqual(expected, res.WIF);
		}
		TEST_METHOD(Test1adr)
		{
			CKeyGen keyGen;
			string input = "enter credit long demand tortoise harsh frame path rifle news then trigger";
			AddressSet res = keyGen.GenerateFromString(input);
			string expected = "1CUuQXtKLY4XoEbHZ9BexWLZfN7wUHPuXC";
			Assert::AreEqual(expected, res.Addresses[0]);
		}
		TEST_METHOD(Test3adr)
		{
			CKeyGen keyGen;
			string input = "enter credit long demand tortoise harsh frame path rifle news then trigger";
			AddressSet res = keyGen.GenerateFromString(input);
			string expected = "3KJq5p2MtPyV4i6yJRboxNkXCob197MiJj";
			Assert::AreEqual(expected, res.Addresses[1]);
		}
		TEST_METHOD(TestBCadr)
		{
			CKeyGen keyGen;
			string input = "enter credit long demand tortoise harsh frame path rifle news then trigger";
			AddressSet res = keyGen.GenerateFromString(input);
			string expected = "bc1q0hc9c4jh39nz2tf8plsyfjsajthg4x4uza7u40";
			Assert::AreEqual(expected, res.Addresses[2]);
		}

		TEST_METHOD(TestString)
		{
			CKeyGen keyGen;
			string input = "test";
			AddressSet res = keyGen.GenerateFromString(input);
			string expected = "L2ZovMyTxxQVJmMtfQemgVcB5YmiEDapDwsvX6RqvuWibgUNRiHz";
			Assert::AreEqual(expected, res.WIF);
		}
		TEST_METHOD(TestInt)
		{
			CKeyGen keyGen;
			int input = 1155;
			AddressSet res = keyGen.GenerateFromInt(input);
			string expected = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFUGxXgtm63M";
			Assert::AreEqual(expected, res.WIF);
		}

		TEST_METHOD(TestInt2)
		{
			CKeyGen keyGen;
			int input = 1155564574;
			AddressSet res = keyGen.GenerateFromInt(input);
			string expected = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M8j6jbf8w5suhf";
			Assert::AreEqual(expected, res.WIF);
		}
	/*	TEST_METHOD(TestBigInt65)
		{
			CKeyGen keyGen;
			var val = System.Numerics.BigInteger.Parse("30568377312064202855");
			AddressSet res = keyGen.GenerateFromBigInt(input);
			string expected = "18ZMbwUFLMHoZBbfpCjUJQTCMCbktshgpe";
			Assert::AreEqual(expected, res.Addresses[0]);
		}*/
	};
}
