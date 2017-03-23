#include <exception>
#include <iostream>
#include <string>

#include "json_web_token.h"

namespace {
using namespace std;
using namespace jwt_verify;
}

int
main() {
	const string token{"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL3N0ZXJuaXN0ZS5ldS5hdXRoMC5jb20vIiwic3ViIjoiZ29vZ2xlLW9hdXRoMnwxMTQ1NjI3NDM2MTU0OTgyMTIyNDQiLCJhdWQiOiJ2YU9JaWVvOUdySHV3ZEhheWlyeHdLdkVQN0NJQ2txbCIsImV4cCI6MTQ4OTAxNTcxNywiaWF0IjoxNDg4OTc5NzE3fQ.tWfmtKeTxseeekEx-13GypnDIumUMUF9RyiO6yBXGGM"};
	try {
		json_web_token jwt{token};
		const string secret_key{"hL1dC6Qeum8Z6HJ1XV01QCoq6dZwDA-XrObI2HTO1FuGdk5vSDRHU4SnTHU73aPR"};
		cout << jwt.verify(secret_key) << endl;
	} catch (const exception& e) {
		cerr << "caught exception: " << e.what() << endl;
		return 1;
	}
}

