#ifndef GENERALSETTINGS_H
#define GENERALSETTINGS_H

#include <string>

using namespace std;

namespace Settings {
	static int rh_port = 22222;
	static string rh_host = "localhost";
	
	static string server_crt = "/media/jojjiw/OS/BCSpace/study/TEE/SampleCode/RemoteAttestation101/server.crt"; //certificate for the HTTPS connection between the SP and the App
	static string server_key = "/media/jojjiw/OS/BCSpace/study/TEE/SampleCode/RemoteAttestation101/server.key"; //private key for the HTTPS connection

	static string spid = "ADDA7CED88291BB8F20AEB027E55D155"; //SPID provided by Intel after registration for the IAS service
	static const char *ias_crt = "/media/jojjiw/OS/BCSpace/study/TEE/SampleCode/RemoteAttestation101/server.crt"; //location of the certificate send to Intel when registring for the IAS
	static const char *ias_key = "/media/jojjiw/OS/BCSpace/study/TEE/SampleCode/RemoteAttestation101/server.key";
	static string ias_url = "https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v2/";
}

#endif
