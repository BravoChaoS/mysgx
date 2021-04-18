# Intel SGX Background

Intel SGX is one of the most popular TEE environments.

SGX can bypass the system's operating system and virtual machine software layers to improve the security of data and code execution. 

Intel SGX application is consist of two components: Untrusted component (Application) and Trusted component (Enclave)

The App can communicate with Enclave directly, which can protect the communication from potential threats targeting the OS/VMMs 

The main protections provided by SGX are: Enclave protection, ocall/ecall interfaces, attestation and sealing.

[https://www.intel.cn/content/www/cn/zh/architecture-and-technology/software-guard-extensions-enhanced-data-protection.html]

### Enclave protection

SGX protect enclave by isolate enclave from application and OS.

Enclave has its own code and data, which are independent of creator application. Enclave memory is resides in Processor Reserved Memory (PRM), it cannot be read or written from outside the enclave.

Enclave is also isolated in runtime. The code and data of enclave are protected in Enclave Page Cache (EPC).  The only interface between the enclave and application is ocalls and ecalls.



### Ocall/Ecall

Ocalls and ecalls are the interfaces between trusted enclave and untrusted application. Application can call ecalls to entering enclave; Enclave using ocalls can returns to untrusted application. All the data transmit between application and enclave during an ocall/ecall are copied to the destination memory, in order to keep the isolation of enclave.



### Attestation

Attestation supported by SGX can verify the enclave information of creation, load and code execution.  There are two kinds of attestation: local attestation and remote attestation.

- Local attestation is between two enclave in the same platform. The prover enclave generate a report about the status of enclave, and the verifier enclave can verify this report by using a shared key from CPU.
- Remote attestation is the prover enclave proving to a remote application. Prover enclave send a request to local Quoting Enclave for a report. The report is signed and packaged in a quote. The verifier application needs to send the quote to Intel Attestation Service (IAS), IAS verify the quote and return the result to the verifier application.  

### Sealing

> sec18-matetic/3.1/Sealing and Memory encryption



# System Design

### Role

This credential delegation system mainly consists of 3 roles: credential owner, delegatee and service provider. Credential owner delegate the credential to the enclave of delegatee by running a c++ program. Delegatee request the SGX application on his PC, if the delegate condition is satisfied, the SGX application with credential can post command to service provider. Service provider can be a website or a database server, it is not need to do any changes for this system.

### Process

#### credential delegate

This is the basic function of this credential delegate system. Besides delegate the credential to the delegatee's enclave, the credential owner can also send a series of commands to restrict the use of the credential. For example, an owner can limit the number of a credential use, or add a time limit to a credential. Only if the condition is satisfied, the enclave will allow the use of the credential.

1. The owner application runs remote attestation to the delegatee's enclave. Once the remote attestation is finished, the owner application can set up a secure session with the delegatee's enclave. 
2. The owner application sends a credential with some restriction conditions to delegatee's enclave.  
3. If the delegatee needs a credential to interact with the service provider, a request will be sent to the local enclave.
4. Enclave will check the conditions of the credential. If all the conditions are satisfied, the credential and the related command will be sent to the service provider.
5. (Optional) The service provider returns the result to the enclave.

