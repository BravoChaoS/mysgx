# Related work

- ARM: [Trust zone](#Trust Zone)
- AMD: SEV
- RISC-V: MultiZone

## Trust Zone

> Secure Core -> Trust OS -> Trust App

处理器架构上，TrustZone将每个物理核虚拟为两个核，一个非安全核（Non-secure Core, NS Core），运行非安全世界的代码；和另一个安全核（Secure Core），运行安全世界的代码。

两个虚拟的核以基于时间片的方式运行，根据需要实时占用物理核，并通过Monitor Mode在安全世界和非安全世界之间切换，类似同一CPU下的多应用程序环境，不同的是多应用程序环境下操作系统实现的是进程间切换，而Trustzone下的Monitor Mode实现了同一CPU上两个操作系统间的切换。

设计上，TrustZone并不是采用一刀切的方式让每个芯片厂家都使用同样的实现。总体上以AMBA3 AXI总线为基础，针对不同的应用场景设计了各种安全组件，芯片厂商根据具体的安全需求，选择不同的安全组件来构建他们的TrustZone实现。

> TrustZone设计的相关方
>
> - ARM公司: 定义TrustZone并实现硬件设计，TEE，TZAPI等
> - 芯片厂家: 在具体芯片上实现TrustZone设计，包括三星、高通、MTK、TI、ST、华为等
> - 应用提供方: 如DRM厂家和安全应用开发商，实现DRM、Playready、DTCP-IP和一些其它安全应用开发和认证

TEE环境下也要有一个操作系统，各家都有自己的Trustzone的操作系统，如Trustonic、高通的QSEE、国内的豆荚，还有开源的OPTEE等。在操作系统之上自然要有应用程序，在Trustzone里面我们一般叫TrustApp，当然TEE里面每个TrustApp都在一个沙盒里，互相之间是隔离的。比如说支付，就可以做成一个App（需要注意的是，和Normal World里面的App是两个概念），这个App简单来说就负责用私钥把网上发来的Challenge签个名，而这个签名的动作是需要在Secure World里面做的，避免恶意程序窃取到私钥来伪造签名。

### 对比SGX

Trustzone默认相信SecureOS，安全世界。SGX仅相信CPU core，通过SGX指令构建enclave容器。

TEE是个公用大保险柜，什么东西都装进去，有漏洞的app可能也进去了，而且保险柜钥匙在管理员手上，必须相信管理员。SGX每个app有自己的保险柜，钥匙在自己手上。

### 总结

ARM提供的标准中没有correctness measure， 默认相信Trustzone OS。Trustzone OS有可能被攻破，进而导致Trust App被篡改。