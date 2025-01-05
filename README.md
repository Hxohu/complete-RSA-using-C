# 使用C语言实现RSA(素数256比特)

在该项目中，使用C语言完成了RSA实现的所有步骤，如:素数生成与检验，加密，解密。其中，在素数生成的过程中先使用C语言内置库生成一些数据，并通过AES加密(查表)来达到随机的目的，并验证是否为素数；在素数检验中使用费马检验。在RSA中，模幂运算是最耗时的部分，在该部分使用蒙哥马利规约(Montgomery reduce)加速模幂运算。

在AMD Ryzen 7 5700U处理器，16GB内存，Windows 11 64位操作系统，gcc 版本 8.1.0 (x86_64-posix-seh-rev0, Built by MinGW-W64 project)中运行32次完整的RSA过程平均耗时0.38s。

In this project, all steps of RSA implementation were completed using the C language, including prime number generation and verification, encryption, and decryption. During the prime number generation process, some initial data were generated using the C standard library and subsequently encrypted using AES (table lookup) to achieve randomness, followed by verification to check primality. Fermat's test was employed for prime verification.  

In the RSA algorithm, modular exponentiation is the most time-consuming part. To accelerate this operation, Montgomery reduction was utilized.  

On an AMD Ryzen 7 5700U processor with 16GB of memory, running Windows 11 64-bit, and using GCC version 8.1.0 (x86_64-posix-seh-rev0, built by the MinGW-W64 project), executing the complete RSA process 32 times resulted in an average runtime of 0.38 seconds.