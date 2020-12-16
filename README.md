# Threshold signaute BLS

This is a Rust implementation of {t,n}-threshold BLS 

Threshold BLS includes two protocols:

-   Key Generation for creating secret shares.
-   Signing for using the secret shares to generate a signature.


## Library Content
1. Basic BLS. This implements the protocol in [1]. 
2. Threshold BLS. The library implements the protocol specified on page 13 in [2]. 
The key generation protocol is specified on page 25 of the same paper.  
## Contact

Feel free to [reach out](mailto:github@kzencorp.com) or join ZenGo X [Telegram](https://t.me/zengo_x) for discussions on code and research.

## References

[1] <https://eprint.iacr.org/2018/483.pdf>

[2] <https://eprint.iacr.org/2020/096.pdf>

