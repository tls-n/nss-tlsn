# TLS-N implementation for NSS 

This is the prototype [TLS-N](https://tls-n.org) implementation based on Mozilla's [NSS](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS) library. 

## Main Library
The main library file can be found inside [nss/lib/ssl/tlsproof.c](nss/lib/ssl/tlsproof.c). Here the most important functions are:

``` tlsproof_addMessageToProof ```
This function adds a record to the evidence calculation.

``` SSL_TLSProofRequestProof ```
The requester calls this function to trigger the evidence request.

``` tlsproof_handleMessageRequest ```
The function used by the generator to finalize the evidence.

``` tlsproof_handleMessageResponse ```
Uses the supplied evidence to create a proof according to the user's wishes.

``` SSL_TLSProofCheckProof ```
Verifies a given proof. 

### Test Applications
We have also provided multiple test applications, such as:
* A standalone [verifier](nss/cmd/verifier) that verifies proofs.
* A [client](nss/cmd/randtrafficClient) and [server](randtrafficServer) application to test TLS-N with a specified amount of random traffic.
* A [benchmarking](nss/cmd/benchmark) app for TLS-N.

#### Test-CA
For testing purposes we provide a Test CA with a test certiface for ```tls-n.testserver``` inside the [ca](ca) folder. The certificate store has an empty password. You have to resolve this hostname accordingly in DNS.
