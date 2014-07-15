@@
expression shared, my, your, pre;
@@

- goldilocks_shared_secret_core(shared, my, your, pre)
+ goldilocks_shared_secret_core(shared, sharedlen, my, your, pre)

@@
expression shared, my, your;
@@

- goldilocks_shared_secret(shared, my, your)
+ goldilocks_shared_secret(shared, sharedlen, my, your)

@@
expression shared, my, your, pre;
@@

- goldilocks_shared_secret_precomputed(shared, my, your, pre)
+ goldilocks_shared_secret_precomputed(shared, sharedlen, my, your, pre)
