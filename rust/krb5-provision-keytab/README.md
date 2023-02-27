# krb5-provision-keytab

This is a CLI tool for provisioning a Kerberos Keytab, and the principals within.

Compared to `kadmin`, it speaks a simple JSON based format that is designed not to be vulnerable to argument injection.

It has to run as a separate short-lived process, because the kadm5 libraries are hard-coded to read
configuration from certain environment variables: https://mailman.mit.edu/pipermail/kerberos/2022-April/022804.html.
