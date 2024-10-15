# ad_gmsa_linux

A utility to generate Kerberos keytabs for Group Managed Service Accounts (gMSA) in Active Directory on Linux environments.


## Building

For now, the utility is packaged for Debian / deb-based distributions.

The packages needed can be built by running `debuild -us -uc` in each directory (`cpp` and `python`).

For other distros or for manual installation, the `cpp` directory contains helper programs for the Python side.
The `python` directory contains a Python wheel for the service that manages the keytabs (the `systemd` unit is inside the `debian` directory).


## Usage

Install the two packages built earlier, which installs some helper programs and a Python service.

Configure the service using the `/etc/ad-gmsa/ad-gmsa.ini` to indicate the Active Directory information.
The `[accounts]` section must be filled with gMSA (Group Managed Service Accounts) that are accessible with the current computer account on the machine.

It is recommended to use `gssproxy` to limit access to the system keytab (for this utility) and the generated keytabs (for the kerberized services).

