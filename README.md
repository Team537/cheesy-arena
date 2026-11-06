Cheesy Arena [![Build Status](https://github.com/Team254/cheesy-arena/actions/workflows/test.yml/badge.svg)](https://github.com/Team254/cheesy-arena/actions)
============
A field management system that just works.

For the game-agnostic version, see [Cheesy Arena Lite](https://github.com/Team254/cheesy-arena-lite).

## Key features

**For participants and spectators**

* Same network isolation and security as the official FIRST FMS
* No-lag realtime scoring
* Team stack lights and seven-segment display are replaced by an LCD screen, which shows team info before the match and
  realtime scoring and timer during the match
* Smooth-scrolling rankings display
* Direct publishing of schedule, results, and rankings to The Blue Alliance

**For scorekeepers and event staff**

* Runs on Windows, macOS, and Linux
* No install prerequisites
* No "pre-start" &ndash; hardware is configured automatically and in the background
* Flexible and quick match schedule generation
* Streamlined realtime score entry
* Reports, results, and logs can be viewed from any computer
* An arbitrary number of auxiliary displays can be set up using any computer with just a web browser, to show rankings,
  queueing, field status, etc.

## License

Teams may use Cheesy Arena freely for practice, scrimmages, and off-season events. See [LICENSE](LICENSE) for more
details.

## Installing

**From a pre-built release**

Download the [latest release](https://github.com/Team254/cheesy-arena/releases). Pre-built packages are available for
Linux, macOS (x64 and M1), and Windows.

On recent versions of macOS, you may be prevented from running an app from an unidentified developer;
see [these instructions](https://support.apple.com/guide/mac-help/open-a-mac-app-from-an-unidentified-developer-mh40616/mac)
on how to bypass the warning.

**From source**

1. Download [Go](https://golang.org/dl/) (version 1.26.7 or later required)
1. Clone this GitHub repository to a location of your choice
1. Navigate to the repository's directory in the terminal
1. Compile the code with `go build`
1. Run the `cheesy-arena` or `cheesy-arena.exe` binary
1. Navigate to http://localhost:8080 in your browser (Google Chrome recommended)

**IP address configuration**

When running Cheesy Arena on a playing field with robots, set the IP address of the computer running Cheesy Arena to
10.0.100.5. By a convention baked into the FRC Driver Station software, driver stations will broadcast their presence on
the network to this hardcoded address so that the FMS does not need to discover them by some other method.

When running Cheesy Arena without robots for testing or development, pass the `-dev` flag to bind driver station
listeners to any local IP address.

## Under the hood

Cheesy Arena is written using [Go](https://golang.org), a language developed by Google and first released in 2009. Go
excels in the areas of concurrency, networking, performance, and portability, which makes it ideal for a field
management system.

Cheesy Arena is implemented as a web server, with all human interaction done via browser. The graphical interfaces are
implemented in HTML, JavaScript, and CSS. There are many advantages to this approach &ndash; development of new
graphical elements is rapid, and no software needs to be installed other than on the server. Client web pages send
commands and receive updates using WebSockets.

[Bolt](https://github.com/etcd-io/bbolt) is used as the datastore, and making backups or transferring data from one
installation to another is as simple as copying the database file.

Schedule generation is fast because pre-generated schedules are included with the code. Each schedule contains a certain
number of matches per team for placeholder teams 1 through N, so generating the actual match schedule becomes a simple
exercise in permuting the mapping of real teams to placeholder teams. The pre-generated schedules are checked into this
repository and can be vetted in advance of any events for deviations from the randomness (and other) requirements.

Cheesy Arena includes support for, but doesn't require, networking hardware similar to that used in official FRC events.
Teams are issued their own SSIDs and WPA keys, and when connected to Cheesy Arena are isolated to a VLAN which prevents
any communication other than between the driver station, robot, and event server. The network hardware is reconfigured
via SSH and Telnet commands for the new set of teams when each mach is loaded.

## PLC integration

Cheesy Arena has the ability to integrate with an Allen-Bradley PLC setup similar to the one that FIRST uses, to read
field sensors and control lights and motors. The PLC hardware travels with the FIRST California fields; contact your FTA
for more information.

The PLC code can be found [here](https://github.com/ejordan376/Cheesy-PLC).

## Team Sign integration

Cheesy Arena has the ability to integrate with
the [Cypress Team Signs](https://cypressintegration.com/customsolutions/teamdisplay/) used at official FRC events. See
the [Configuring Cheesy Arena wiki page](https://github.com/Team254/cheesy-arena/wiki/Configuring-Cheesy-Arena-Settings#team-signs)
for details configurating the team signs in Cheesy Arena.

## DMX Lighting integration

Cheesy Arena has the ability to integrate with DMX lighting hardware like what's used at official FRC events.
See the [DMX Lighting Setup wiki page](https://github.com/Team254/cheesy-arena/wiki/DMX-Lighting-Setup) for details.

## LED hardware

Due to the prohibitive cost of the LEDs and LED controllers used on official fields, for years in which LEDs are
mandatory for a proper game experience (such as 2018), Cheesy Arena integrates
with [Advatek](https://www.advateklights.com) controllers and LEDs.

## Advanced networking

The field switch supports Cisco IOS (including the existing Catalyst 3500-series) and IOS XE
(including the Catalyst 3850). Per-match VLAN and DHCP commands are shared by both platforms.
The existing [switch baseline](switch_config.txt) is for the older hardware; it is not a
3850 configuration. IOS XE interfaces typically use names such as `GigabitEthernet1/0/1`,
and its fixed 802.1Q trunks do not accept `switchport trunk encapsulation dot1q`.
Provision the same VLANs, routing, ACLs, and port assignments before enabling network management.

Cheesy Arena tries SSH on port 22 first and uses Telnet on port 23 only when the SSH TCP
connection cannot be established. SSH negotiation, authentication, and command failures
are reported without falling back to Telnet. Set **Switch SSH Username** in the field
settings to the switch's local username (SSH defaults to `admin` if blank).
When a username is configured, Telnet also uses interactive username/password login;
leaving it blank preserves the original password-only Telnet login.
**Switch Password** is used for both login and `enable`; privilege-15 SSH logins are supported.
Configure IOS XE for SSH v2, generate its host key, and enable the desired VTY transports
(`transport input telnet ssh` with `login local` for username/password login).

SSH supports `curve25519-sha256`, `diffie-hellman-group14-sha256`, and
`diffie-hellman-group1-sha1` key exchange, with `aes128-gcm@openssh.com`, `aes128-ctr`,
and `aes128-cbc` ciphers, in that preference order. Available algorithms on the switch
depend on its IOS XE release. Group1/SHA-1, AES-CBC, and RSA/SHA-1 host signatures are
legacy compatibility options; prefer modern algorithms. Like the SCC switch client,
the field switch client accepts unverified host keys. Telnet transmits credentials in
plaintext, so restrict management access to a trusted, isolated field network.

See the [Advanced Networking wiki page](https://github.com/Team254/cheesy-arena/wiki/Advanced-Networking-Concepts) for
instructions on what equipment to obtain and how to configure it in order to support advanced network security.

## Contributing

Cheesy Arena is far from finished! You can help by:

* Writing a missing feature, and sending a pull request
* Filing any bugs or feature requests using the [issue tracker](https://github.com/Team254/cheesy-arena/issues)
* Contributing documentation to the [wiki](https://github.com/Team254/cheesy-arena/wiki)
* Sending baked goods to [Pat](https://github.com/patfair)

## Acknowledgements

[Several folks](https://github.com/Team254/cheesy-arena/graphs/contributors) have contributed pull requests. Thanks!

In addition, the following individuals have contributed to make Cheesy Arena a reality:

* Tom Bottiglieri
* James Cerar
* Kiet Chau
* Travis Covington
* Nick Eyre
* Patrick Fairbank
* Eugene Fang
* Thad House
* Ed Jordan
* Karthik Kanagasabapathy
* Ken Mitchell
* Andrew Nabors
* Jared Russell
* Ken Schenke
* Austin Schuh
* Colin Wilson
