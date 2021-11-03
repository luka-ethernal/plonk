This module explains the inner workings of commitment schemes. 

# Commitment Schemes

To employ a commitment scheme, is simply to select a value from a finite set 
and commit to the value such that the new 'committed' value cannot be changed.
Commitment schemes are used in cryptography, often in conjunction with zero 
knowledge proofs to allow a prover to commit to a polynomial, with values 
represented by a short reference string.
This is then used by verifiers to confirm or deny the claims made by the 
original committing party.
With this process, the commitment, which the committer publishes, is bound, 
meaning it cannot be changed.
This process is called **binding**.
Additionally, the prover is able to make this commitment without revealing it, 
this is called **hiding**.
After the commitment has been made, a prover is able to reveal the committed 
message to a verifier so that the message can be compared, for consistency, 
with the commitment.

## Generic Example

Consider a game of players *A* and *B*. *A* writes down message &phi; on a 
piece of paper, places the message in a box, locks the box with a key and gives 
the locked box plus the key to *B*.

With this setup *B* is able to open the box and see the committed message. *A* 
is unable to change the value after giving the box to *B* thus the message is 
binding. As *B* is unable to see the commitment prior to opening the box, the 
commitment is also hiding. 

Commitment schemes are defined by a public key *pk* generation algorithm. The 
input is 1<sup><em>l</em></sup> where *l* is the security parameter that 
directly relates to the length of the string. There is an outputted *pk*, which 
is the public key of the commitment scheme. In practice, the protocol is ran 
like this:

1. *A* or *B* executes the public key generation algorithm to return *pk*, as a 
string, and sends it to the other party.
2. To make the commitment, the receiving party calculates a random &psi; from 
(0,1)<sup><em>l</em></sup> and computes the commitment *C*(&phi;,&psi;):
3. The commitment is opened, meaning &phi; & &psi; are revealed and *B* checks 
that the commitment *C* satisfies: *C*(&phi;,&psi;)

The property of having either *A* or *B* running the algorithm affects the type 
of commitment scheme and the satisfied requirements. With respect to the hiding 
and binding properties, this commitment can be constructed in two different 
ways.

## Computational Binding and Unconditional Hiding

When *B* generates the public key and sends it to *A*, the binding is 
computational and the hiding is unconditional. The **computational binding** in 
this commitment scheme, means the chance of being able to change the commitment 
is negligible. The **unconditional hiding** means that a commitment to &phi; 
reveals no information about &phi;.

## Unconditional Binding and Computational Hiding

When *A* generates *pk* and sends it to *B* then the binding is unconditional 
and the hiding is computational. The **unconditional binding** describes how 
*A* is unable to change the commitment value after it has been committed to. 
The **computational hiding** means the probability of *B* being able to guess 
the commitment value is negligible. 

## Polynomial Commitment Schemes

Polynomial commitment schemes can be defined in the following way:

Let &Gopf; be a group of prime order *p*. Let *g* and *h* be generators of 
&Gopf;, such that *g*, *h* &isin; &Gopf;.

Either *g* or *h* are used to produce *pk*, which has a commitment appended to 
it by the committer.

This commitment is equal to message *m*, where *m* &isin; 
&Zopf;<sub><em>p</em></sub>

The commitment *C*, which is made once these variables are derived, is:

&emsp;*C*<sub><em>pk</em></sub>(&phi;,&psi;) &equals; *g*<sup>&psi;</sup> &times; *h*<sup>&phi;</sup>

The above equation is generic to using short strings, as values, to commit to a 
polynomial and generate an evaluated value.
