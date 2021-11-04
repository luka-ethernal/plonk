In this module we show how, and why, the KZG10 polynomial commitment scheme has 
been implemented for this PLONK implementation.

# KZG10 (Kate) Commitments 

PLONK can be constructed with different commitment schemes and does not require 
solely homomorphic commitments. However, this library implements only 
homomorphic commitments for two reasons. One is their useful properties when 
given encrypted values, and the second is the requirements of the linearization 
technique in PLONK.

PLONK makes use of the linearization technique, originally conceived in the 
[SONIC paper](https://eprint.iacr.org/2019/099.pdf) This technique requires the 
the commitment scheme to be homomorphic. The use of this linearizer in the 
PLONK protocol prevents us from being able to use Merkle-tree like techniques, 
such as the [FRI protocol](https://drops.dagstuhl.de/opus/volltexte/2018/9018/pdf/LIPIcs-ICALP-2018-14.pdf).

We use KZG10 commitments, often called 'Kate commitments', the commitment 
scheme created by Kate, Zaverucha and Goldberg.
A detailed explanation on how this particular commitment scheme operates can be 
found in the [original paper](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf).
Aside from the compatibility with the chosen linearization technique, there are 
multiple benefits of using the KZG10 commitment scheme in the PLONK.
The first is that it allows us to have constant size commitments; the witness 
of the evaluations is a single group element.
The cost of these commitments is also constant irrespective of the number of 
evaluations, so we are able to employ them with a low overhead cost.

This commitment is used to commit to a polynomial, from a given structured 
reference string (SRS) by means of a bilinear pairing group.
Where &Gopf;<sub>1</sub> and &Gopf;<sub>2</sub> and groups two different 
pairing curves with generators *g*<sub>1</sub> &isin; &Gopf;<sub>1</sub> 
and *g*<sub>2</sub> &isin; &Gopf;<sub>2</sub>.

These commitments are homomorphic, which enables us to perform operations on 
the already encrypted values and have the evaluation be indistinguishable from 
the evaluation of operations performed on the decrypted values.In terms of Kate 
commitments, we are able to take two commitment messages, *m*<sub>1</sub> and 
*m*<sub>2</sub>, and know there is an efficient product operation for them both 
which equates to a commitment *C*(*m*<sub>1</sub> *m*<sub>2</sub>).

For example:

&emsp;*C*(*m*<sub>1</sub>) &sdot; *C*(*m*<sub>2</sub>) &equals; *m*<sub>1</sub> &otimes; *m*<sub>2</sub> 
