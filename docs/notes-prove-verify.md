This module contains the notes on how the prover algorithm is constructed for 
PLONK.

## PLONK proof construction 

Following on from the generic SNARK construction, here we will give the set up 
of a PLONK proof and show which steps need to be satisfied to utilise the 
protocol.

First we will explain the derivation and simplification of the arithmetic 
circuits. 

PLONK uses both gate constraints and copy constraints, to collect like 
expressions. Using the same example of:

&emsp; *W<sub>L</sub>* &sdot; *W<sub>R</sub>* = *W<sub>O</sub>*

We can express multiples of the same wires in or out of the same gate, with the 
above equation.

Thus we have 'ith' gates, so the index from left or right across the circuit is 
mitigated for wires which are equal.

For example, in the two equations:

&emsp; *A*<sub>1</sub> &compfn; *X* &sdot; *B*<sub>1</sub> &compfn; *X*<sup>2</sup> = *C*<sub>1</sub>

and

&emsp; *A*<sub>2</sub> &compfn; *X*<sup>2</sup> &sdot; *B*<sub>2</sub> &compfn; *X* = *C*<sub>2</sub>

We can state the equalities that:

&emsp; *A*<sub>1</sub> = *B*<sub>2</sub> and *B*<sub>2</sub> = *A*<sub>1</sub> 

These are examples of constraints collected in PLONK. Which is done the same 
for addition gates, except the gate constrain satisfies:

&emsp; *W<sub>L</sub>* + *W<sub>R</sub>* = *W<sub>O</sub>*

PLONK also uses 'copy constraints', which are used to associate wires, which 
have equality, from the entire circuit.These constraints are checked with a 
permutation argument. In essence, this checks that wires are not repeated by 
using randomness given by the verifier.

This process is better explained in within the permutation section of the notes.

After the constraints are made, they are formatted into a system of numerical 
equations, which in PLONK are reduced to a small amount of polynomial equations 
which are capable of representing the constraints. PLONK allows us to combine 
the two gate equations by describing their relationship relative to the role in 
the circuit. PLONK also has constants, which are denoted as *Q*. These values 
will change for each programme. The shape of the circuit is defined by these 
values. When they are combined with the gate equations, we get the polynomial 
equation for a reduced form as:

&emsp; *Q<sub>L</sub>a<sub>i</sub>* + *Q<sub>R</sub>b<sub>i</sub>* + *Q<sub>O</sub>c<sub>i</sub>* + *Q<sub>M</sub>a<sub>i</sub>b<sub>i</sub>*  + *Q<sub>R</sub>* = 0

With *a<sub>i</sub>*, *b<sub>i</sub>* and *c<sub>i</sub>* the wires of the 
*i*<sup>th</sup> gate and *Q<sub>L</sub>*, *Q<sub>R</sub>*, *Q<sub>O</sub>*, 
*Q<sub>M</sub>* and *Q<sub>C</sub>* the left, right, output, middle and 
constants wire selector respectively.

This can be used for both addition and multiplication gates, where their values 
can be provided by the user depending on the circuit composition.

Setting *Q<sub>M</sub>* = *Q<sub>C</sub>* = 0, 
*Q<sub>L</sub>* = *Q<sub>R</sub>* = 1 and *Q<sub>O</sub>* = -1 
results in the addition gate:

&emsp; *a<sub>i</sub>* + *b<sub>i</sub>* - *c<sub>i</sub>* = 0

Setting *Q<sub>L</sub>* = *Q<sub>R</sub>* = *Q<sub>C</sub>* = 0, 
*Q<sub>M</sub>* = 1 and *Q<sub>O</sub>* = -1 
results in the addition gate:

&emsp; *a<sub>i</sub>b<sub>i</sub>* - *c<sub>i</sub>* = 0

With this format, there is a specific method used to convert all the equations 
into polynomial form.Basically, in order to bundle these together, PLONK can 
take sets of equations and turn them into one single equation over polynomials. 
This is called the evaluation form. We are then able to use Lagrangian 
interpolation to convert to coefficient form. The only thing this interpolation 
is doing,is allowing us to evaluate a functions over specific points,for 'x' 
values, where the target polynomial is equal to 1 or 0.

With these specific bases, we can derive the relation between all sets of 
equations into one single polynomial equation, where we have a vector of inputs 
to each gate type:

&emsp; *Q<sub>L</sub>(x)a(x)* + *Q<sub>R</sub>(x)b(x)* + *Q<sub>O</sub>(x)c(x)* + *Q<sub>M</sub>(x)a(x)b(x)* + *Q<sub>R</sub>(x)* = 0

The utility for this in PLONK, as a universal SNARK, is that any operation or 
relationship that holds with the inputted vectors, will also hold over the 
polynomial.

In order to check this in PLONK, a 'vanishing polynomial' is introduced. Which 
is just a polynomial equal to zero forall the points we evaluate at. So this 
means that the vectors will be divisible by this vanishing polynomial, if the 
expression we check does indeed hold.

To summarize what the PLONK proof must satisfy:

The generation of copy and gate constraints where the former are representative 
of permuted wires. Generate all of the polynomials to be checked against the 
vanishing polynomials.Take all of the wire values and convert them into three 
polynomials, *A(z)*, *B(z)* and *C(z)*. Check the polynomials at some random 
*Z<sub>z</sub>*, by making commitments and checking the evaluation form. Then 
commit all evaluation polynomials forms for the verifier.

# Lagrange Polynomials

The use of polynomials in the PLONK proving scheme refers to specific 
evaluation domains,named Lagrange polynomials, based on interpolation of two 
functions of particular group elements. The following section gives a more 
comprehensive understanding to the way in which these polynomials are formed, 
given certain inputs.

Lagrange polynomials are introduced as a means of constructing continuos 
functions from discrete data. With alternative polynomial constructions, 
discrete data sets can be approximated; Lagrange polynomials, however, form a 
solution that fits data exactly. This is achieved through **interpolation**, 
which finds a linear combination of 'n' inputted functions with respect to a 
given data set which imposes 'n' constraints and computes an exact fitting 
solution. 

Linear Algebra dictates that the interpolation polynomial ought to be formed 
from the system *A(x)* = *b*, where *b<sub>i</sub>* = *y<sub>i</sub>*, 
*i* = 0,..,*n* and the entries of *A(x)* are defined by 
*a<sub>ij</sub>* = *P(x<sub>i</sub>)*, and *i*,*j* &isin; 0,..,*n*.
Additionally, the used points for the interpolation are 
*x<sub>0</sub>*,*x<sub>1</sub>*,..,*x<sub>n</sub>*, from which the data points
*y<sub>0</sub>*,*y<sub>1</sub>*,..,*y<sub>n</sub>* are obtained and 
*P<sub>j</sub>(x<sub>i</sub>)* = *x<sup>j</sup>*, with *i* &isin; 0,..,*n*.
The basis 1,*x<sup>1</sup>*,*x<sup>2</sup>*,..,*x<sup>n</sup>* of the space of 
polynomials with degree *n+1* is called the **monomial basis** and the 
corresponding matrix *A* is called the **Vandermonde matrix** for the points 
*x<sub>0</sub>*,*x<sub>1</sub>*,..,*x<sub>n</sub>*.

With the Lagrange interpolation, however, matrix *A* is the identity matrix.
This stems from writing the interpolating polynomial as:

![interpolating polynomial](graphics/fig1.png)

The polynomials &Lopf;<sub><em>n</em></sub> and *j(x)* = 0,..,*n* are 
interpolations of the points *x<sub>0</sub>*,*x<sub>1</sub>*,..,*x<sub>n</sub>*.
They are commonly called the **Lagrangian polynomials**. They are written in 
the form:

![Lagrange polynomial](graphics/fig2.png)

the unique solution polynomial of degree *n* that satisfies 
*P<sub>n</sub>(x<sub>j</sub>*, where *i,j* = *f(x<sub>j</sub>)*, *j* = 0,1,..,*n*

The polynomial *P<sub>n</sub>(x<sub>j</sub>)* is called the **interpolating
polynomial** of *f(x)*.

To understand these as an expanded product argument, it can be written as

Given a set of k + 1 data points *(x<sub>j</sub>,y<sub>j</sub)* with *j* &isin; 
*{0,..,k}*

where *(x<sub>j</sub>,y<sub>j</sub)* &ne; *(x<sub>i</sub>,y<sub>i</sub)* for 
all *i*&ne;*j*, *i,j*&isin;*{0,..,n}*.

The interpolation polynomial in the Lagrange form is a linear combination

![Lagrange polynomial](graphics/fig3.png)

of Lagrange basis polynomials

![basis polynomials](graphics/fig4.png)
