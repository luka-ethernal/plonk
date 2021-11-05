# LaTeX Graphics Sourcecode

Paste the code in an [online LaTeX editor](https://latexeditor.lagrida.com/) 
to create the respective figure.

1. P_n(x) = \sum_{j=0}^{n}y_i\mathbb{L}_n,j(x)
2. \mathbb{L}_n,j(x) = \prod_{m=0}^{k} \frac{(x-x_{m})} {(x_{j}-x_{m})}
3. L(x) := \sum_{j=0}^k y_j\ell_j(x)
4. \ell_j(x) := \prod_{\begin{smallmatrix}0\leq i\leq k\\i\ne j\end{smallmatrix}}\frac{x-x_i}{x_j-x_i} = \frac{x-x_0}{x_j-x_0} ... \frac{x-x_{j-1}}{x_j-x_{j-1}} \frac{x-x_{j+1}}{x_j-x_{j+1}} ... \frac{x-x_k}{x_j-x_k}
